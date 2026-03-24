const BASE = import.meta.env.VITE_API_BASE || `${import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000'}/vulnerablecode`

export const detectQueryType = (query) => {
  const q = query.trim().toLowerCase()
  if (q.startsWith('pkg:')) return 'package'
  if (q.startsWith('cpe:')) return 'cpe'
  return 'alias'
}

export const smartSearch = async (query) => {
  const type = detectQueryType(query)

  if (type === 'package') {
    const res = await fetch(`${BASE}/packages/?purl=${encodeURIComponent(query)}`)
    if (!res.ok) throw new Error(`API error ${res.status}`)
    const data = await res.json()
    return { type: 'package', data }
  }

  const res = await fetch(`${BASE}/vulnerabilities/?vulnerability_id=${encodeURIComponent(query)}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  const data = await res.json()

  if (!data.results?.length) {
    const res2 = await fetch(`${BASE}/vulnerabilities/?alias=${encodeURIComponent(query)}`)
    if (!res2.ok) throw new Error(`API error ${res2.status}`)
    const data2 = await res2.json()
    return { type: 'alias', data: data2 }
  }

  return { type: 'alias', data }
}

export const fetchPackageHistory = async (pkgUrl) => {
  const id = pkgUrl?.split('/packages/')?.[1]?.replace(/\/$/, '')
  if (!id) return []
  const res = await fetch(`${BASE}/packages/${id}/history/`)
  if (!res.ok) return []
  const data = await res.json()
  return Array.isArray(data) ? data : (data.results || [])
}

// Parse uploaded file → array of purls
export const parseUploadedFile = (filename, content) => {
  const ext = filename.split('.').pop().toLowerCase()

  // package.json
  if (ext === 'json') {
    try {
      const json = JSON.parse(content)
      const deps = { ...json.dependencies, ...json.devDependencies }
      return Object.entries(deps).map(([name, ver]) => {
        const clean = ver.replace(/^[^\d]*/, '') // remove ^~>=
        return `pkg:npm/${name}@${clean}`
      })
    } catch { return [] }
  }

  // requirements.txt
  if (ext === 'txt' || filename === 'requirements.txt') {
    return content.split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'))
      .map(l => {
        // already a purl
        if (l.startsWith('pkg:')) return l
        // name==version or name>=version etc
        const match = l.match(/^([A-Za-z0-9_.-]+)\s*[=><!]+\s*([\d.]+)/)
        if (match) return `pkg:pypi/${match[1].toLowerCase()}@${match[2]}`
        return `pkg:pypi/${l.toLowerCase()}`
      })
  }

  // plain purl list
  return content.split('\n')
    .map(l => l.trim())
    .filter(l => l.startsWith('pkg:'))
}

// Search single purl
export const searchPurl = async (purl) => {
  const res = await fetch(`${BASE}/packages/?purl=${encodeURIComponent(purl)}`)
  const data = await res.json()
  return { purl, results: data.results || [] }
}
