const API_KEY = import.meta.env.VITE_GEMINI_API_KEY
const URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${API_KEY}`

// Slim down context to avoid token bloat & 429s
function buildContextSummary(ctx) {
  if (!ctx) return ''

  try {
    // Compare page: array of packages
    if (Array.isArray(ctx)) {
      const pkgs = ctx.map(p => ({
        purl: p.purl,
        vulnerable: p.is_vulnerable,
        risk: p.risk_score,
        affected: (p.affected_by_vulnerabilities || []).map(v => ({
          id: v.vulnerability_id,
          aliases: (v.aliases || []).map(a => typeof a === 'string' ? a : a?.alias),
          cvss: v.references?.flatMap(r => r.scores || []).find(s => s.scoring_system?.startsWith('cvss'))?.value,
          summary: v.summary?.slice(0, 120),
          fixed_in: (v.fixed_packages || []).map(f => f.purl),
        })),
        fixes: (p.fixing_vulnerabilities || []).map(v => v.vulnerability_id),
        next_safe: p.next_non_vulnerable_version,
      }))
      return `COMPARE DATA (${pkgs.length} packages):\n${JSON.stringify(pkgs, null, 1)}`
    }

    // File scan: { purls, items }
    if (ctx.items) {
      const summary = ctx.items.map(item => {
        const p = item.results?.[0]
        if (!p) return { purl: item.purl, found: false }
        return {
          purl: p.purl,
          vulnerable: p.is_vulnerable,
          risk: p.risk_score,
          affected_count: p.affected_by_vulnerabilities?.length || 0,
          top_vulns: (p.affected_by_vulnerabilities || []).slice(0, 3).map(v => ({
            id: v.vulnerability_id,
            cvss: v.references?.flatMap(r => r.scores || []).find(s => s.scoring_system?.startsWith('cvss'))?.value,
            summary: v.summary?.slice(0, 100),
          })),
          next_safe: p.next_non_vulnerable_version,
        }
      })
      return `FILE SCAN DATA (${summary.length} packages):\n${JSON.stringify(summary, null, 1)}`
    }

    // Package search: { results: [...] }
    if (ctx.results) {
      const slim = ctx.results.slice(0, 5).map(p => ({
        purl: p.purl,
        vulnerable: p.is_vulnerable,
        risk: p.risk_score,
        affected: (p.affected_by_vulnerabilities || []).map(v => ({
          id: v.vulnerability_id,
          aliases: (v.aliases || []).map(a => typeof a === 'string' ? a : a?.alias),
          cvss: v.references?.flatMap(r => r.scores || []).find(s => s.scoring_system?.startsWith('cvss'))?.value,
          summary: v.summary?.slice(0, 120),
          fixed_in: (v.fixed_packages || []).map(f => f.purl),
        })),
        next_safe: p.next_non_vulnerable_version,
      }))
      return `PACKAGE SEARCH DATA:\n${JSON.stringify(slim, null, 1)}`
    }

    // Vuln/CVE search
    if (ctx.count !== undefined || ctx.next !== undefined) {
      const slim = (ctx.results || []).slice(0, 5).map(v => ({
        id: v.vulnerability_id,
        aliases: (v.aliases || []).map(a => typeof a === 'string' ? a : a?.alias),
        risk: v.risk_score,
        summary: v.summary?.slice(0, 150),
        affected_count: v.affected_packages?.length,
        fixed_count: v.fixed_packages?.length,
        cvss: v.references?.flatMap(r => r.scores || []).find(s => s.scoring_system?.startsWith('cvss'))?.value,
      }))
      return `VULNERABILITY SEARCH DATA:\n${JSON.stringify(slim, null, 1)}`
    }
  } catch { /* ignore */ }

  return ''
}

// Retry fetch with exponential backoff on 429
async function fetchWithRetry(url, options, retries = 1) {
  for (let i = 0; i < retries; i++) {
    const res = await fetch(url, options)
    if (res.status !== 429) return res
    const wait = (i + 1) * 2000 // 2s, 4s, 6s
    await new Promise(r => setTimeout(r, wait))
  }
  throw new Error('Rate limit exceeded. Please wait a moment and try again.')
}

// history: [{role:'user'|'ai', text:'...'}]
export async function askGemini(userMessage, searchContext, history = []) {
  const contextBlock = buildContextSummary(searchContext)

  const systemPrompt = `You are a cybersecurity expert assistant in SecureView, a vulnerability intelligence platform.${
    contextBlock ? `\n\nCURRENT DATA CONTEXT (use this for specific answers):\n${contextBlock}` : ''
  }\n\nRules: be concise, technical, use the context data when relevant, format clearly.`

  const contents = [
    { role: 'user', parts: [{ text: systemPrompt }] },
    { role: 'model', parts: [{ text: 'Understood. Ready to help with the provided context.' }] },
    // last 6 messages of history to keep tokens low
    ...history.slice(-6).map(m => ({
      role: m.role === 'user' ? 'user' : 'model',
      parts: [{ text: m.text }]
    })),
    { role: 'user', parts: [{ text: userMessage }] }
  ]

  const res = await fetchWithRetry(URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents })
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err?.error?.message || 'Gemini API error')
  }
  const data = await res.json()
  return data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response.'
}
