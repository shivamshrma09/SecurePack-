import React, { useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { smartSearch, detectQueryType, parseUploadedFile, searchPurl } from '../api/vulnerablecode'
import Navbar from '../components/Navbar'
import GeminiChat from '../components/GeminiChat'
import { SiGooglegemini } from 'react-icons/si'

// aliases can be string[] (package vuln) or {alias}[] (vuln search)
const getAliasStr = (a) => typeof a === 'string' ? a : a?.alias || ''

const getBestCvss = (references) => {
  if (!references?.length) return null
  const all = references.flatMap(r => r.scores || [])
  return (
    all.find(s => s.scoring_system === 'cvssv3.1')?.value ||
    all.find(s => s.scoring_system === 'cvssv3')?.value ||
    all.find(s => s.scoring_system === 'cvssv2')?.value ||
    null
  )
}

const severityStyle = (val) => {
  const v = parseFloat(val)
  if (v >= 9)  return { bg: 'rgba(239,68,68,0.18)',   color: '#f87171', label: 'Critical' }
  if (v >= 7)  return { bg: 'rgba(249,115,22,0.18)',  color: '#fb923c', label: 'High'     }
  if (v >= 4)  return { bg: 'rgba(234,179,8,0.18)',   color: '#facc15', label: 'Medium'   }
  return             { bg: 'rgba(34,197,94,0.18)',    color: '#4ade80', label: 'Low'      }
}

const ScoreBadge = ({ value }) => {
  if (!value || isNaN(parseFloat(value))) return <span style={{ color: '#4b5563' }}>—</span>
  const s = severityStyle(value)
  return (
    <span style={{ background: s.bg, color: s.color, padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: '700' }}>
      {value} {s.label}
    </span>
  )
}

const MetaRow = ({ items }) => (
  <div style={{ padding: '12px 20px', display: 'flex', gap: '28px', borderBottom: '1px solid #1f2937', flexWrap: 'wrap', background: '#0d0d0d' }}>
    {items.filter(([, v]) => v).map(([label, val]) => (
      <div key={label}>
        <div style={{ color: '#4b5563', fontSize: '10px', marginBottom: '2px', textTransform: 'uppercase' }}>{label}</div>
        <div style={{ color: '#e5e7eb', fontSize: '12px', fontWeight: '600' }}>{val}</div>
      </div>
    ))}
  </div>
)

export default function Home() {
  const navigate = useNavigate()
  const [query, setQuery]       = useState('')
  const [focused, setFocused]   = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [results, setResults]   = useState(null)
  const [searchType, setSearchType] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [refsOpen, setRefsOpen] = useState({})
  const [fileResults, setFileResults] = useState(null)
  const [fileLoading, setFileLoading] = useState(false)
  const [chatOpen, setChatOpen] = useState(false)
  const fileRef = useRef()

  const toggleRefs = useCallback((key, e) => {
    e.stopPropagation()
    setRefsOpen(p => ({ ...p, [key]: !p[key] }))
  }, [])

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ''
    const content = await file.text()
    const purls = parseUploadedFile(file.name, content)
    if (!purls.length) return alert('No packages found in file.')
    setFileResults({ purls, done: 0, items: [] })
    setFileLoading(true)
    setResults(null)
    for (let i = 0; i < purls.length; i++) {
      const item = await searchPurl(purls[i])
      setFileResults(prev => ({ ...prev, done: i + 1, items: [...prev.items, item] }))
    }
    setFileLoading(false)
  }

  const toggle = (key) => setExpanded(p => p === key ? null : key)

  const handleSearch = async () => {
    if (!query.trim()) return
    setLoading(true); setResults(null); setError(null); setExpanded(null)
    try {
      const type = detectQueryType(query)
      setSearchType(type)
      setResults(await smartSearch(query))
    } catch {
      setError('API request failed. Check your connection.')
    }
    setLoading(false)
  }

  // ─── Package Search Results ───────────────────────────────────────
  const PackageResults = ({ packages }) => {
    if (!packages.length) return <Empty text="No packages found." />
    return (
      <div>
        <TableHeader count={packages.length} unit="package" />
        {packages.map((pkg, i) => {
          const isOpen = expanded === `p${i}`
          const cvss = getBestCvss(pkg.affected_by_vulnerabilities?.flatMap(v => v.references || []))
          return (
            <div key={i} style={{ borderBottom: '1px solid #1f2937' }}>
              {/* Row */}
              <div onClick={() => toggle(`p${i}`)} style={rowStyle(isOpen)}>
                <div style={{ flex: 1 }}>
                  <span style={{ color: '#60a5fa', fontWeight: '600', fontSize: '13px' }}>{pkg.purl}</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {pkg.is_vulnerable
                    ? <Tag bg="rgba(239,68,68,0.15)" color="#f87171">VULNERABLE</Tag>
                    : <Tag bg="rgba(74,222,128,0.1)" color="#4ade80">SAFE</Tag>
                  }
                  {pkg.risk_score != null && <Tag bg="rgba(217,119,87,0.15)" color="#D97757">Risk {pkg.risk_score}</Tag>}
                  <span style={{ color: '#f87171', fontSize: '12px' }}>{pkg.affected_by_vulnerabilities?.length || 0} affected</span>
                  <span style={{ color: '#4ade80', fontSize: '12px' }}>{pkg.fixing_vulnerabilities?.length || 0} fixing</span>
                  <Chevron open={isOpen} />
                </div>
              </div>

              {/* Expanded */}
              {isOpen && (
                <div style={{ background: '#0d0d0d', borderTop: '1px solid #1f2937' }}>
                  <MetaRow items={[
                    ['Type', pkg.type],
                    ['Namespace', pkg.namespace],
                    ['Name', pkg.name],
                    ['Version', pkg.version],
                    ['Next Safe Version', pkg.next_non_vulnerable_version],
                    ['Latest Safe Version', pkg.latest_non_vulnerable_version],
                  ]} />

                  {/* Affected vulnerabilities */}
                  {pkg.affected_by_vulnerabilities?.length > 0 && (
                    <>
                      <SectionLabel text={`AFFECTED BY ${pkg.affected_by_vulnerabilities.length} VULNERABILIT${pkg.affected_by_vulnerabilities.length > 1 ? 'IES' : 'Y'}`} />
                      {pkg.affected_by_vulnerabilities.map((vuln, j) => {
                        const score = getBestCvss(vuln.references)
                        const epssRefs = (vuln.references || []).filter(r => r.scores?.some(s => s.scoring_system === 'epss'))
                        const nonEpssRefs = (vuln.references || []).filter(r => !r.scores?.some(s => s.scoring_system === 'epss'))
                        return (
                          <div key={j} style={{ borderBottom: '1px solid #1a1a1a' }}>
                            {/* Vuln header */}
                            <div className="vuln-header">
                              <div className="vuln-id-col">
                                <div style={{ color: '#D97757', fontWeight: '700', fontSize: '13px' }}>{vuln.vulnerability_id}</div>
                                <div style={{ display: 'flex', gap: '4px', marginTop: '4px', flexWrap: 'wrap' }}>
                                  {(vuln.aliases || []).map((a, k) => (
                                    <span key={k} style={{ color: '#6b7280', fontSize: '10px', background: '#1f2937', padding: '1px 6px', borderRadius: '3px' }}>
                                      {getAliasStr(a)}
                                    </span>
                                  ))}
                                </div>
                                <div style={{ marginTop: '6px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                                  {vuln.risk_score != null && <span style={{ color: '#6b7280', fontSize: '11px' }}>Risk: <b style={{ color: '#e5e7eb' }}>{vuln.risk_score}</b></span>}
                                  {vuln.exploitability != null && <span style={{ color: '#6b7280', fontSize: '11px' }}>Exploit: <b style={{ color: '#e5e7eb' }}>{vuln.exploitability}</b></span>}
                                  {vuln.weighted_severity != null && <span style={{ color: '#6b7280', fontSize: '11px' }}>W.Sev: <b style={{ color: '#e5e7eb' }}>{vuln.weighted_severity}</b></span>}
                                </div>
                              </div>
                              <div className="vuln-summary">{vuln.summary || '—'}</div>
                              <div className="vuln-score-col"><ScoreBadge value={score} /></div>
                            </div>

                            {/* Fixed packages for this vuln */}
                            {vuln.fixed_packages?.length > 0 && (
                              <div className="fixed-in-row" style={{ padding: '8px 20px', borderTop: '1px solid #1a1a1a', background: '#0d0d0d' }}>
                                <span style={{ color: '#4ade80', fontSize: '10px', marginRight: '8px', textTransform: 'uppercase' }}>Fixed in:</span>
                                <span className="fixed-pills">
                                  {vuln.fixed_packages.map((fp, k) => (
                                    <span key={k} style={{ background: 'rgba(74,222,128,0.08)', color: '#86efac', padding: '2px 8px', borderRadius: '4px', fontSize: '11px' }}>
                                      {fp.purl}
                                    </span>
                                  ))}
                                </span>
                              </div>
                            )}

                            {/* EPSS Scores */}
                            {epssRefs.length > 0 && (
                              <div style={{ borderTop: '1px solid #1a1a1a', background: '#0a0a0a' }}>
                                <div style={{ padding: '6px 20px', color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>EPSS Scores ({epssRefs.flatMap(r => r.scores.filter(s => s.scoring_system === 'epss')).length} entries)</div>
                                <div style={{ padding: '0 20px 10px', maxHeight: '180px', overflowY: 'auto' }}>
                                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                                    <thead>
                                      <tr style={{ color: '#4b5563' }}>
                                        <th style={{ textAlign: 'left', padding: '4px 8px 4px 0', fontWeight: '500' }}>Date</th>
                                        <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: '500' }}>EPSS Score</th>
                                        <th style={{ textAlign: 'left', padding: '4px 0', fontWeight: '500' }}>Percentile</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {epssRefs.flatMap(r => r.scores.filter(s => s.scoring_system === 'epss'))
                                        .sort((a, b) => new Date(b.published_at) - new Date(a.published_at))
                                        .map((s, k) => (
                                          <tr key={k} style={{ borderTop: '1px solid #1a1a1a' }}>
                                            <td style={{ padding: '3px 8px 3px 0', color: '#6b7280' }}>{s.published_at ? s.published_at.slice(0, 10) : '—'}</td>
                                            <td style={{ padding: '3px 8px', color: '#fbbf24', fontWeight: '600' }}>{(parseFloat(s.value) * 100).toFixed(2)}%</td>
                                            <td style={{ padding: '3px 0', color: '#9ca3af' }}>{s.scoring_elements ? (parseFloat(s.scoring_elements) * 100).toFixed(1) + '%' : '—'}</td>
                                          </tr>
                                        ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            )}

                            {/* All other references */}
                            {nonEpssRefs.length > 0 && (() => {
                              const rKey = `ref-p${i}-v${j}`
                              const rOpen = !!refsOpen[rKey]
                              return (
                                <div style={{ borderTop: '1px solid #1a1a1a', background: '#0a0a0a' }}>
                                  <div onClick={e => toggleRefs(rKey, e)}
                                    style={{ padding: '8px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none' }}>
                                    <span style={{ color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>References ({nonEpssRefs.length})</span>
                                    <span style={{ color: '#4b5563', fontSize: '11px', transform: rOpen ? 'rotate(90deg)' : 'none', display: 'inline-block', transition: 'transform 0.2s' }}>▶</span>
                                  </div>
                                  {rOpen && (
                                    <div style={{ padding: '0 20px 10px' }}>
                                      {nonEpssRefs.map((ref, k) => {
                                        const cvssScore = ref.scores?.find(s => s.scoring_system?.includes('cvss') && !s.scoring_system.includes('textual'))
                                        const textScore = ref.scores?.find(s => s.scoring_system === 'generic_textual')
                                        const otherScore = ref.scores?.find(s => !s.scoring_system?.includes('cvss') && s.scoring_system !== 'generic_textual' && s.scoring_system !== 'epss')
                                        return (
                                          <div key={k} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '4px 0', borderBottom: '1px solid #111' }}>
                                            <a href={ref.url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                                              style={{ color: '#60a5fa', fontSize: '11px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: 'none' }}>
                                              {ref.reference_id ? <span style={{ color: '#9ca3af', marginRight: '6px' }}>[{ref.reference_id}]</span> : null}
                                              {ref.url}
                                            </a>
                                            <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                                              {cvssScore && <span style={{ color: '#fbbf24', fontSize: '10px', background: 'rgba(251,191,36,0.1)', padding: '1px 5px', borderRadius: '3px' }}>{cvssScore.value}</span>}
                                              {textScore?.value && <span style={{ color: '#9ca3af', fontSize: '10px' }}>{textScore.value}</span>}
                                              {otherScore && <span style={{ color: '#6b7280', fontSize: '10px' }}>{otherScore.scoring_system}: {otherScore.value}</span>}
                                            </div>
                                          </div>
                                        )
                                      })}
                                    </div>
                                  )}
                                </div>
                              )
                            })()}
                          </div>
                        )
                      })}
                    </>
                  )}

                  {/* Fixing vulnerabilities */}
                  {pkg.fixing_vulnerabilities?.length > 0 && (
                    <>
                      <SectionLabel text={`FIXES ${pkg.fixing_vulnerabilities.length} VULNERABILIT${pkg.fixing_vulnerabilities.length > 1 ? 'IES' : 'Y'}`} color="#4ade80" />
                      {pkg.fixing_vulnerabilities.map((vuln, j) => (
                        <div key={j} style={{ padding: '10px 20px', borderBottom: '1px solid #1a1a1a', display: 'flex', gap: '16px', alignItems: 'center' }}>
                          <span style={{ color: '#4ade80', fontWeight: '600', fontSize: '13px', minWidth: '200px' }}>{vuln.vulnerability_id}</span>
                          <span style={{ color: '#6b7280', fontSize: '12px' }}>{vuln.summary || '—'}</span>
                        </div>
                      ))}
                    </>
                  )}

                  {!pkg.affected_by_vulnerabilities?.length && !pkg.fixing_vulnerabilities?.length && (
                    <div style={{ padding: '20px', color: '#4ade80', textAlign: 'center', fontSize: '13px' }}>✓ No known vulnerabilities</div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    )
  }

  // ─── Vulnerability Search Results ────────────────────────────────
  const VulnResults = ({ vulns }) => {
    if (!vulns.length) return <Empty text="No vulnerabilities found." />
    return (
      <div>
        <TableHeader count={vulns.length} unit="vulnerability" />
        {vulns.map((vuln, i) => {
          const isOpen = expanded === `v${i}`
          const score = getBestCvss(vuln.references)
          // aliases here are [{alias: 'CVE-...'}]
          const aliasStrs = (vuln.aliases || []).map(getAliasStr)
          return (
            <div key={i} style={{ borderBottom: '1px solid #1f2937' }}>
              {/* Row */}
              <div onClick={() => toggle(`v${i}`)} style={rowStyle(isOpen)}>
                <div style={{ minWidth: '220px' }}>
                  <div style={{ color: '#D97757', fontWeight: '700', fontSize: '13px' }}>{vuln.vulnerability_id}</div>
                  <div style={{ display: 'flex', gap: '4px', marginTop: '4px', flexWrap: 'wrap' }}>
                    {aliasStrs.map((a, k) => (
                      <span key={k} style={{ color: '#6b7280', fontSize: '10px', background: '#1f2937', padding: '1px 6px', borderRadius: '3px' }}>{a}</span>
                    ))}
                  </div>
                </div>
                <div style={{ flex: 1, color: '#9ca3af', fontSize: '12px', lineHeight: '1.6', padding: '0 16px' }}>
                  <div style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                    {vuln.summary || '—'}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <ScoreBadge value={score} />
                  {vuln.risk_score != null && <Tag bg="rgba(217,119,87,0.12)" color="#D97757">Risk {vuln.risk_score}</Tag>}
                  <Chevron open={isOpen} />
                </div>
              </div>

              {/* Expanded */}
              {isOpen && (
                <div style={{ background: '#0d0d0d', borderTop: '1px solid #1f2937' }}>
                  <MetaRow items={[
                    ['Risk Score', vuln.risk_score],
                    ['Exploitability', vuln.exploitability],
                    ['Weighted Severity', vuln.weighted_severity],
                    ['Severity Range', vuln.severity_range_score],
                  ]} />

                  {/* Affected Packages */}
                  {vuln.affected_packages?.length > 0 && (
                    <>
                      <SectionLabel text={`AFFECTED PACKAGES (${vuln.affected_packages.length})`} color="#f87171" />
                      <div style={{ padding: '10px 20px', display: 'flex', gap: '8px', flexWrap: 'wrap', borderBottom: '1px solid #1f2937' }}>
                        {vuln.affected_packages.map((ap, k) => (
                          <span key={k} style={{ background: 'rgba(239,68,68,0.08)', color: '#fca5a5', padding: '3px 10px', borderRadius: '4px', fontSize: '11px' }}>
                            {ap.purl}
                          </span>
                        ))}
                      </div>
                    </>
                  )}

                  {/* Fixed Packages */}
                  {vuln.fixed_packages?.length > 0 && (
                    <>
                      <SectionLabel text={`FIXED IN (${vuln.fixed_packages.length})`} color="#4ade80" />
                      <div style={{ padding: '10px 20px', display: 'flex', gap: '8px', flexWrap: 'wrap', borderBottom: '1px solid #1f2937' }}>
                        {vuln.fixed_packages.map((fp, k) => (
                          <span key={k} style={{ background: 'rgba(74,222,128,0.08)', color: '#86efac', padding: '3px 10px', borderRadius: '4px', fontSize: '11px' }}>
                            {fp.purl}
                          </span>
                        ))}
                      </div>
                    </>
                  )}

                  {/* References */}
                  {vuln.references?.length > 0 && (() => {
                    const rKey = `ref-v${i}`
                    const rOpen = !!refsOpen[rKey]
                    return (
                      <div style={{ borderTop: '1px solid #1f2937' }}>
                        <div onClick={e => toggleRefs(rKey, e)}
                          style={{ padding: '10px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none', background: '#0d0d0d' }}>
                          <span style={{ color: '#6b7280', fontSize: '11px', letterSpacing: '0.05em' }}>References ({vuln.references.length})</span>
                          <span style={{ color: '#4b5563', fontSize: '11px', transform: rOpen ? 'rotate(90deg)' : 'none', display: 'inline-block', transition: 'transform 0.2s' }}>▶</span>
                        </div>
                        {rOpen && (
                          <div style={{ padding: '0 20px 12px', background: '#0a0a0a' }}>
                            {vuln.references.map((ref, k) => {
                              const cvssScore = ref.scores?.find(s => s.scoring_system?.includes('cvss') && !s.scoring_system.includes('textual'))
                              const textScore = ref.scores?.find(s => s.scoring_system === 'generic_textual')
                              const epssScore = ref.scores?.find(s => s.scoring_system === 'epss')
                              const otherScore = ref.scores?.find(s => !s.scoring_system?.includes('cvss') && s.scoring_system !== 'generic_textual' && s.scoring_system !== 'epss')
                              return (
                                <div key={k} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '4px 0', borderBottom: '1px solid #1a1a1a' }}>
                                  <a href={ref.url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                                    style={{ color: '#60a5fa', fontSize: '11px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: 'none' }}>
                                    {ref.reference_id ? <span style={{ color: '#9ca3af', marginRight: '6px' }}>[{ref.reference_id}]</span> : null}
                                    {ref.url}
                                  </a>
                                  <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                                    {cvssScore && <span style={{ color: '#fbbf24', fontSize: '10px', background: 'rgba(251,191,36,0.1)', padding: '1px 5px', borderRadius: '3px' }}>{cvssScore.value}</span>}
                                    {textScore?.value && <span style={{ color: '#9ca3af', fontSize: '10px' }}>{textScore.value}</span>}
                                    {epssScore && <span style={{ color: '#a78bfa', fontSize: '10px' }}>EPSS {(parseFloat(epssScore.value)*100).toFixed(1)}%</span>}
                                    {otherScore && <span style={{ color: '#6b7280', fontSize: '10px' }}>{otherScore.scoring_system}: {otherScore.value}</span>}
                                  </div>
                                </div>
                              )
                            })}
                          </div>
                        )}
                      </div>
                    )
                  })()}
                </div>
              )}
            </div>
          )
        })}
      </div>
    )
  }

  const renderResults = () => {
    if (!results) return null
    const { type, data } = results
    if (type === 'package') return <PackageResults packages={data?.results || []} />
    return <VulnResults vulns={data?.results || []} />
  }

  return (
    <>
      <div style={{ minHeight: '100vh', background: '#121212', color: 'white', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>

        <Navbar />

        {/* Hero */}
      <div style={{ textAlign: 'center', maxWidth: '700px', width: '100%', padding: '48px 16px 0' }}>
        <h1 className="hero-title" style={{ fontSize: '48px', fontWeight: '700', lineHeight: '1.2', marginBottom: '0' }}>
          Find <span style={{ color: '#D97757' }}>Vulnerabilities</span> Before
        </h1>
        <h1 className="hero-title" style={{ fontSize: '48px', fontWeight: '700', lineHeight: '1.2', marginBottom: '16px' }}>
          They Find <span style={{ color: '#D97757' }}>You</span>
        </h1>
        <p style={{ color: '#6b7280', fontSize: '15px', marginBottom: '32px' }}></p>
      </div>

      {/* Search */}
      <div style={{ width: '100%', maxWidth: '680px', padding: '0 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', border: `1px solid ${focused ? 'white' : 'rgba(115,115,115,0.3)'}`, borderRadius: '12px', background: 'rgba(30,30,30,0.8)', overflow: 'hidden', transition: 'border-color 0.2s' }}>
          <input
            value={query} onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
            placeholder="CVE-2019-17571  or  pkg:maven/log4j/log4j@1.2.27  or  VCID-..."
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: 'white', fontSize: '14px', padding: '14px 16px' }}
          />
          <button onClick={handleSearch} className="search-btn" style={{ background: '#D97757', border: 'none', color: 'white', padding: '14px 28px', fontSize: '14px', fontWeight: '600', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            {loading ? 'Searching...' : 'Search'}
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: '14px 0' }}>
          <div style={{ flex: 1, height: '1px', background: '#1f2937' }} />
          <span style={{ color: '#4b5563', fontSize: '12px' }}>or</span>
          <div style={{ flex: 1, height: '1px', background: '#1f2937' }} />
        </div>

        <div style={{ textAlign: 'center', marginTop: '14px' }}>
          <input type="file" ref={fileRef} style={{ display: 'none' }} accept=".json,.txt" onChange={handleFileUpload} />
          <button onClick={() => fileRef.current.click()}
            style={{ background: 'none', border: '1px solid rgba(115,115,115,0.3)', color: '#6b7280', padding: '10px 20px', borderRadius: '10px', fontSize: '13px', cursor: 'pointer' }}>
            {fileLoading ? `Scanning... (${fileResults?.done}/${fileResults?.purls?.length})` : 'Upload package.json / requirements.txt'}
          </button>
        </div>
      </div>

      {error && <div style={{ marginTop: '20px', color: '#f87171', background: 'rgba(239,68,68,0.1)', padding: '10px 20px', borderRadius: '8px', fontSize: '13px' }}>{error}</div>}

      {/* File Scan Results */}
      {fileResults && (
        <div style={{ width: '100%', maxWidth: '1100px', padding: '40px 16px 0', marginBottom: fileResults && !results ? '40px' : '0' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <span style={{ color: '#f3f4f6', fontWeight: '600', fontSize: '15px' }}>File Scan</span>
            <Tag bg="rgba(96,165,250,0.1)" color="#60a5fa">{fileResults.purls.length} packages</Tag>
            {fileLoading
              ? <Tag bg="rgba(234,179,8,0.1)" color="#facc15">Scanning {fileResults.done}/{fileResults.purls.length}...</Tag>
              : <Tag bg="rgba(74,222,128,0.1)" color="#4ade80">Done</Tag>
            }
            <button onClick={() => setFileResults(null)}
              style={{ marginLeft: 'auto', background: 'none', border: '1px solid #374151', color: '#6b7280', padding: '3px 10px', borderRadius: '6px', fontSize: '11px', cursor: 'pointer' }}>Clear</button>
          </div>

          {/* Summary table */}
          <div style={{ background: '#1a1a1a', border: '1px solid rgba(115,115,115,0.2)', borderRadius: '12px', overflow: 'hidden' }}>
            {/* Header */}
            <div className="file-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 120px 100px 100px', padding: '10px 20px', background: '#111', borderBottom: '1px solid #1f2937' }}>
              {['Package', 'Status', 'Affected', 'Risk'].map((h, idx) => (
                <span key={h} className={idx >= 2 ? 'file-grid-hide' : ''} style={{ color: '#4b5563', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</span>
              ))}
            </div>

            {fileResults.items.map((item, i) => {
              const pkg = item.results?.[0]
              const isOpen = expanded === `f${i}`
              return (
                <div key={i} style={{ borderBottom: '1px solid #1f2937' }}>
                  <div onClick={() => pkg && toggle(`f${i}`)}
                    style={{ display: 'grid', gridTemplateColumns: '1fr 120px 100px 100px', padding: '12px 20px', cursor: pkg ? 'pointer' : 'default', background: isOpen ? '#161616' : 'transparent', transition: 'background 0.15s' }}
                    className="file-grid">
                    <span style={{ color: '#60a5fa', fontSize: '12px', fontWeight: '500', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.purl}</span>
                    <span>
                      {!pkg
                        ? <Tag bg="rgba(75,85,99,0.2)" color="#6b7280">Not found</Tag>
                        : pkg.is_vulnerable
                          ? <Tag bg="rgba(239,68,68,0.15)" color="#f87171">Vulnerable</Tag>
                          : <Tag bg="rgba(74,222,128,0.1)" color="#4ade80">Safe</Tag>
                      }
                    </span>
                    <span style={{ color: pkg?.affected_by_vulnerabilities?.length ? '#f87171' : '#4b5563', fontSize: '12px' }} className="file-grid-hide">
                      {pkg ? (pkg.affected_by_vulnerabilities?.length || 0) : '—'}
                    </span>
                    <span style={{ color: '#D97757', fontSize: '12px' }} className="file-grid-hide">
                      {pkg?.risk_score ?? '—'}
                    </span>
                  </div>

                  {/* Expanded: full detail same as PackageResults */}
                  {isOpen && pkg && (
                    <div style={{ background: '#0d0d0d', borderTop: '1px solid #1f2937' }}>
                      <MetaRow items={[
                        ['Type', pkg.type],
                        ['Namespace', pkg.namespace],
                        ['Name', pkg.name],
                        ['Version', pkg.version],
                        ['Next Safe Version', pkg.next_non_vulnerable_version],
                        ['Latest Safe Version', pkg.latest_non_vulnerable_version],
                      ]} />

                      {pkg.affected_by_vulnerabilities?.length > 0 && (
                        <>
                          <SectionLabel text={`AFFECTED BY ${pkg.affected_by_vulnerabilities.length} VULNERABILIT${pkg.affected_by_vulnerabilities.length > 1 ? 'IES' : 'Y'}`} />
                          {pkg.affected_by_vulnerabilities.map((vuln, j) => {
                            const score = getBestCvss(vuln.references)
                            const epssRefs = (vuln.references || []).filter(r => r.scores?.some(s => s.scoring_system === 'epss'))
                            const nonEpssRefs = (vuln.references || []).filter(r => !r.scores?.some(s => s.scoring_system === 'epss'))
                            return (
                              <div key={j} style={{ borderBottom: '1px solid #1a1a1a' }}>
                                <div className="vuln-header">
                                  <div className="vuln-id-col">
                                    <div style={{ color: '#D97757', fontWeight: '700', fontSize: '13px' }}>{vuln.vulnerability_id}</div>
                                    <div style={{ display: 'flex', gap: '4px', marginTop: '4px', flexWrap: 'wrap' }}>
                                      {(vuln.aliases || []).map((a, k) => (
                                        <span key={k} style={{ color: '#6b7280', fontSize: '10px', background: '#1f2937', padding: '1px 6px', borderRadius: '3px' }}>{getAliasStr(a)}</span>
                                      ))}
                                    </div>
                                    <div style={{ marginTop: '6px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                                      {vuln.risk_score != null && <span style={{ color: '#6b7280', fontSize: '11px' }}>Risk: <b style={{ color: '#e5e7eb' }}>{vuln.risk_score}</b></span>}
                                      {vuln.exploitability != null && <span style={{ color: '#6b7280', fontSize: '11px' }}>Exploit: <b style={{ color: '#e5e7eb' }}>{vuln.exploitability}</b></span>}
                                      {vuln.weighted_severity != null && <span style={{ color: '#6b7280', fontSize: '11px' }}>W.Sev: <b style={{ color: '#e5e7eb' }}>{vuln.weighted_severity}</b></span>}
                                    </div>
                                  </div>
                                  <div className="vuln-summary">{vuln.summary || '—'}</div>
                                  <div className="vuln-score-col"><ScoreBadge value={score} /></div>
                                </div>

                                {vuln.fixed_packages?.length > 0 && (
                                  <div className="fixed-in-row" style={{ padding: '8px 20px', borderTop: '1px solid #1a1a1a', background: '#0d0d0d' }}>
                                    <span style={{ color: '#4ade80', fontSize: '10px', marginRight: '8px', textTransform: 'uppercase' }}>Fixed in:</span>
                                    <span className="fixed-pills">
                                      {vuln.fixed_packages.map((fp, k) => (
                                        <span key={k} style={{ background: 'rgba(74,222,128,0.08)', color: '#86efac', padding: '2px 8px', borderRadius: '4px', fontSize: '11px' }}>{fp.purl}</span>
                                      ))}
                                    </span>
                                  </div>
                                )}

                                {epssRefs.length > 0 && (
                                  <div style={{ borderTop: '1px solid #1a1a1a', background: '#0a0a0a' }}>
                                    <div style={{ padding: '6px 20px', color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>EPSS Scores ({epssRefs.flatMap(r => r.scores.filter(s => s.scoring_system === 'epss')).length} entries)</div>
                                    <div style={{ padding: '0 20px 10px' }}>
                                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
                                        <thead>
                                          <tr style={{ color: '#4b5563' }}>
                                            <th style={{ textAlign: 'left', padding: '4px 8px 4px 0', fontWeight: '500' }}>Date</th>
                                            <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: '500' }}>EPSS Score</th>
                                            <th style={{ textAlign: 'left', padding: '4px 0', fontWeight: '500' }}>Percentile</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {epssRefs.flatMap(r => r.scores.filter(s => s.scoring_system === 'epss'))
                                            .sort((a, b) => new Date(b.published_at) - new Date(a.published_at))
                                            .map((s, k) => (
                                              <tr key={k} style={{ borderTop: '1px solid #1a1a1a' }}>
                                                <td style={{ padding: '3px 8px 3px 0', color: '#6b7280' }}>{s.published_at ? s.published_at.slice(0, 10) : '—'}</td>
                                                <td style={{ padding: '3px 8px', color: '#fbbf24', fontWeight: '600' }}>{(parseFloat(s.value) * 100).toFixed(2)}%</td>
                                                <td style={{ padding: '3px 0', color: '#9ca3af' }}>{s.scoring_elements ? (parseFloat(s.scoring_elements) * 100).toFixed(1) + '%' : '—'}</td>
                                              </tr>
                                            ))}
                                        </tbody>
                                      </table>
                                    </div>
                                  </div>
                                )}

                                {nonEpssRefs.length > 0 && (() => {
                                  const rKey = `ref-f${i}-v${j}`
                                  const rOpen = !!refsOpen[rKey]
                                  return (
                                    <div style={{ borderTop: '1px solid #1a1a1a', background: '#0a0a0a' }}>
                                      <div onClick={e => toggleRefs(rKey, e)}
                                        style={{ padding: '8px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none' }}>
                                        <span style={{ color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>References ({nonEpssRefs.length})</span>
                                        <span style={{ color: '#4b5563', fontSize: '11px', transform: rOpen ? 'rotate(90deg)' : 'none', display: 'inline-block', transition: 'transform 0.2s' }}>▶</span>
                                      </div>
                                      {rOpen && (
                                        <div style={{ padding: '0 20px 10px' }}>
                                          {nonEpssRefs.map((ref, k) => {
                                            const cvssScore = ref.scores?.find(s => s.scoring_system?.includes('cvss') && !s.scoring_system.includes('textual'))
                                            const textScore = ref.scores?.find(s => s.scoring_system === 'generic_textual')
                                            const otherScore = ref.scores?.find(s => !s.scoring_system?.includes('cvss') && s.scoring_system !== 'generic_textual' && s.scoring_system !== 'epss')
                                            return (
                                              <div key={k} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '4px 0', borderBottom: '1px solid #111' }}>
                                                <a href={ref.url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                                                  style={{ color: '#60a5fa', fontSize: '11px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: 'none' }}>
                                                  {ref.reference_id ? <span style={{ color: '#9ca3af', marginRight: '6px' }}>[{ref.reference_id}]</span> : null}
                                                  {ref.url}
                                                </a>
                                                <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                                                  {cvssScore && <span style={{ color: '#fbbf24', fontSize: '10px', background: 'rgba(251,191,36,0.1)', padding: '1px 5px', borderRadius: '3px' }}>{cvssScore.value}</span>}
                                                  {textScore?.value && <span style={{ color: '#9ca3af', fontSize: '10px' }}>{textScore.value}</span>}
                                                  {otherScore && <span style={{ color: '#6b7280', fontSize: '10px' }}>{otherScore.scoring_system}: {otherScore.value}</span>}
                                                </div>
                                              </div>
                                            )
                                          })}
                                        </div>
                                      )}
                                    </div>
                                  )
                                })()}
                              </div>
                            )
                          })}
                        </>
                      )}

                      {pkg.fixing_vulnerabilities?.length > 0 && (
                        <>
                          <SectionLabel text={`FIXES ${pkg.fixing_vulnerabilities.length} VULNERABILIT${pkg.fixing_vulnerabilities.length > 1 ? 'IES' : 'Y'}`} color="#4ade80" />
                          {pkg.fixing_vulnerabilities.map((vuln, j) => (
                            <div key={j} style={{ padding: '10px 20px', borderBottom: '1px solid #1a1a1a', display: 'flex', gap: '16px', alignItems: 'center' }}>
                              <span style={{ color: '#4ade80', fontWeight: '600', fontSize: '13px', minWidth: '200px' }}>{vuln.vulnerability_id}</span>
                              <span style={{ color: '#6b7280', fontSize: '12px' }}>{vuln.summary || '—'}</span>
                            </div>
                          ))}
                        </>
                      )}

                      {!pkg.affected_by_vulnerabilities?.length && !pkg.fixing_vulnerabilities?.length && (
                        <div style={{ padding: '20px', color: '#4ade80', textAlign: 'center', fontSize: '13px' }}>✓ No known vulnerabilities</div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}

            {/* Pending rows while loading */}
            {fileLoading && fileResults.purls.slice(fileResults.done).map((purl, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 100px 100px', padding: '12px 20px', borderBottom: '1px solid #1f2937', opacity: 0.4 }}>
                <span style={{ color: '#4b5563', fontSize: '12px' }}>{purl}</span>
                <span style={{ color: '#4b5563', fontSize: '11px' }}>scanning...</span>
                <span /><span />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div style={{ width: '100%', maxWidth: '1100px', padding: '40px 16px', marginBottom: '40px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <span style={{ color: '#f3f4f6', fontWeight: '600', fontSize: '15px' }}>Results</span>
            <Tag bg="rgba(217,119,87,0.15)" color="#D97757">{results.data?.count ?? results.data?.results?.length ?? 0} found</Tag>
            <Tag bg="rgba(96,165,250,0.1)" color="#60a5fa">
              {searchType === 'package' ? 'Package Search' : 'CVE / VCID Search'}
            </Tag>
            <span style={{ color: '#4b5563', fontSize: '11px' }}>Click row to expand</span>
          </div>
          <div style={{ background: '#1a1a1a', border: '1px solid rgba(115,115,115,0.2)', borderRadius: '12px', overflow: 'hidden' }}>
            {renderResults()}
          </div>
        </div>
      )}
    </div>

      {/* Gemini AI Button - fixed bottom right */}
      {!chatOpen && (
        <button onClick={() => setChatOpen(true)}
          style={{
            position: 'fixed', bottom: '24px', right: '24px', zIndex: 9999,
            background: '#1a1a1a', border: '1px solid rgba(217,119,87,0.4)',
            borderRadius: '10px', padding: '9px 16px',
            display: 'flex', alignItems: 'center', gap: '7px',
            color: '#D97757', fontSize: '13px', fontWeight: '600', cursor: 'pointer',
            transition: 'border-color 0.2s, background 0.2s'
          }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(217,119,87,0.08)'; e.currentTarget.style.borderColor = '#D97757' }}
          onMouseLeave={e => { e.currentTarget.style.background = '#1a1a1a'; e.currentTarget.style.borderColor = 'rgba(217,119,87,0.4)' }}>
          <SiGooglegemini style={{ fontSize: '14px' }} />
          SecureView AI
        </button>
      )}

      <GeminiChat
        isOpen={chatOpen}
        onClose={() => setChatOpen(false)}
        searchContext={results?.data ?? fileResults ?? null}
      />
    </>
  )
}

// ─── Small helpers ────────────────────────────────────────────────
const Empty = ({ text }) => <div style={{ padding: '40px', textAlign: 'center', color: '#6b7280' }}>{text}</div>

const TableHeader = ({ count, unit }) => (
  <div style={{ padding: '10px 20px', background: '#111', borderBottom: '1px solid #1f2937' }}>
    <span style={{ fontSize: '12px', color: '#6b7280' }}>{count} {unit}{count !== 1 ? 's' : ''} found</span>
  </div>
)

const SectionLabel = ({ text, color = '#6b7280' }) => (
  <div style={{ padding: '8px 20px', color, fontSize: '11px', borderBottom: '1px solid #1f2937', letterSpacing: '0.05em' }}>{text}</div>
)

const Tag = ({ bg, color, children }) => (
  <span style={{ background: bg, color, padding: '2px 10px', borderRadius: '20px', fontSize: '11px', fontWeight: '500' }}>{children}</span>
)

const Chevron = ({ open }) => (
  <span style={{ color: '#4b5563', fontSize: '11px', transition: 'transform 0.2s', display: 'inline-block', transform: open ? 'rotate(90deg)' : 'none' }}>▶</span>
)

const rowStyle = (isOpen) => ({
  display: 'flex', alignItems: 'center', gap: '12px',
  padding: '14px 20px', cursor: 'pointer',
  background: isOpen ? '#161616' : 'transparent',
  transition: 'background 0.15s'
})
