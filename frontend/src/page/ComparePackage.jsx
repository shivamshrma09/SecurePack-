import { useState, useCallback } from 'react'
import Navbar from '../components/Navbar'
import GeminiChat from '../components/GeminiChat'
import { SiGooglegemini } from 'react-icons/si'
import { searchPurl } from '../api/vulnerablecode'

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
  if (v >= 9) return { bg: 'rgba(239,68,68,0.18)', color: '#f87171', label: 'Critical' }
  if (v >= 7) return { bg: 'rgba(249,115,22,0.18)', color: '#fb923c', label: 'High' }
  if (v >= 4) return { bg: 'rgba(234,179,8,0.18)', color: '#facc15', label: 'Medium' }
  return { bg: 'rgba(34,197,94,0.18)', color: '#4ade80', label: 'Low' }
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

const Tag = ({ bg, color, children }) => (
  <span style={{ background: bg, color, padding: '2px 10px', borderRadius: '20px', fontSize: '11px', fontWeight: '500' }}>{children}</span>
)

const SectionLabel = ({ text, color = '#6b7280' }) => (
  <div style={{ padding: '8px 20px', color, fontSize: '11px', borderBottom: '1px solid #1f2937', letterSpacing: '0.05em' }}>{text}</div>
)

const Chevron = ({ open }) => (
  <span style={{ color: '#4b5563', fontSize: '11px', display: 'inline-block', transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }}>▶</span>
)

const LABELS = ['A', 'B', 'C', 'D', 'E', 'F']

// ─── Single column for side-by-side compare ──────────────────────
function PkgColumn({ pkg, label, refsOpen, toggleRefs, idx, isLast }) {
  const [openVulns, setOpenVulns] = useState({})
  const toggleVuln = (k) => setOpenVulns(p => ({ ...p, [k]: !p[k] }))

  return (
    <div className="compare-col" style={{
      flex: '0 0 480px', width: '480px',
      borderRight: isLast ? 'none' : '1px solid rgba(115,115,115,0.2)',
      display: 'flex', flexDirection: 'column'
    }}>
      {/* Header */}
      <div style={{ padding: '14px 16px', background: '#161616', borderBottom: '1px solid #1f2937', position: 'sticky', top: 0, zIndex: 2 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <Tag bg="rgba(217,119,87,0.15)" color="#D97757">{label}</Tag>
          {pkg.is_vulnerable
            ? <Tag bg="rgba(239,68,68,0.15)" color="#f87171">VULNERABLE</Tag>
            : <Tag bg="rgba(74,222,128,0.1)" color="#4ade80">SAFE</Tag>
          }
          {pkg.risk_score != null && <Tag bg="rgba(217,119,87,0.12)" color="#D97757">Risk {pkg.risk_score}</Tag>}
        </div>
        <div style={{ color: '#60a5fa', fontWeight: '600', fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pkg.purl}</div>
        <div style={{ display: 'flex', gap: '12px', marginTop: '6px' }}>
          <span style={{ color: '#f87171', fontSize: '11px' }}>{pkg.affected_by_vulnerabilities?.length || 0} affected</span>
          <span style={{ color: '#4ade80', fontSize: '11px' }}>{pkg.fixing_vulnerabilities?.length || 0} fixing</span>
        </div>
      </div>

      {/* Meta */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid #1f2937', display: 'flex', flexWrap: 'wrap', gap: '12px', background: '#0d0d0d' }}>
        {[['Type', pkg.type], ['Namespace', pkg.namespace], ['Name', pkg.name], ['Version', pkg.version],
          ['Next Safe', pkg.next_non_vulnerable_version], ['Latest Safe', pkg.latest_non_vulnerable_version]]
          .filter(([, v]) => v).map(([l, v]) => (
            <div key={l}>
              <div style={{ color: '#4b5563', fontSize: '10px', textTransform: 'uppercase' }}>{l}</div>
              <div style={{ color: '#e5e7eb', fontSize: '11px', fontWeight: '600' }}>{v}</div>
            </div>
          ))}
      </div>

      {/* Affected vulns */}
      {pkg.affected_by_vulnerabilities?.length > 0 && (
        <>
          <div style={{ padding: '7px 16px', color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #1f2937', background: '#0a0a0a' }}>
            Affected by {pkg.affected_by_vulnerabilities.length} vuln{pkg.affected_by_vulnerabilities.length > 1 ? 's' : ''}
          </div>
          {pkg.affected_by_vulnerabilities.map((vuln, j) => {
            const score = getBestCvss(vuln.references)
            const isVOpen = !!openVulns[j]
            const epssRefs = (vuln.references || []).filter(r => r.scores?.some(s => s.scoring_system === 'epss'))
            const nonEpssRefs = (vuln.references || []).filter(r => !r.scores?.some(s => s.scoring_system === 'epss'))
            return (
              <div key={j} style={{ borderBottom: '1px solid #1a1a1a' }}>
                {/* Vuln row - clickable */}
                <div onClick={() => toggleVuln(j)}
                  style={{ padding: '10px 16px', cursor: 'pointer', background: isVOpen ? '#111' : 'transparent', transition: 'background 0.15s' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: '#D97757', fontWeight: '700', fontSize: '12px' }}>{vuln.vulnerability_id}</div>
                      <div style={{ display: 'flex', gap: '4px', marginTop: '3px', flexWrap: 'wrap' }}>
                        {(vuln.aliases || []).map((a, k) => (
                          <span key={k} style={{ color: '#6b7280', fontSize: '10px', background: '#1f2937', padding: '1px 5px', borderRadius: '3px' }}>{getAliasStr(a)}</span>
                        ))}
                      </div>
                      <div style={{ display: 'flex', gap: '8px', marginTop: '4px', flexWrap: 'wrap' }}>
                        {vuln.risk_score != null && <span style={{ color: '#6b7280', fontSize: '10px' }}>Risk: <b style={{ color: '#e5e7eb' }}>{vuln.risk_score}</b></span>}
                        {vuln.exploitability != null && <span style={{ color: '#6b7280', fontSize: '10px' }}>Exploit: <b style={{ color: '#e5e7eb' }}>{vuln.exploitability}</b></span>}
                        {vuln.weighted_severity != null && <span style={{ color: '#6b7280', fontSize: '10px' }}>W.Sev: <b style={{ color: '#e5e7eb' }}>{vuln.weighted_severity}</b></span>}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
                      <ScoreBadge value={score} />
                      <Chevron open={isVOpen} />
                    </div>
                  </div>
                  {vuln.summary && <div style={{ color: '#9ca3af', fontSize: '11px', marginTop: '6px', lineHeight: '1.5' }}>{vuln.summary}</div>}
                </div>

                {/* Expanded vuln detail */}
                {isVOpen && (
                  <div style={{ background: '#0a0a0a' }}>
                    {vuln.fixed_packages?.length > 0 && (
                      <div style={{ padding: '8px 16px', borderTop: '1px solid #1a1a1a' }}>
                        <span style={{ color: '#4ade80', fontSize: '10px', marginRight: '6px', textTransform: 'uppercase' }}>Fixed in:</span>
                        {vuln.fixed_packages.map((fp, k) => (
                          <span key={k} style={{ background: 'rgba(74,222,128,0.08)', color: '#86efac', padding: '1px 6px', borderRadius: '3px', fontSize: '10px', marginRight: '4px' }}>{fp.purl}</span>
                        ))}
                      </div>
                    )}

                    {epssRefs.length > 0 && (
                      <div style={{ borderTop: '1px solid #1a1a1a' }}>
                        <div style={{ padding: '6px 16px', color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                          EPSS ({epssRefs.flatMap(r => r.scores.filter(s => s.scoring_system === 'epss')).length} entries)
                        </div>
                        <div style={{ padding: '0 16px 8px' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '10px' }}>
                            <thead>
                              <tr style={{ color: '#4b5563' }}>
                                <th style={{ textAlign: 'left', padding: '3px 6px 3px 0', fontWeight: '500' }}>Date</th>
                                <th style={{ textAlign: 'left', padding: '3px 6px', fontWeight: '500' }}>Score</th>
                                <th style={{ textAlign: 'left', padding: '3px 0', fontWeight: '500' }}>Percentile</th>
                              </tr>
                            </thead>
                            <tbody>
                              {epssRefs.flatMap(r => r.scores.filter(s => s.scoring_system === 'epss'))
                                .sort((a, b) => new Date(b.published_at) - new Date(a.published_at))
                                .map((s, k) => (
                                  <tr key={k} style={{ borderTop: '1px solid #1a1a1a' }}>
                                    <td style={{ padding: '2px 6px 2px 0', color: '#6b7280' }}>{s.published_at ? s.published_at.slice(0, 10) : '—'}</td>
                                    <td style={{ padding: '2px 6px', color: '#fbbf24', fontWeight: '600' }}>{(parseFloat(s.value) * 100).toFixed(2)}%</td>
                                    <td style={{ padding: '2px 0', color: '#9ca3af' }}>{s.scoring_elements ? (parseFloat(s.scoring_elements) * 100).toFixed(1) + '%' : '—'}</td>
                                  </tr>
                                ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {nonEpssRefs.length > 0 && (() => {
                      const rKey = `ref-cp${idx}-v${j}`
                      const rOpen = !!refsOpen[rKey]
                      return (
                        <div style={{ borderTop: '1px solid #1a1a1a' }}>
                          <div onClick={e => { e.stopPropagation(); toggleRefs(rKey) }}
                            style={{ padding: '7px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none' }}>
                            <span style={{ color: '#6b7280', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>References ({nonEpssRefs.length})</span>
                            <span style={{ color: '#4b5563', fontSize: '10px', transform: rOpen ? 'rotate(90deg)' : 'none', display: 'inline-block', transition: 'transform 0.2s' }}>▶</span>
                          </div>
                          {rOpen && (
                            <div style={{ padding: '0 16px 8px' }}>
                              {nonEpssRefs.map((ref, k) => {
                                const cvssScore = ref.scores?.find(s => s.scoring_system?.includes('cvss') && !s.scoring_system.includes('textual'))
                                const textScore = ref.scores?.find(s => s.scoring_system === 'generic_textual')
                                return (
                                  <div key={k} style={{ display: 'flex', gap: '8px', alignItems: 'center', padding: '3px 0', borderBottom: '1px solid #111' }}>
                                    <a href={ref.url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                                      style={{ color: '#60a5fa', fontSize: '10px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textDecoration: 'none' }}>
                                      {ref.reference_id ? <span style={{ color: '#9ca3af', marginRight: '4px' }}>[{ref.reference_id}]</span> : null}
                                      {ref.url}
                                    </a>
                                    <div style={{ display: 'flex', gap: '3px', flexShrink: 0 }}>
                                      {cvssScore && <span style={{ color: '#fbbf24', fontSize: '10px', background: 'rgba(251,191,36,0.1)', padding: '1px 4px', borderRadius: '3px' }}>{cvssScore.value}</span>}
                                      {textScore?.value && <span style={{ color: '#9ca3af', fontSize: '10px' }}>{textScore.value}</span>}
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
        </>
      )}

      {/* Fixing vulns */}
      {pkg.fixing_vulnerabilities?.length > 0 && (
        <>
          <div style={{ padding: '7px 16px', color: '#4ade80', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #1f2937', borderTop: '1px solid #1f2937', background: '#0a0a0a' }}>
            Fixes {pkg.fixing_vulnerabilities.length} vuln{pkg.fixing_vulnerabilities.length > 1 ? 's' : ''}
          </div>
          {pkg.fixing_vulnerabilities.map((vuln, j) => (
            <div key={j} style={{ padding: '8px 16px', borderBottom: '1px solid #1a1a1a' }}>
              <div style={{ color: '#4ade80', fontWeight: '600', fontSize: '11px' }}>{vuln.vulnerability_id}</div>
              {vuln.summary && <div style={{ color: '#6b7280', fontSize: '10px', marginTop: '3px' }}>{vuln.summary}</div>}
            </div>
          ))}
        </>
      )}

      {!pkg.affected_by_vulnerabilities?.length && !pkg.fixing_vulnerabilities?.length && (
        <div style={{ padding: '24px', textAlign: 'center', color: '#4ade80', fontSize: '12px' }}>✓ No known vulnerabilities</div>
      )}
    </div>
  )
}

export default function ComparePackage() {
  const [cards, setCards] = useState([{ id: 0, query: '' }, { id: 1, query: '' }])
  const [results, setResults] = useState({})
  const [loading, setLoading] = useState(false)
  const [refsOpen, setRefsOpen] = useState({})
  const [chatOpen, setChatOpen] = useState(false)
  const nextId = cards.length

  const addCard = () => {
    if (cards.length >= LABELS.length) return
    setCards(p => [...p, { id: nextId, query: '' }])
  }

  const removeCard = (id) => {
    setCards(p => p.filter(c => c.id !== id))
    setResults(p => { const n = { ...p }; delete n[id]; return n })
  }

  const updateQuery = (id, val) => setCards(p => p.map(c => c.id === id ? { ...c, query: val } : c))

  const searchAll = useCallback(async () => {
    setLoading(true)
    const filled = cards.filter(c => c.query.trim())
    const res = await Promise.all(filled.map(c => searchPurl(c.query.trim())))
    const map = {}
    filled.forEach((c, i) => { map[c.id] = res[i] })
    setResults(map)
    setLoading(false)
  }, [cards])

  const toggleRefs = (key) => setRefsOpen(p => ({ ...p, [key]: !p[key] }))

  const resultEntries = cards.filter(c => results[c.id]?.results?.[0])

  // Build compare context for Gemini: array of pkg objects
  const compareContext = resultEntries.length
    ? resultEntries.map(card => results[card.id].results[0])
    : null

  return (
    <>
    <div style={{ minHeight: '100vh', background: '#121212', color: 'white', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <Navbar />

      <div style={{ width: '100%', maxWidth: '1100px', padding: '40px 16px 60px' }}>
        <div style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '22px', fontWeight: '700', margin: 0 }}>Compare Packages</h2>
          <p style={{ color: '#6b7280', fontSize: '13px', marginTop: '6px' }}>Add packages and search all at once to compare vulnerability status.</p>
        </div>

        {/* Input cards */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          {cards.map((card, i) => (
            <div key={card.id} style={{ background: '#1a1a1a', border: '1px solid rgba(115,115,115,0.2)', borderRadius: '10px', padding: '14px 16px', minWidth: '260px', flex: '1 1 260px', maxWidth: '340px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ color: '#D97757', fontSize: '11px', fontWeight: '700', background: 'rgba(217,119,87,0.12)', padding: '2px 8px', borderRadius: '4px' }}>
                  Package {LABELS[i]}
                </span>
                {cards.length > 2 && (
                  <button onClick={() => removeCard(card.id)}
                    style={{ background: 'none', border: 'none', color: '#4b5563', cursor: 'pointer', fontSize: '16px', lineHeight: 1, padding: '0 4px' }}>×</button>
                )}
              </div>
              <input
                value={card.query}
                onChange={e => updateQuery(card.id, e.target.value)}
                onKeyDown={e => e.key === 'Enter' && searchAll()}
                placeholder="pkg:npm/lodash@4.17.21"
                style={{ width: '100%', background: '#111', border: '1px solid rgba(115,115,115,0.25)', borderRadius: '7px', outline: 'none', color: 'white', fontSize: '12px', padding: '9px 12px', boxSizing: 'border-box' }}
              />
            </div>
          ))}

          {/* Add card button */}
          {cards.length < LABELS.length && (
            <div onClick={addCard}
              style={{ minWidth: '260px', flex: '1 1 260px', maxWidth: '340px', background: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(115,115,115,0.25)', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', minHeight: '90px', color: '#4b5563', fontSize: '13px', gap: '8px', transition: 'border-color 0.2s' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = '#D97757'}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(115,115,115,0.25)'}>
              <span style={{ fontSize: '20px' }}>+</span> Add Package
            </div>
          )}
        </div>

        {/* Search all button */}
        <button onClick={searchAll} disabled={loading || !cards.some(c => c.query.trim())}
          style={{ background: 'none', border: '1px solid rgba(217,119,87,0.5)', color: '#D97757', padding: '7px 18px', borderRadius: '8px', fontSize: '13px', fontWeight: '500', cursor: loading ? 'not-allowed' : 'pointer', marginBottom: '32px', opacity: loading ? 0.6 : 1, transition: 'all 0.15s' }}
          onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = '#D97757'; e.currentTarget.style.color = 'white' }}}
          onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = '#D97757' }}>
          {loading ? 'Searching...' : `Search All (${cards.filter(c => c.query.trim()).length})`}
        </button>

        {/* Results - side by side with overflow scroll */}
        {resultEntries.length > 0 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
              <span style={{ color: '#f3f4f6', fontWeight: '600', fontSize: '15px' }}>Results</span>
              <Tag bg="rgba(217,119,87,0.15)" color="#D97757">{resultEntries.length} packages</Tag>
              <span style={{ color: '#4b5563', fontSize: '11px' }}>Scroll horizontally to compare</span>
            </div>

            {/* Outer scroll container */}
            <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '75vh', border: '1px solid rgba(115,115,115,0.2)', borderRadius: '12px', background: '#111' }}>
              <div style={{ display: 'flex', minWidth: `${resultEntries.length * 480}px` }}>
                {resultEntries.map((card, i) => {
                  const pkg = results[card.id].results[0]
                  return (
                    <PkgColumn key={card.id} pkg={pkg} label={LABELS[i]}
                      refsOpen={refsOpen} toggleRefs={toggleRefs}
                      idx={card.id} isLast={i === resultEntries.length - 1} />
                  )
                })}
              </div>
            </div>

            {/* Not found */}
            {cards.filter(c => results[c.id] && !results[c.id]?.results?.[0]).map((card) => (
              <div key={card.id} style={{ marginTop: '8px', color: '#6b7280', fontSize: '12px', padding: '8px 16px', background: '#1a1a1a', borderRadius: '8px', border: '1px solid rgba(115,115,115,0.15)' }}>
                <Tag bg="rgba(217,119,87,0.12)" color="#D97757">{LABELS[cards.indexOf(card)]}</Tag>
                <span style={{ marginLeft: '10px' }}>{card.query} — not found</span>
              </div>
            ))}
          </div>
        )}
      </div>
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
        searchContext={compareContext}
      />
    </>
  )
}
