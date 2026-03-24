import { useState, useRef, useEffect } from 'react'
import { SiGooglegemini } from 'react-icons/si'
import { askGemini } from '../api/gemini'

const WELCOME = 'Hi! I\'m your AI security assistant. I have access to your current search/compare data as context — ask me anything about the packages or vulnerabilities you\'re viewing!'

export default function GeminiChat({ searchContext, isOpen, onClose }) {
  const [messages, setMessages] = useState([{ role: 'ai', text: WELCOME }])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const prevContextRef = useRef(null)
  const bottomRef = useRef()

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Notify user when context updates (new search/compare result)
  useEffect(() => {
    if (!searchContext) return
    if (prevContextRef.current === searchContext) return
    prevContextRef.current = searchContext

    // Build a short summary of what context arrived
    let summary = ''
    if (searchContext.results?.length) {
      const pkg = searchContext.results[0]
      summary = `Package: ${pkg.purl}\nStatus: ${pkg.is_vulnerable ? 'Vulnerable' : 'Safe'}\nAffected by: ${pkg.affected_by_vulnerabilities?.length || 0} vuln(s)`
    } else if (searchContext.items?.length) {
      const total = searchContext.items.length
      const vuln = searchContext.items.filter(i => i.results?.[0]?.is_vulnerable).length
      summary = `File scan: ${total} package(s) scanned\nVulnerable: ${vuln} | Safe: ${total - vuln}`
    } else if (Array.isArray(searchContext)) {
      const vuln = searchContext.filter(p => p?.is_vulnerable).length
      summary = `Compare: ${searchContext.length} package(s) loaded\nVulnerable: ${vuln} | Safe: ${searchContext.length - vuln}`
    }

    if (summary) {
      setMessages(p => [...p, {
        role: 'ai',
        text: `Context updated! I now have the latest data:\n\n${summary}\n\nAsk me anything about these results.`
      }])
    }
  }, [searchContext])

  const send = async () => {
    const msg = input.trim()
    if (!msg || loading) return
    setInput('')
    const history = messages.filter(m => m.text !== WELCOME)
    setMessages(p => [...p, { role: 'user', text: msg }])
    setLoading(true)
    try {
      const reply = await askGemini(msg, searchContext, history)
      setMessages(p => [...p, { role: 'ai', text: reply }])
    } catch (err) {
      const msg = err.message?.includes('Rate limit') || err.message?.includes('429')
        ? 'Rate limit hit. Please wait a few seconds and try again.'
        : err.message || 'Something went wrong. Please try again.'
      setMessages(p => [...p, { role: 'ai', text: msg }])
    }
    setLoading(false)
  }

  return (
    <>
      {/* Backdrop */}
      {isOpen && (
        <div onClick={onClose}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 49 }} />
      )}

      {/* Side panel */}
      <div className="gemini-panel" style={{
        position: 'fixed', top: 0, right: 0, height: '100vh', width: '380px',
        background: '#0f0f0f', borderLeft: '1px solid rgba(115,115,115,0.2)',
        display: 'flex', flexDirection: 'column', zIndex: 50,
        transform: isOpen ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform 0.3s cubic-bezier(0.4,0,0.2,1)'
      }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid rgba(115,115,115,0.2)', display: 'flex', alignItems: 'center', gap: '10px', background: '#111' }}>
          <SiGooglegemini style={{ color: '#818cf8', fontSize: '18px' }} />
          <div style={{ flex: 1 }}>
            <div style={{ color: 'white', fontWeight: '600', fontSize: '14px' }}>AI Security Assistant</div>
            <div style={{ color: '#6b7280', fontSize: '11px' }}>Powered by Gemini</div>
          </div>
          {searchContext && (
            <span style={{ background: 'rgba(74,222,128,0.1)', color: '#4ade80', fontSize: '10px', padding: '2px 8px', borderRadius: '20px' }}>
              ● Context loaded
            </span>
          )}
          <button onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: '18px', lineHeight: 1, padding: '2px' }}>×</button>
        </div>

        {/* Messages */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {messages.map((msg, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
              {msg.role === 'ai' && (
                <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: 'rgba(129,140,248,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginRight: '8px', marginTop: '2px' }}>
                  <SiGooglegemini style={{ color: '#818cf8', fontSize: '12px' }} />
                </div>
              )}
              <div style={{
                maxWidth: '85%', padding: '10px 14px', borderRadius: msg.role === 'user' ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                background: msg.role === 'user' ? '#D97757' : '#1a1a1a',
                color: msg.role === 'user' ? 'white' : '#e5e7eb',
                fontSize: '13px', lineHeight: '1.6',
                border: msg.role === 'ai' ? '1px solid rgba(115,115,115,0.15)' : 'none',
                whiteSpace: 'pre-wrap', wordBreak: 'break-word'
              }}>
                {msg.text}
              </div>
            </div>
          ))}
          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: 'rgba(129,140,248,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <SiGooglegemini style={{ color: '#818cf8', fontSize: '12px' }} />
              </div>
              <div style={{ background: '#1a1a1a', border: '1px solid rgba(115,115,115,0.15)', borderRadius: '12px 12px 12px 2px', padding: '10px 14px', display: 'flex', gap: '4px', alignItems: 'center' }}>
                {[0, 1, 2].map(i => (
                  <div key={i} style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#818cf8', animation: `bounce 1.2s ${i * 0.2}s infinite` }} />
                ))}
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div style={{ padding: '12px 16px', borderTop: '1px solid rgba(115,115,115,0.2)', background: '#111' }}>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end' }}>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
              placeholder="Ask about vulnerabilities, packages, CVEs..."
              rows={2}
              style={{
                flex: 1, background: '#1a1a1a', border: '1px solid rgba(115,115,115,0.25)',
                borderRadius: '8px', outline: 'none', color: 'white', fontSize: '13px',
                padding: '9px 12px', resize: 'none', fontFamily: 'inherit', lineHeight: '1.5'
              }}
            />
            <button onClick={send} disabled={loading || !input.trim()}
              style={{
                background: loading || !input.trim() ? '#1f2937' : '#818cf8',
                border: 'none', color: 'white', borderRadius: '8px',
                padding: '9px 14px', cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                fontSize: '13px', fontWeight: '600', whiteSpace: 'nowrap', transition: 'background 0.15s'
              }}>
              Send
            </button>
          </div>
          <div style={{ color: '#374151', fontSize: '10px', marginTop: '6px' }}>Enter to send · Shift+Enter for new line</div>
        </div>
      </div>

      <style>{`
        @keyframes bounce {
          0%, 60%, 100% { transform: translateY(0); }
          30% { transform: translateY(-6px); }
        }
      `}</style>
    </>
  )
}
