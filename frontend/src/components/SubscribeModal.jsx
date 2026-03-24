import { useState } from 'react'

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000'

export default function SubscribeModal({ onClose }) {
  const [email, setEmail] = useState('')
  const [purl, setPurl] = useState('')
  const [status, setStatus] = useState(null)
  const [message, setMessage] = useState('')
  const [emailFocused, setEmailFocused] = useState(false)
  const [purlFocused, setPurlFocused] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setStatus('loading')
    setMessage('')
    try {
      const res = await fetch(`${BACKEND_URL}/subscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), purl: purl.trim() })
      })
      const data = await res.json()
      if (!res.ok) { setStatus('error'); setMessage(data.error || 'Something went wrong.') }
      else setStatus('success')
    } catch {
      setStatus('error')
      setMessage('Could not connect to server.')
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose} style={{
        position: 'fixed', inset: 0, zIndex: 999,
        background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)'
      }} />

      {/* Card */}
      <div style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        zIndex: 1000, width: '420px', maxWidth: '94vw',
        background: '#111',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: '20px',
        boxShadow: '0 40px 80px rgba(0,0,0,0.6)',
        overflow: 'hidden'
      }}>

        {status === 'success' ? (
          /* ── Success State ── */
          <div style={{ padding: '40px 32px', textAlign: 'center' }}>
            <div style={{
              width: '56px', height: '56px', borderRadius: '50%',
              background: 'rgba(74,222,128,0.1)',
              border: '1px solid rgba(74,222,128,0.25)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 20px', color: '#4ade80', fontSize: '24px'
            }}>✓</div>
            <div style={{ color: 'white', fontWeight: '700', fontSize: '17px', marginBottom: '10px' }}>
              Subscribed!
            </div>
            <div style={{ color: '#6b7280', fontSize: '13px', lineHeight: '1.8', marginBottom: '28px' }}>
              We'll notify <span style={{ color: '#e5e7eb', fontWeight: '500' }}>{email}</span> when<br />
              <span style={{ color: '#60a5fa', fontFamily: 'monospace', fontSize: '12px' }}>{purl}</span><br />
              receives a vulnerability update.
            </div>
            <button onClick={onClose} style={{
              background: '#D97757', border: 'none', color: 'white',
              padding: '10px 32px', borderRadius: '10px',
              fontSize: '13px', fontWeight: '600', cursor: 'pointer'
            }}>Done</button>
          </div>

        ) : (
          /* ── Form State ── */
          <>
            {/* Header */}
            <div style={{
              padding: '24px 28px 20px',
              borderBottom: '1px solid rgba(255,255,255,0.05)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start'
            }}>
              <div>
                <div style={{ color: 'white', fontWeight: '700', fontSize: '16px', marginBottom: '4px' }}>
                  Package Alerts
                </div>
                <div style={{ color: '#4b5563', fontSize: '12px' }}>
                  Get notified on new vulnerability updates
                </div>
              </div>
              <button onClick={onClose} style={{
                background: 'rgba(255,255,255,0.05)', border: 'none',
                color: '#9ca3af', cursor: 'pointer',
                width: '28px', height: '28px', borderRadius: '8px',
                fontSize: '16px', display: 'flex', alignItems: 'center',
                justifyContent: 'center', flexShrink: 0
              }}>×</button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} style={{ padding: '24px 28px 28px' }}>

              {/* Email field */}
              <div style={{ marginBottom: '16px' }}>
                <label style={{
                  display: 'block', color: '#6b7280', fontSize: '11px',
                  fontWeight: '600', letterSpacing: '0.06em',
                  textTransform: 'uppercase', marginBottom: '7px'
                }}>Email</label>
                <input
                  type="email" value={email} required
                  onChange={e => setEmail(e.target.value)}
                  onFocus={() => setEmailFocused(true)}
                  onBlur={() => setEmailFocused(false)}
                  placeholder="you@example.com"
                  style={{
                    width: '100%', background: '#0d0d0d',
                    border: `1px solid ${emailFocused ? 'rgba(217,119,87,0.6)' : 'rgba(255,255,255,0.06)'}`,
                    borderRadius: '10px', outline: 'none',
                    color: 'white', fontSize: '13px',
                    padding: '11px 14px', boxSizing: 'border-box',
                    transition: 'border-color 0.2s'
                  }}
                />
              </div>

              {/* PURL field */}
              <div style={{ marginBottom: '22px' }}>
                <label style={{
                  display: 'block', color: '#6b7280', fontSize: '11px',
                  fontWeight: '600', letterSpacing: '0.06em',
                  textTransform: 'uppercase', marginBottom: '7px'
                }}>Package PURL</label>
                <input
                  type="text" value={purl} required
                  onChange={e => setPurl(e.target.value)}
                  onFocus={() => setPurlFocused(true)}
                  onBlur={() => setPurlFocused(false)}
                  placeholder="pkg:npm/lodash@4.17.21"
                  style={{
                    width: '100%', background: '#0d0d0d',
                    border: `1px solid ${purlFocused ? 'rgba(217,119,87,0.6)' : 'rgba(255,255,255,0.06)'}`,
                    borderRadius: '10px', outline: 'none',
                    color: '#60a5fa', fontSize: '12px',
                    padding: '11px 14px', boxSizing: 'border-box',
                    fontFamily: 'monospace', transition: 'border-color 0.2s'
                  }}
                />
                <div style={{ color: '#374151', fontSize: '11px', marginTop: '6px', paddingLeft: '2px' }}>
                  Format: pkg:type/name@version
                </div>
              </div>

              {/* Error */}
              {status === 'error' && (
                <div style={{
                  background: 'rgba(239,68,68,0.07)',
                  border: '1px solid rgba(239,68,68,0.15)',
                  borderRadius: '8px', padding: '10px 14px',
                  color: '#f87171', fontSize: '12px', marginBottom: '16px'
                }}>{message}</div>
              )}

              {/* Submit */}
              <button type="submit" disabled={status === 'loading'} style={{
                width: '100%',
                background: status === 'loading' ? '#1f2937' : '#D97757',
                border: 'none', color: 'white', padding: '12px',
                borderRadius: '10px', fontSize: '13px', fontWeight: '600',
                cursor: status === 'loading' ? 'not-allowed' : 'pointer',
                transition: 'background 0.15s, opacity 0.15s',
                opacity: status === 'loading' ? 0.7 : 1
              }}>
                {status === 'loading' ? 'Subscribing...' : 'Subscribe'}
              </button>
            </form>
          </>
        )}
      </div>
    </>
  )
}
