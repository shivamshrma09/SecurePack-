import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import SubscribeModal from './SubscribeModal'

const NAV = [
  { label: 'Search',          path: '/' },
  { label: 'Compare Package', path: '/compare_package' },
  { label: 'Docs',            href: 'https://vulnerablecode.readthedocs.io/en/latest/' },
]

export default function Navbar() {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const [showSubscribe, setShowSubscribe] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <>
      <nav style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        width: '100%', maxWidth: '1000px', marginTop: '16px', padding: '8px 20px',
        border: '1px solid rgba(115,115,115,0.25)', borderRadius: '16px',
        background: 'rgba(26,26,26,0.8)', backdropFilter: 'blur(10px)', flexShrink: 0,
        position: 'relative'
      }}>
        {/* Logo */}
        <h1 onClick={() => { navigate('/'); setMenuOpen(false) }}
          style={{ fontSize: '20px', fontWeight: '700', color: '#D97757', margin: 0, cursor: 'pointer', whiteSpace: 'nowrap' }}>
          Secure<span style={{ color: 'white', fontWeight: '600' }}>Pack</span>
        </h1>

        {/* Desktop nav links */}
        <div className="nav-links" style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          {NAV.map(({ label, path, href }) =>
            href ? (
              <a key={label} href={href} target="_blank" rel="noreferrer"
                style={{ color: 'rgba(255,255,255,0.55)', fontSize: '13px', textDecoration: 'none', transition: 'color 0.15s' }}
                onMouseEnter={e => e.currentTarget.style.color = 'white'}
                onMouseLeave={e => e.currentTarget.style.color = 'rgba(255,255,255,0.55)'}>
                {label}
              </a>
            ) : (
              <span key={label} onClick={() => navigate(path)}
                style={{
                  color: pathname === path ? '#D97757' : 'rgba(255,255,255,0.55)',
                  fontSize: '13px', cursor: 'pointer', whiteSpace: 'nowrap',
                  borderBottom: pathname === path ? '1px solid #D97757' : '1px solid transparent',
                  paddingBottom: '2px', transition: 'color 0.15s'
                }}
                onMouseEnter={e => { if (pathname !== path) e.currentTarget.style.color = 'white' }}
                onMouseLeave={e => { if (pathname !== path) e.currentTarget.style.color = 'rgba(255,255,255,0.55)' }}>
                {label}
              </span>
            )
          )}
        </div>

        {/* Right side */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button onClick={() => setShowSubscribe(true)} className="nav-subscribe"
            style={{ background: '#D97757', border: 'none', color: 'white', padding: '7px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '500', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            Subscribe
          </button>

          {/* Hamburger — mobile only */}
          <button onClick={() => setMenuOpen(p => !p)}
            style={{
              display: 'none', background: 'none', border: '1px solid rgba(115,115,115,0.3)',
              borderRadius: '7px', padding: '6px 9px', cursor: 'pointer', color: 'white',
              fontSize: '16px', lineHeight: 1
            }}
            className="hamburger">
            {menuOpen ? '✕' : '☰'}
          </button>
        </div>

        {/* Mobile dropdown */}
        {menuOpen && (
          <div style={{
            position: 'absolute', top: 'calc(100% + 8px)', left: 0, right: 0,
            background: '#1a1a1a', border: '1px solid rgba(115,115,115,0.2)',
            borderRadius: '12px', padding: '8px', zIndex: 100,
            display: 'flex', flexDirection: 'column', gap: '2px'
          }}>
            {NAV.map(({ label, path, href }) =>
              href ? (
                <a key={label} href={href} target="_blank" rel="noreferrer"
                  onClick={() => setMenuOpen(false)}
                  style={{ color: 'rgba(255,255,255,0.7)', fontSize: '14px', textDecoration: 'none', padding: '10px 14px', borderRadius: '8px' }}>
                  {label}
                </a>
              ) : (
                <span key={label} onClick={() => { navigate(path); setMenuOpen(false) }}
                  style={{
                    color: pathname === path ? '#D97757' : 'rgba(255,255,255,0.7)',
                    fontSize: '14px', cursor: 'pointer', padding: '10px 14px', borderRadius: '8px',
                    background: pathname === path ? 'rgba(217,119,87,0.08)' : 'transparent'
                  }}>
                  {label}
                </span>
              )
            )}
          </div>
        )}
      </nav>

      {showSubscribe && <SubscribeModal onClose={() => setShowSubscribe(false)} />}

      <style>{`
        @media (max-width: 768px) {
          .nav-links { display: none !important; }
          .hamburger { display: block !important; }
        }
      `}</style>
    </>
  )
}
