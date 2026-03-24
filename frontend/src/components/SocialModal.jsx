import { FaLinkedin, FaGithub, FaMediumM } from 'react-icons/fa'
import { FaXTwitter } from 'react-icons/fa6'

export default function SocialModal({ onClose }) {
  const socials = [
    { name: 'X (Twitter)', url: 'https://x.com/Vsion09', icon: <FaXTwitter />, color: '#000' },
    { name: 'LinkedIn', url: 'https://www.linkedin.com/in/shivamkumar2717/', icon: <FaLinkedin />, color: '#0A66C2' },
    { name: 'GitHub', url: 'https://github.com/shivamshrma09', icon: <FaGithub />, color: '#24292e' },
    { name: 'Medium', url: 'https://medium.com/@vsion09', icon: <FaMediumM />, color: '#000' }
  ]

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
        zIndex: 1000, width: '360px', maxWidth: '92vw',
        background: '#111',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: '20px',
        boxShadow: '0 40px 80px rgba(0,0,0,0.6)',
        overflow: 'hidden'
      }}>

        {/* Header */}
        <div style={{
          padding: '24px 28px 20px',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <div>
            <div style={{ color: 'white', fontWeight: '700', fontSize: '16px', marginBottom: '4px' }}>
              Connect with Us
            </div>
            <div style={{ color: '#4b5563', fontSize: '12px' }}>
              Follow for updates and insights
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

        {/* Social links */}
        <div style={{ padding: '24px 28px 28px', display: 'flex', justifyContent: 'center', gap: '16px' }}>
          {socials.map((social, i) => (
            <a key={i} href={social.url} target="_blank" rel="noreferrer"
              style={{
                width: '52px', height: '52px', borderRadius: '12px',
                background: social.color,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'white', fontSize: '22px', textDecoration: 'none',
                border: '1px solid rgba(255,255,255,0.08)',
                transition: 'transform 0.15s, opacity 0.15s'
              }}
              onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.1)'}
              onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}>
              {social.icon}
            </a>
          ))}
        </div>
      </div>
    </>
  )
}
