import Navbar from '../components/Navbar'

export default function Dashboard() {
  return (
    <div style={{ minHeight: '100vh', background: '#121212', color: 'white', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <Navbar />
      <div style={{ marginTop: '120px', textAlign: 'center', color: '#4b5563' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>📊</div>
        <div style={{ fontSize: '20px', fontWeight: '600', color: '#6b7280' }}>Dashboard</div>
        <div style={{ fontSize: '13px', marginTop: '8px' }}>Coming soon...</div>
      </div>
    </div>
  )
}
