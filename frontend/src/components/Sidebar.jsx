
const navigation = [
  { icon: '◈', label: 'Overview' },
  { icon: '◎', label: 'Face Verification' },
  { icon: '▦', label: 'Access Control' },
  { icon: '⌁', label: 'Authentication Factors' },
  { icon: '◷', label: 'Access Logs' },
  { icon: '⚙', label: 'Settings' },
]

function Sidebar({ activeSection, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">V</div>
        <div>
          <h2>VeriGate</h2>
          <span>SECURE CAMPUS ACCESS</span>
        </div>
      </div>

      <div className="nav-label">MAIN MENU</div>

      <nav className="navigation">
        {navigation.map((item) => (
          <button
            key={item.label}
            type="button"
            onClick={() => onNavigate(item.label)}
            className={`nav-item ${
              activeSection === item.label ? 'active' : ''
            }`}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="security-indicator">
          <span className="status-dot" />
          Security systems active
        </div>
        <p>VeriGate v1.0.0</p>
      </div>
    </aside>
  )
}

export default Sidebar
