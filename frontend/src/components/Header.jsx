
import { useState } from 'react'

function Header() {
  const [notificationsOpen, setNotificationsOpen] = useState(false)

  return (
    <header className="top-header">
      <div className="header-title">
        <span className="breadcrumb">VERIGATE /</span>
        <h1>Security Overview</h1>
        <p>Real-time campus identity and access monitoring</p>
      </div>

      <div className="header-actions">
        <div className="header-clock">
          <span className="clock-dot" />
          SYSTEM ACTIVE
        </div>

        <div className="notification-wrapper">
          <button
            className="icon-button"
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            aria-label="Toggle notifications"
          >
            ♧
            <span className="notification-badge">2</span>
          </button>

          {notificationsOpen && (
            <div className="notification-dropdown">
              <h3>Notifications</h3>
              <p>System is operating in demo mode.</p>
              <p>Offline synchronization is awaiting configuration.</p>
            </div>
          )}
        </div>

        <div className="profile">
          <div className="profile-avatar">AD</div>
          <div>
            <strong>Admin</strong>
            <span>Security Operator</span>
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header
