
import { useState } from 'react'

import Sidebar from './components/Sidebar'
import Header from './components/Header'
import VerificationPanel from './components/VerificationPanel'
import ContextPanel from './components/ContextPanel'
import AuthFactors from './components/AuthFactors'
import OfflinePanel from './components/OfflinePanel'
import AccessLogs from './components/AccessLogs'
import SystemStatus from './components/SystemStatus'
import './App.css'

function App() {
  const [activeSection, setActiveSection] = useState('Overview')

  function renderSection() {
    switch (activeSection) {
      case 'Face Verification':
        return (
          <>
            <div className="welcome-banner">
              <div>
                <span className="eyebrow">IDENTITY SECURITY</span>
                <h2>Face Verification</h2>
                <p>
                  Capture a face for verification. Live liveness and identity
                  checks will be connected to the backend.
                </p>
              </div>
            </div>
            <div className="dashboard-grid">
              <VerificationPanel />
            </div>
          </>
        )

      case 'Access Control':
        return (
          <>
            <div className="welcome-banner">
              <div>
                <span className="eyebrow">CAMPUS ACCESS POLICIES</span>
                <h2>Access Control</h2>
                <p>
                  Review location, schedule and offline access settings.
                </p>
              </div>
            </div>
            <div className="dashboard-grid">
              <ContextPanel />
              <OfflinePanel />
            </div>
          </>
        )

      case 'Authentication Factors':
        return (
          <>
            <div className="welcome-banner">
              <div>
                <span className="eyebrow">MULTI-FACTOR SECURITY</span>
                <h2>Authentication Factors</h2>
                <p>
                  Manage the available additional verification factors.
                </p>
              </div>
            </div>
            <div className="dashboard-grid">
              <AuthFactors />
            </div>
          </>
        )

      case 'Access Logs':
        return (
          <>
            <div className="welcome-banner">
              <div>
                <span className="eyebrow">SECURITY AUDIT</span>
                <h2>Access Logs</h2>
                <p>
                  Review recorded campus access decisions.
                </p>
              </div>
            </div>
            <AccessLogs />
          </>
        )

      case 'Settings':
        return (
          <>
            <div className="welcome-banner">
              <div>
                <span className="eyebrow">SYSTEM CONFIGURATION</span>
                <h2>Settings</h2>
                <p>
                  VeriGate system information and configuration status.
                </p>
              </div>
            </div>

            <div className="dashboard-grid">
              <section className="panel">
                <h3>System Information</h3>
                <p>Application: VeriGate</p>
                <p>Version: 1.0.0</p>
                <p>AWS Region: us-east-1</p>
                <p>Environment: Frontend demo</p>
              </section>

              <section className="panel">
                <h3>Security Principles</h3>
                <p>Failed liveness must never be overridden.</p>
                <p>Access decisions must be fail-safe.</p>
                <p>Backend policy determines final authorization.</p>
              </section>
            </div>
          </>
        )

      default:
        return (
          <>
            <div className="welcome-banner">
              <div>
                <span className="eyebrow">CAMPUS SECURITY INTELLIGENCE</span>
                <h2>Welcome to VeriGate <span>✦</span></h2>
                <p>
                  Intelligent identity verification and secure campus access,
                  all in one place.
                </p>
              </div>

              <div className="welcome-decoration">
                <div className="orbit orbit-one" />
                <div className="orbit orbit-two" />
                <div className="shield-symbol">⬡</div>
              </div>
            </div>

            <div className="overview-grid">
              <div className="stat-card">
                <span className="stat-icon blue">◎</span>
                <span className="stat-label">SYSTEM STATUS</span>
                <strong><SystemStatus online={true} /></strong>
                <span className="stat-caption">Demo connectivity state</span>
              </div>

              <div className="stat-card">
                <span className="stat-icon green">✓</span>
                <span className="stat-label">AUTHENTICATION</span>
                <strong>Multi-factor</strong>
                <span className="stat-caption">Modular security enabled</span>
              </div>

              <div className="stat-card">
                <span className="stat-icon purple">⌁</span>
                <span className="stat-label">ACCESS POLICY</span>
                <strong>Context-aware</strong>
                <span className="stat-caption">Schedule + location checks</span>
              </div>

              <div className="stat-card">
                <span className="stat-icon orange">◷</span>
                <span className="stat-label">SECURITY MODE</span>
                <strong>Fail-safe</strong>
                <span className="stat-caption">Never fail open</span>
              </div>
            </div>

            <div className="dashboard-grid">
              <VerificationPanel />
              <ContextPanel />
              <AuthFactors />
              <OfflinePanel />
            </div>

            <AccessLogs />
          </>
        )
    }
  }

  return (
    <div className="app-shell">
      <Sidebar
        activeSection={activeSection}
        onNavigate={setActiveSection}
      />

      <main className="main-content">
        <Header />

        <div className="dashboard-content">
          {renderSection()}

          <footer className="dashboard-footer">
            <span>VERIGATE © 2026</span>
            <span>SECURE ACCESS · PRIVACY FIRST · FAIL-SAFE BY DESIGN</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

export default App



// import Sidebar from './components/Sidebar'
// import Header from './components/Header'
// import VerificationPanel from './components/VerificationPanel'
// import ContextPanel from './components/ContextPanel'
// import AuthFactors from './components/AuthFactors'
// import OfflinePanel from './components/OfflinePanel'
// import AccessLogs from './components/AccessLogs'
// import SystemStatus from './components/SystemStatus'
// import './App.css'

// function App() {
//   return (
//     <div className="app-shell">
//       <Sidebar />

//       <main className="main-content">
//         <Header />

//         <div className="dashboard-content">
//           <div className="welcome-banner">
//             <div>
//               <span className="eyebrow">CAMPUS SECURITY INTELLIGENCE</span>
//               <h2>Welcome to VeriGate <span>✦</span></h2>
//               <p>
//                 Intelligent identity verification and secure campus access,
//                 all in one place.
//               </p>
//             </div>

//             <div className="welcome-decoration">
//               <div className="orbit orbit-one" />
//               <div className="orbit orbit-two" />
//               <div className="shield-symbol">⬡</div>
//             </div>
//           </div>

//           <div className="overview-grid">
//             <div className="stat-card">
//               <span className="stat-icon blue">◎</span>
//               <span className="stat-label">SYSTEM STATUS</span>
//               <strong><SystemStatus online={true} /></strong>
//               <span className="stat-caption">Demo connectivity state</span>
//             </div>

//             <div className="stat-card">
//               <span className="stat-icon green">✓</span>
//               <span className="stat-label">AUTHENTICATION</span>
//               <strong>Multi-factor</strong>
//               <span className="stat-caption">Modular security enabled</span>
//             </div>

//             <div className="stat-card">
//               <span className="stat-icon purple">⌁</span>
//               <span className="stat-label">ACCESS POLICY</span>
//               <strong>Context-aware</strong>
//               <span className="stat-caption">Schedule + location checks</span>
//             </div>

//             <div className="stat-card">
//               <span className="stat-icon orange">◷</span>
//               <span className="stat-label">SECURITY MODE</span>
//               <strong>Fail-safe</strong>
//               <span className="stat-caption">Never fail open</span>
//             </div>
//           </div>

//           <div className="dashboard-grid">
//             <VerificationPanel />
//             <ContextPanel />
//             <AuthFactors />
//             <OfflinePanel />
//           </div>

//           <AccessLogs />

//           <footer className="dashboard-footer">
//             <span>VERIGATE © 2026</span>
//             <span>SECURE ACCESS · PRIVACY FIRST · FAIL-SAFE BY DESIGN</span>
//           </footer>
//         </div>
//       </main>
//     </div>
//   )
// }

// export default App
