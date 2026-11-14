
import { useState } from 'react'

function OfflinePanel() {
  const [isOnline, setIsOnline] = useState(true)
  const [policyValid] = useState(true)
  const [pendingEvents, setPendingEvents] = useState(3)

  const mode = isOnline ? 'ONLINE' : 'OFFLINE'

  return (
    <section className="panel offline-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">RESILIENT ACCESS INFRASTRUCTURE</span>
          <h2>Offline Safe Mode</h2>
          <p>Connectivity and local policy monitoring</p>
        </div>
        <span className={`mode-badge ${isOnline ? 'online' : 'offline'}`}>
          ● {mode}
        </span>
      </div>

      <div className="offline-status-card">
        <div className="offline-status-icon">
          {isOnline ? '↗' : '⚡'}
        </div>
        <div>
          <strong>{isOnline ? 'Central server connected' : 'Local safe mode active'}</strong>
          <p>
            {isOnline
              ? 'Access decisions use the central authorization service.'
              : 'Central server unavailable. Local policy verification required.'}
          </p>
        </div>
      </div>

      <div className="offline-metrics">
        <div>
          <span>LOCAL POLICY</span>
          <strong className={policyValid ? 'success-text' : 'error-text'}>
            {policyValid ? 'VALID' : 'EXPIRED'}
          </strong>
        </div>

        <div>
          <span>PENDING AUDIT EVENTS</span>
          <strong>{pendingEvents}</strong>
        </div>

        <div>
          <span>DECISION MODE</span>
          <strong>{isOnline ? 'CENTRAL' : 'LOCAL'}</strong>
        </div>
      </div>

      <div className="offline-actions">
        <button
          className="secondary-button"
          onClick={() => setIsOnline((value) => !value)}
        >
          Simulate {isOnline ? 'Connection Loss' : 'Reconnection'}
        </button>

        {!isOnline && (
          <button
            className="primary-button"
            onClick={() => setPendingEvents(0)}
          >
            Simulate Audit Sync
          </button>
        )}
      </div>

      <p className="demo-notice">
        Demonstration only. Production offline authorization requires signed,
        unexpired local policy and secure credential validation. Invalid or
        unverifiable policy must result in DENY.
      </p>
    </section>
  )
}

export default OfflinePanel
