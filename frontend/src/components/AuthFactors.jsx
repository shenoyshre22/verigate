
import { useState } from 'react'

const availableFactors = [
  {
    id: 'RFID',
    name: 'RFID Card',
    description: 'Contactless card authentication',
    icon: '▤',
  },
  {
    id: 'FINGERPRINT',
    name: 'Fingerprint',
    description: 'Biometric reader authentication',
    icon: '◉',
  },
  {
    id: 'PIN',
    name: 'Security PIN',
    description: 'Additional knowledge-based factor',
    icon: '⌗',
  },
]

function AuthFactors() {
  const [enabledFactors, setEnabledFactors] = useState(['RFID'])

  function toggleFactor(id) {
    setEnabledFactors((current) =>
      current.includes(id)
        ? current.filter((factor) => factor !== id)
        : [...current, id]
    )
  }

  return (
    <section className="panel auth-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">MULTI-FACTOR SECURITY</span>
          <h2>Authentication Factors</h2>
          <p>Configure supported additional factors</p>
        </div>
        <span className="policy-tag">MODULAR</span>
      </div>

      <div className="factor-list">
        {availableFactors.map((factor) => {
          const enabled = enabledFactors.includes(factor.id)

          return (
            <div className="factor-item" key={factor.id}>
              <div className="factor-icon">{factor.icon}</div>

              <div className="factor-info">
                <strong>{factor.name}</strong>
                <span>{factor.description}</span>
              </div>

              <button
                className={`toggle-switch ${enabled ? 'enabled' : ''}`}
                onClick={() => toggleFactor(factor.id)}
                aria-label={`Toggle ${factor.name}`}
                aria-pressed={enabled}
              >
                <span />
              </button>
            </div>
          )
        })}
      </div>

      <p className="demo-notice">
        UI configuration only. Enabling a factor does not enroll or verify a credential.
      </p>
    </section>
  )
}

export default AuthFactors
