
import { useState } from 'react'

const initialLogs = [
  {
    id: 1,
    user: 'EMP-1024',
    location: 'Main Gate',
    method: 'Face + RFID',
    decision: 'ALLOW',
    time: '09:42:18',
    mode: 'ONLINE',
  },
  {
    id: 2,
    user: 'EMP-1088',
    location: 'Research Lab',
    method: 'Face + Fingerprint',
    decision: 'STEP-UP',
    time: '09:38:52',
    mode: 'ONLINE',
  },
  {
    id: 3,
    user: 'EMP-1042',
    location: 'Library',
    method: 'Face',
    decision: 'DENY',
    time: '09:31:06',
    mode: 'OFFLINE',
  },
]

function AccessLogs() {
  const [filter, setFilter] = useState('ALL')

  const filteredLogs = initialLogs.filter((log) =>
    filter === 'ALL' ? true : log.decision === filter
  )

  return (
    <section className="panel logs-panel">
      <div className="panel-heading logs-heading">
        <div>
          <span className="eyebrow">SECURITY AUDIT TRAIL</span>
          <h2>Recent Access Events</h2>
          <p>Demonstration access records</p>
        </div>

        <select
          aria-label="Filter access logs"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          className="log-filter"
        >
          <option value="ALL">All events</option>
          <option value="ALLOW">Allowed</option>
          <option value="STEP-UP">Step-up</option>
          <option value="DENY">Denied</option>
        </select>
      </div>

      <div className="logs-table-wrapper">
        <table className="logs-table">
          <thead>
            <tr>
              <th>USER ID</th>
              <th>LOCATION</th>
              <th>AUTHENTICATION</th>
              <th>DECISION</th>
              <th>MODE</th>
              <th>TIME</th>
            </tr>
          </thead>

          <tbody>
            {filteredLogs.map((log) => (
              <tr key={log.id}>
                <td>{log.user}</td>
                <td>{log.location}</td>
                <td>{log.method}</td>
                <td>
                  <span className={`decision-badge ${log.decision.toLowerCase()}`}>
                    {log.decision}
                  </span>
                </td>
                <td>{log.mode}</td>
                <td>{log.time}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredLogs.length === 0 && (
          <p className="empty-logs">No events match this filter.</p>
        )}
      </div>

      <p className="demo-notice">
        Sample records for UI demonstration. Production logs will come from the backend.
      </p>
    </section>
  )
}

export default AccessLogs
