
import { useState } from 'react'

function ContextPanel() {
  const [selectedLocation, setSelectedLocation] = useState('Main Gate')
  const [selectedSchedule, setSelectedSchedule] = useState('Morning Shift')

  const locations = ['Main Gate', 'Research Lab', 'Library', 'Data Center']

  return (
    <section className="panel context-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">INTELLIGENT ACCESS POLICY</span>
          <h2>Context-Aware Access</h2>
          <p>Verify access against campus policies</p>
        </div>
        <span className="policy-tag">POLICY ENGINE</span>
      </div>

      <div className="context-fields">
        <div className="context-field">
          <label htmlFor="location">ACCESS LOCATION</label>
          <select
            id="location"
            value={selectedLocation}
            onChange={(event) => setSelectedLocation(event.target.value)}
          >
            {locations.map((location) => (
              <option key={location} value={location}>
                {location}
              </option>
            ))}
          </select>
        </div>

        <div className="context-field">
          <label htmlFor="schedule">ACCESS SCHEDULE</label>
          <select
            id="schedule"
            value={selectedSchedule}
            onChange={(event) => setSelectedSchedule(event.target.value)}
          >
            <option>Morning Shift</option>
            <option>Afternoon Shift</option>
            <option>Evening Shift</option>
            <option>Weekend Access</option>
          </select>
        </div>
      </div>

      <div className="context-summary">
        <div className="context-row">
          <span>Selected location</span>
          <strong>{selectedLocation}</strong>
        </div>

        <div className="context-row">
          <span>Selected schedule</span>
          <strong>{selectedSchedule}</strong>
        </div>

        <div className="context-row">
          <span>Policy evaluation</span>
          <span className="pending-badge">NOT EVALUATED</span>
        </div>
      </div>

      <p className="demo-notice">
        Demo configuration only. The backend must validate actual access schedules and permissions.
      </p>
    </section>
  )
}

export default ContextPanel
