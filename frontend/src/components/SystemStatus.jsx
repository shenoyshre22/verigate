
function SystemStatus({ online }) {
  return (
    <div>
      <h2>System Status</h2>
      <p data-testid="system-status">
        {online ? 'ONLINE' : 'OFFLINE'}
      </p>
    </div>
  )
}

export default SystemStatus
