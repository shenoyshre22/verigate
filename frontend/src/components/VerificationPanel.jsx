
import { useEffect, useRef, useState } from 'react'

function VerificationPanel() {
  const videoRef = useRef(null)
  const streamRef = useRef(null)

  const [cameraActive, setCameraActive] = useState(false)
  const [cameraStarting, setCameraStarting] = useState(false)
  const [cameraError, setCameraError] = useState('')

  async function startCamera() {
    try {
      setCameraError('')
      setCameraStarting(true)

      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error(
          'Camera API unavailable. Open this app using localhost or HTTPS.'
        )
      }

      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: false,
      })

      streamRef.current = stream

      const video = videoRef.current

      if (!video) {
        throw new Error('Video preview element was not found.')
      }

      video.srcObject = stream
      await video.play()

      setCameraActive(true)
    } catch (error) {
      streamRef.current?.getTracks().forEach((track) => track.stop())
      streamRef.current = null

      setCameraActive(false)

      if (error.name === 'NotAllowedError') {
        setCameraError('Camera permission denied. Allow camera access in Chrome settings.')
      } else if (error.name === 'NotFoundError') {
        setCameraError('No camera detected. Check your camera connection.')
      } else if (error.name === 'NotReadableError') {
        setCameraError('Camera is being used by another app. Close other camera apps and retry.')
      } else {
        setCameraError(error.message || 'Unable to start camera.')
      }

      console.error('Camera error:', error)
    } finally {
      setCameraStarting(false)
    }
  }

  function stopCamera() {
    streamRef.current?.getTracks().forEach((track) => track.stop())
    streamRef.current = null

    if (videoRef.current) {
      videoRef.current.srcObject = null
    }

    setCameraActive(false)
    setCameraError('')
  }

  useEffect(() => {
    return () => {
      streamRef.current?.getTracks().forEach((track) => track.stop())
    }
  }, [])

  return (
    <section className="panel verification-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">BIOMETRIC AUTHENTICATION</span>
          <h2>Face Verification</h2>
          <p>Primary identity and liveness verification</p>
        </div>
        <span className="live-tag">● LIVE CAMERA</span>
      </div>

      <div className="camera-container">
        <video
          ref={videoRef}
          className="camera-video"
          autoPlay
          muted
          playsInline
          style={{ opacity: cameraActive ? 1 : 0 }}
        />

        {!cameraActive && (
          <div className="camera-placeholder">
            <div className="camera-symbol">◎</div>
            <h3>Camera is ready</h3>
            <p>Start the camera to begin face capture</p>
          </div>
        )}

        {cameraActive && (
          <div className="camera-overlay">
            <span>CAMERA ACTIVE</span>
            <div className="face-frame" />
          </div>
        )}
      </div>

      {cameraError && (
        <p className="error-message">{cameraError}</p>
      )}

      <div className="camera-actions">
        {!cameraActive ? (
          <button
            className="primary-button"
            onClick={startCamera}
            disabled={cameraStarting}
          >
            {cameraStarting ? 'Starting Camera...' : '◎ Start Camera'}
          </button>
        ) : (
          <button
            className="secondary-button"
            onClick={stopCamera}
          >
            ■ Stop Camera
          </button>
        )}
      </div>

      <div className="verification-checks">
        <div className="verification-check">
          <div className="check-icon">◉</div>
          <div>
            <strong>Face Liveness</strong>
            <span>Awaiting AWS verification</span>
          </div>
          <span className="pending-badge">PENDING</span>
        </div>

        <div className="verification-check">
          <div className="check-icon">⌕</div>
          <div>
            <strong>Identity Match</strong>
            <span>Awaiting face comparison</span>
          </div>
          <span className="pending-badge">PENDING</span>
        </div>
      </div>

      <p className="demo-notice">
        Camera capture only. Liveness and identity are not yet verified.
      </p>
    </section>
  )
}

export default VerificationPanel
