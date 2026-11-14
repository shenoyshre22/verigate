# VERIGATE Testing

Initial testing outline for the Python backend.

## Tools

- Pytest for automated tests.
- FastAPI's test client for HTTP behavior.
- Mocked service clients for future Amazon Rekognition and AWS integrations.

## Current checks

- Verify the FastAPI application imports successfully.
- Verify `GET /health` returns HTTP 200 and `{"status": "ok"}`.

## Planned face authentication coverage

- Liveness and identity results are represented separately.
- Genuine live faces can be accepted when identity verification matches.
- Spoof or identity mismatch results are rejected.
- Invalid requests return explicit validation errors.
- AWS integrations are tested without requiring credentials or live resources.
