# VERIGATE Testing

Initial testing outline for the Python backend.

## Tools

- Pytest for automated tests.
- FastAPI's test client for HTTP behavior.
- Mocked Rekognition clients for automated tests; pytest must not call live AWS.

## Current checks

- Verify the FastAPI application imports successfully.
- Verify `GET /health` returns HTTP 200 and `{"status": "ok"}`.
- Verify face image validation and identity recognition using mocked provider
  responses.

## Planned face authentication coverage

- Liveness and identity results are represented separately.
- Genuine live faces can be accepted when identity verification matches.
- Spoof or identity mismatch results are rejected.
- Invalid requests return explicit validation errors.
- AWS integrations are tested without requiring credentials or live resources.

Recognition evaluation procedure: use a consented, access-controlled dataset
with distinct genuine and impostor comparison pairs. Fix the enrolled reference
set and decision threshold before evaluation, record each pair's ground-truth
label and recognition result, then compute Genuine Match Rate, False Acceptance
Rate, and False Rejection Rate from the resulting counts. Report the dataset
composition, threshold, exclusions, and sample counts. Measure end-to-end
recognition latency and report p50, p95, and p99 only when sample counts are
sufficient; label all other values as illustrative. Synthetic unit-test images
and mocked AWS results are not accuracy measurements.
