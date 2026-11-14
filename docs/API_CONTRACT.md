# VERIGATE API Contract

Initial outline for the backend API contract.

## Status

The service health endpoint and face identity recognition endpoint are
implemented. The combined face authentication contract remains pending the
liveness service interface.

## Conventions

- JSON request and response bodies.
- Pydantic models for validation and serialization.
- Explicit authentication and verification result fields.
- Errors use standard FastAPI HTTP error responses.

## Current endpoint

### `GET /health`

Returns a lightweight service health response:

```json
{
  "status": "ok"
}
```

## Combined face authentication (pending)

The future face authentication response will keep liveness and identity
recognition as separate processing results, including their status, confidence
or evidence fields, and an overall module result.

## Face identity recognition

### `POST /api/v1/face-auth/recognize`

Accepts `multipart/form-data` with:

- `user_id`: enrolled identity identifier.
- `image`: submitted JPEG or PNG image, smaller than 5 MB.

The current development provider reads `<user_id>.jpg`, `.jpeg`, or `.png`
from `FACE_REFERENCE_DIR`. Production must use an appropriately enrolled
reference provider. The endpoint requires exactly one detectable face in each
image and returns a measured similarity score, the configured threshold, and
separate preprocessing, AWS, provider, and total recognition latency fields.

`FACE_RECOGNITION_ENGINE` selects exactly one comparison backend per process:
`rekognition` (default) or optional `deepface`. DeepFace is selected only after
installing the isolated dependencies from `backend/requirements-deepface.txt`.
The recognition route remains 1:1 against the submitted `user_id`; it does not
perform campus-wide identity retrieval or create trusted decision-engine
evidence.

The response status is `MATCH` or `NO_MATCH`. It describes identity recognition
only; it is not the combined Face Authentication decision. The configurable
similarity threshold is not a claim of security or accuracy.

Expected HTTP errors include 400 for invalid image data, 404 for a missing
reference, 413 for an oversized upload, 422 for no or multiple faces, 502 for
provider errors or denied AWS access, 503 for throttling/unconfigured provider,
and 504 for upstream timeouts.

The combined `POST /api/v1/face-auth/verify` endpoint is intentionally not
finalized until the liveness provider's user and attempt correlation contract
is documented and coordinated.
