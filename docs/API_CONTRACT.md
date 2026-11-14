# VERIGATE API Contract

Initial outline for the backend API contract.

## Status

The current phase provides only the service health endpoint. Face
authentication endpoints will be specified before implementation.

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

## Planned face authentication contract

The future face authentication response will keep liveness and identity
recognition as separate processing results, including their status, confidence
or evidence fields, and an overall module result.
