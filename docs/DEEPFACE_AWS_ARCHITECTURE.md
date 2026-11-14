# DeepFace and AWS architecture assessment

## Current AWS pieces in the repository

`aws/template.yaml` defines an HTTP API, a Python 3.12 Lambda, DynamoDB tables for identity/authorization/revocation/audit data, a private S3 face-reference bucket, and scoped policies. The template is infrastructure code; this work did not deploy or modify AWS resources. The face-reference bucket currently has a seven-day lifecycle, which is not suitable for durable student enrollment without an explicit retention decision. The API template currently has no JWT authorizer.

The existing face-authentication code calls Rekognition for face detection and comparison. The liveness module calls Rekognition for liveness sessions. The Lambda role currently grants S3 reference reads and Rekognition actions; it does not grant an enrollment workflow's write permissions. DeepFace's upstream S3 file store uses boto3's default credential chain, but the upstream implementation does not add VERIGATE authentication, campus identity mapping, or DynamoDB storage.

## Service decision

| Service | Assessment for this integration |
|---|---|
| Amazon Rekognition | Retain as the current production face-comparison and liveness provider for Lambda. This avoids deploying a second inference stack before DeepFace's model footprint and latency are measured. |
| DeepFace | Imported unchanged and exposed through an optional 1:1 adapter for isolated evaluation. Its ONNX, TensorFlow, and PyTorch paths have different native dependencies and model files; the source tree alone is not a runnable inference deployment. |
| DynamoDB | Existing identity and audit tables can hold campus identity metadata and references, but no DeepFace-specific table or adapter is present. A DynamoDB scan is not a vector-search design. Do not store raw biometric images or unencrypted embeddings there. |
| S3 | The existing bucket is private and encrypted, but its seven-day expiration conflicts with durable enrollment. Do not upload reference images until retention, deletion, encryption-key ownership, consent, and access authorization are decided. |
| Lambda | Suitable for existing API orchestration and metadata work. Do not assume it is suitable for DeepFace inference until package/model size, cold start, memory, and latency are measured. |
| API Gateway | Provides the current HTTP boundary, but the template has no authorizer. Enrollment and trusted-evidence routes must wait for a verified user/device authentication design. |
| IAM | Current policies do not include biometric enrollment writes. Add only the exact actions required after the data flow is approved. |
| Secrets Manager | No DeepFace credential is required for local model inference. AWS credentials must continue to use the configured role/credential chain; do not put credentials in source or model metadata. |
| CloudWatch | Use structured operational logs with request/attempt IDs and safe outcome codes only. Never log images, embeddings, access tokens, or secrets. |
| Bedrock | Not part of recognition or access decisions. Any later explanation feature must remain downstream and non-authoritative. |

## Recommended flow after required configuration exists

```text
Authenticated terminal/user
  -> API Gateway authorizer
  -> Lambda validates principal, attempt, and request
  -> chosen recognition provider (one provider per deployment)
  -> DynamoDB identity/enrollment metadata + approved biometric reference store
  -> trusted evidence adapter
  -> existing deterministic decision engine
  -> ALLOW / REQUEST_VERIFICATION / DENY
```

The campus user ID must come from an authenticated identity mapping, not from an arbitrary DeepFace gallery filename or client field. The engine remains authoritative, and recognition/liveness evidence cannot override suspension, revocation, mandatory failures, or authorization policy.

## Decisions still required

- Identity provider, token issuer/audience, and verified claim used for the canonical user ID.
- Authentication-attempt lifecycle and durable attempt-store owner.
- Whether production recognition remains Rekognition or moves to a measured DeepFace deployment.
- Biometric reference format and storage location; retention, consent, deletion, and model migration policy.
- Whether the existing seven-day S3 policy is temporary and what durable retention should replace it.
- Trusted device/terminal authentication and the exact API routes requiring authorization.

## Phase 2 local implementation status

The separate DeepFace 1:N module uses Windows DPAPI-protected embeddings in a local SQLite development store. It does not use DynamoDB, S3 or live AWS calls. No AWS resources were created or modified. The existing DynamoDB identity table must not be treated as a vector index.

For an AWS deployment, use DynamoDB for enrollment metadata and a stable biometric-record reference (user ID, status, model/version, timestamps, audit reference), with conditional writes and narrowly scoped IAM. Keep vector search in a purpose-built protected store such as PostgreSQL with pgvector and encryption at rest using a customer-managed KMS key, with network isolation and application-level authorization. Avoid storing biometric embeddings directly in DynamoDB unless a separate threat model and encryption design approve that choice. Do not retain raw enrollment images in S3 by default. If retention is explicitly required, use a private bucket, KMS encryption, strict lifecycle/deletion controls and audited access. This is a design recommendation only; it is not deployed or wired in this phase.

The local API router is registered, but its authentication principal, attempt provider and trusted evidence sink deliberately default to unavailable. Until the host application provides verified authentication and an approved evidence consumer, protected operations fail closed with 503. No production end-to-end enrollment or Zero Trust delivery is claimed.
