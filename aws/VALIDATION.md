# Deployment Validation: verigate-dev

Real deployment to the hackathon AWS sandbox. All responses below are copied from live calls.
Account IDs are masked as `<account-id>`.

- Date: 2026-11-14
- Stack / region: `verigate-dev` / `us-east-1`, status **CREATE_COMPLETE**
- Caller: `WSParticipantRole/Participant` (profile `hid`)
- Parameters: `Stage=dev`, `AllowClientEvidence=true` (**demo mode**; switch to `false` once a liveness-session route exists), `BedrockModelId` empty (reports disabled)

## Deploy steps run

| Step | Command | Result |
|------|---------|--------|
| Lint | `cfn-lint aws/template.yaml` | clean |
| Build | `powershell -File aws\build.ps1` | Linux wheels (`*-x86_64-linux-gnu.so`), tests excluded |
| Artifact bucket | `aws s3api create-bucket --bucket verigate-artifacts-<account-id>-us-east-1` + public access block | created, SSE `AES256` |
| Package | `aws cloudformation package --s3-prefix verigate-dev` | 11,168,337-byte code zip uploaded |
| Deploy | `aws cloudformation deploy --stack-name verigate-dev --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --parameter-overrides Stage=dev AllowClientEvidence=true` | `Successfully created/updated stack` |
| Seed | `.venv\Scripts\python.exe aws\dynamodb\seed.py --stage dev` | `Seeded 3 identities, 2 grants, 1 revocations (synthetic).` |

The org SCP did **not** block CloudFormation, IAM role creation, Lambda, API Gateway, DynamoDB or S3.

## Stack outputs

| Output | Value |
|--------|-------|
| ApiUrl | `https://y6v7j9rp2j.execute-api.us-east-1.amazonaws.com` |
| FunctionName | `verigate-dev-api` |
| IdentitiesTableName | `verigate-dev-identities` |
| AuthorizationTableName | `verigate-dev-authorization` |
| RevocationsTableName | `verigate-dev-revocations` |
| AuditTableName | `verigate-dev-audit` |
| FaceRefsBucketName | `verigate-dev-face-refs-<account-id>` |

## Live API responses

```
GET /health                      -> HTTP 200  {"status":"ok"}   3.47 s (cold start)
GET /health                      -> HTTP 200  {"status":"ok"}   0.76 s (warm, includes network)
GET /openapi.json  paths         -> ['/api/v1/face-auth/recognize', '/health']
POST /decision/evaluate          -> HTTP 404  {"detail":"Not Found"}
```

`/decision/*` returns 404 because `backend/app/main.py` does not include the decision router yet.
That file is owned by Shreya; the two lines she needs to add:

```python
from backend.modules.decision_engine.api import router as decision_engine_router
app.include_router(decision_engine_router)
```

## Lambda runtime evidence

| Check | Result |
|-------|--------|
| Runtime / arch / memory / timeout | `python3.12` / `x86_64` / 1024 MB / 30 s, state `Active` |
| Env | `ALLOW_CLIENT_EVIDENCE=true`, `FACE_REFERENCE_BUCKET=verigate-dev-face-refs-<account-id>` |
| Cold start (CloudWatch REPORT) | `Init Duration: 1338.27 ms`, first request `123.63 ms`, max memory 104 MB |
| Warm requests | 1.93 ms - 12.20 ms |
| Errors / tracebacks in logs | none |
| Reserved concurrency on `verigate-dev-api` | none set; no 429 / throttling seen |
| Log retention | 7 days |

## Data layer evidence (real DynamoDB, read-only, from a laptop with the same code)

Item counts after seeding: identities 3, authorization 2, revocations 1, audit 0.

`ContextLoader` against the live tables plus `decide()`:

```
P001 LAB3 by person            person=P001 schedule_ok=True  revoked=False fresh=True -> ALLOW: live person and identity verified
CARD-A1 LAB3 by card (GSI)     person=P001 schedule_ok=True  revoked=False fresh=True -> ALLOW: live person and identity verified
P002 LAB3 suspended            person=P002 schedule_ok=False revoked=False fresh=True -> DENY: person is suspended (disciplinary record)
CARD-X9 revoked/unknown card   person=None schedule_ok=False revoked=True  fresh=True -> DENY: identity not found in campus records
```

This proves the seed data, the `by-card` GSI, grant windows and revocation lookups work on the real tables.
It ran with the caller's credentials, **not** the Lambda role, so the Lambda's IAM for these reads is verified only once the route is live.

## Face reference bucket

| Setting | Result |
|---------|--------|
| Public access block | all four `true` |
| Encryption | SSE-S3 (template `AES256`) |
| Lifecycle | `delete-face-refs-after-7-days`, Enabled, 7 days |
| Versioning | never enabled |
| Bucket policy | denies non-TLS access |

## Not yet verified live

- `/decision/evaluate` and `/decision/offline-sync` through API Gateway (blocked on the `include_router` lines).
- Audit hash chain on the real audit table (no route has written to it yet).
- Rekognition Face Liveness (no route creates sessions yet) and CompareFaces with S3 references (needs Shreya's S3 provider and an uploaded `<person_id>.jpg`).
- Bedrock invoke (checkpoint 5).
