# Deployment Validation: verigate-dev

Real deployment to the hackathon AWS sandbox. All responses below are copied from live calls.
Account IDs are masked as `<account-id>`.

- Date: 2026-11-14
- Stack / region: `verigate-dev` / `us-east-1`, status **CREATE_COMPLETE**
- Caller: `WSParticipantRole/Participant` (profile `hid`)
- Parameters: `Stage=dev`, `AllowClientEvidence=true` (**demo mode**; switch to `false` once a liveness-session route exists), `BedrockModelId` empty (reports disabled)
- Deploys: 1) first deploy, CREATE_COMPLETE. 2) handler includes the decision router, S1..S5 seeded, UPDATE_COMPLETE 07:33 UTC.
  3) audit number canonicalization fix, UPDATE_COMPLETE 07:37 UTC.

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

## Live API responses: first deploy

```
GET /health                      -> HTTP 200  {"status":"ok"}   3.47 s (cold start)
GET /health                      -> HTTP 200  {"status":"ok"}   0.76 s (warm, includes network)
GET /openapi.json  paths         -> ['/api/v1/face-auth/recognize', '/health']
POST /decision/evaluate          -> HTTP 404  {"detail":"Not Found"}
```

At first deploy `/decision/*` returned 404 because `backend/app/main.py` did not include the decision router.
Since redeploy 2, `aws/lambda/handler.py` includes it when main.py has not (it checks the served paths, so
there is never a duplicate once Shreya adds `app.include_router(decision_engine_router)` herself).

## Judge scenarios on the live ApiUrl (redeploy 3, 2026-11-14 07:38 UTC)

Seeded synthetic people S1..S5 (`aws/dynamodb/seed.py`). `AllowClientEvidence=true`, so liveness and face
scores are client-reported for this demo and recorded as such in the audit item (`evidence_source`).
`decision_ms` is measured in the Lambda (records + engine); `rtt` is the full round trip from a laptop.
Every request body below was sent to `POST <ApiUrl>/decision/evaluate` with `room_id` as shown.

| # | Scenario | Request (identity / room / evidence) | HTTP | Decision | Reasons | decision_ms | rtt |
|---|----------|--------------------------------------|------|----------|---------|-------------|-----|
| S1 | Active student, scheduled now | `person_id=S1` / LAB3 / liveness 97, face S1 99 | 200 | **ALLOW** | live person and identity verified; authorized for this room now | 430.91 (first call: DynamoDB client warm-up) | 1431 ms |
| S2 | Weak face match | `person_id=S2` / LAB3 / liveness 97, face S2 **88** | 200 | **REQUEST_VERIFICATION** | face match 88% below 95%; additional verification required | 29.13 | 922 ms |
| S2+ | Same, after fingerprint step-up | as S2 + `fingerprint_match=true` | 200 | **ALLOW** | ...; additional verification passed | 15.33 | 771 ms |
| S3 | Suspended (disciplinary office) | `person_id=S3` / LAB3 / perfect face match | 200 | **DENY** | person is suspended (disciplinary record) | 19.71 | 741 ms |
| S4 | Card reported lost | `rfid_card_id=CARD-S4` / LAB3 / face S4 99 | 200 | **DENY** | credential revoked | 26.44 | 830 ms |
| S5 | Exam hall, exam starts in 2 h | `person_id=S5` / EXAMHALL / perfect face match | 200 | **DENY** | no scheduled access to this room now | 16.31 | 833 ms |

Every response had `"mode":"online"` and `"audited":true`. Example full response (S1):

```json
{"attempt_id":"b135472ccafb4effb237398315f30304","decision":"ALLOW","reasons":["live person and identity verified","authorized for this room now"],"mode":"online","decision_ms":430.91,"audited":true}
```

Warm decisions: 15-29 ms in the Lambda.

### Offline sync with duplicates (`POST <ApiUrl>/decision/offline-sync`)

Batch from `KIOSK-01` (`cache_version=2`): `OFF-073806-1` (ALLOW, CARD-S1) **twice**, plus `OFF-073806-2`
(ALLOW, CARD-S4, which was revoked before the offline decision).

```json
{"synced":["OFF-073806-1","OFF-073806-2"],"duplicates":["OFF-073806-1"],"rejected":[],
 "flagged":[{"attempt_id":"OFF-073806-2","reason":"offline ALLOW used credential CARD-S4 revoked at 2026-11-14T07:37:42Z"}],"failed":[]}
```

Resending `OFF-073806-1` in a new batch:

```json
{"synced":[],"duplicates":["OFF-073806-1"],"rejected":[],"flagged":[],"failed":[]}
```

A batch containing a `face_image` field: **HTTP 422**, `biometric data is not accepted by this API (field 'decisions.0.face_image')`, nothing audited.

### Audit hash chain on the real `verigate-dev-audit` table

Read back with a consistent scan and checked with `audit_store.verify_items`:

| Check | Result |
|-------|--------|
| Records / seq range / contiguous | 16 / 1-16 / yes |
| Chain for this run (seq 9-16, written by the fixed code) | **verifies** |
| HEAD item hash == last record hash | yes |
| Copy with one decision flipped | **detected** |
| Offline-sync dedup markers | 4 |
| Modes present | `online`, `offline-synced` |
| Full table (seq 1-16) | **fails**, see below |

**Bug found by this live check, and fixed.** In the first live run (redeploy 2), all 6 online records failed
verification. Cause: records were hashed with numbers as written (`Decimal("97.0")`), but DynamoDB returns
numbers normalized (`Decimal("97")`), so the hash input changed on read. The offline records (no float fields)
verified. Fix (redeploy 3): numbers are hashed in DynamoDB's canonical form on write and on verify
(`audit_store.canonical_number`). The test fake now normalizes numbers like DynamoDB. With the old code it fails
5 tests, so this cannot regress unnoticed. seq 1-6 stay unverifiable by design: they were hashed over the
old form, and rewriting audit records to "fix" them would defeat the point of a tamper-evident log.

Per-record result: seq 1-6 fail (pre-fix online records), seq 7-16 verify.

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
It ran with the caller's credentials, not the Lambda role. The judge scenarios below then confirmed the Lambda
role's own reads (identities incl. GSI, grants, revocations) and audit writes through the live API.

## Face reference bucket

| Setting | Result |
|---------|--------|
| Public access block | all four `true` |
| Encryption | SSE-S3 (template `AES256`) |
| Lifecycle | `delete-face-refs-after-7-days`, Enabled, 7 days |
| Versioning | never enabled |
| Bucket policy | denies non-TLS access |

## Not yet verified live

- Server-verified liveness: the demo runs with `AllowClientEvidence=true`, because no route creates sessions yet.
- Rekognition Face Liveness (no route creates sessions yet) and CompareFaces with S3 references (needs Shreya's S3 provider and an uploaded `<person_id>.jpg`).
- Bedrock invoke (checkpoint 5).
