# Deployment Validation: verigate-dev

Real deployment to the hackathon AWS sandbox. All responses below are copied from live calls.
Account IDs are masked as `<account-id>`.

- Date: 2026-11-14
- Stack / region: `verigate-dev` / `us-east-1`, status **CREATE_COMPLETE**
- Caller: `WSParticipantRole/Participant` (profile `hid`)
- Parameters: `Stage=dev`, `AllowClientEvidence=true` (**demo mode**; switch to `false` once a liveness-session route exists), `BedrockModelId` empty (reports disabled)
- Deploys: 1) first deploy, CREATE_COMPLETE. 2) handler includes the decision router, S1..S5 seeded, UPDATE_COMPLETE 07:33 UTC.
  3) audit number canonicalization fix, UPDATE_COMPLETE 07:37 UTC. 4) judge-scenario rules (code only), UPDATE_COMPLETE 07:51 UTC.

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

## Scenarios S1..S5 on the live ApiUrl (redeploy 3, 2026-11-14 07:38 UTC)

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

## Judge scenarios (live)

Run on the live ApiUrl after redeploy 4 (code only), 2026-11-14 07:51 UTC, `POST <ApiUrl>/decision/evaluate`.
Synthetic people J1..J5 come from `aws/dynamodb/seed.py`. The request bodies are the shared
`backend/tests/decision_engine/judge_cases.py`, which `test_judge.py` also runs against exactly the seeded records.
`AllowClientEvidence=true` (demo), so liveness inputs are client-reported and marked so in the audit record.
`decision_ms` is measured inside the Lambda. **8/8 matched the expected decision.**

| Case | What the records say | Request | Decision | Reasons (verbatim) | decision_ms |
|------|----------------------|---------|----------|--------------------|-------------|
| **J1** Spoof | active, scheduled in LAB3 | `{"person_id":"J1","rfid_card_id":"CARD-J1","room_id":"LAB3","evidence":{"face_person_id":"J1","face_similarity":99.0,"liveness_status":"SPOOF"}}` | **DENY** | spoof suspected (liveness status SPOOF) | 436.72 (cold DynamoDB client) |
| **J2** Suspended | registrar: active (v4); disciplinary_office: suspended (v2) | `{"person_id":"J2","rfid_card_id":"CARD-J2","room_id":"LAB3","evidence":{"liveness":97.0,"face_similarity":99.0,"face_person_id":"J2","fingerprint_match":true,"challenge_passed":true}}` | **DENY** | person is suspended (disciplinary record) | 33.31 |
| **J3** Temporary exam pass | LAB2 exam schedule (`requires_pass`) active + invigilator lab pass valid now | `{"person_id":"J3","room_id":"LAB2","evidence":{"liveness":97.0,"face_similarity":99.0,"face_person_id":"J3"}}` | **ALLOW** | live person and identity verified; authorized for this room now | 25.70 |
| J3 expired-pass variant | LAB4 exam schedule active, lab pass expired 30 min ago | as J3, `"room_id":"LAB4"` | **DENY** | exam in this room requires a valid temporary lab pass; none is valid now | 23.53 |
| **J4** Stale revocation, sensitive room | card issuer `contractor-office`; its revocation feed last refreshed 3 h ago (`refresh_failed`); EXAMHALL exam active | `{"person_id":"J4","rfid_card_id":"CARD-J4","room_id":"EXAMHALL","evidence":{"liveness":97.0,"face_similarity":99.0,"face_person_id":"J4"}}` | **DENY** | revocation list could not be refreshed; sensitive room stays closed | 34.57 |
| J4 normal-room variant | same, LAB3 | as J4, `"room_id":"LAB3"` | **REQUEST_VERIFICATION** | revocation list could not be refreshed; extra check needed | 30.41 |
| **J5** Conflicting records | registrar: active (v3); hr: inactive (v3), equal authority | `{"person_id":"J5","room_id":"LAB3","evidence":{"liveness":97.0,"face_similarity":99.0,"face_person_id":"J5"}}` | **REQUEST_VERIFICATION** | conflicting records from equally authoritative sources; manual verification required; equally authoritative sources disagree: hr=inactive, registrar=active | 23.51 |
| J5 sensitive-room variant | same, EXAMHALL exam active | as J5, `"room_id":"EXAMHALL"` | **DENY** | conflicting authoritative records for a sensitive room; equally authoritative sources disagree: hr=inactive, registrar=active | 22.73 |

All responses: HTTP 200, `"mode":"online"`, `"audited":true`. Round trips from the laptop were 767-1270 ms.

How the engine decides these (deny-first order in `engine.py`):
1. J1: the worst of the numeric liveness verdict and the reported `liveness_status` is used. SPOOF can't be outweighed by card, face, fingerprint or challenge.
2. J2: `reconcile.py` keeps each source's latest version. The most authoritative sources decide (disciplinary_office 3 > registrar 2).
3. J3: a schedule entry with `requires_pass` needs **both** the schedule window and a lab pass window to contain "now".
4. J4: revocation-feed freshness (`SYNC#<card_issuer>`, 60 min) is separate from record freshness. Stale feed: sensitive room DENY, otherwise REQUEST_VERIFICATION.
5. J5: equally authoritative sources disagree. The engine never picks one: REQUEST_VERIFICATION, or DENY in a sensitive room.

Audit chain for this run, read back from `verigate-dev-audit`: seq 17-24 (8 records) **verify**, and HEAD matches the last record.
The audit records carry the facts behind each decision. For example, J5's `context` holds `status: null`,
`status_sources: ["hr","registrar"]` and `records_conflict: true`. J4's holds `revocation_fresh: false`,
`card_issuer: "contractor-office"` and `room_sensitive: true`.

Demo note: the campus feed status `SYNC#campus` is fresh for 60 min after seeding. After that, every campus card gets
REQUEST_VERIFICATION, which is correct behaviour. Before a demo, run `seed.py --stage dev --refresh-sync`.

## Local integration (real AWS)

2026-11-14 ~08:15 UTC. The app object the Lambda serves (`aws/lambda/handler.py` -> `app`) ran locally with uvicorn on
127.0.0.1:8765, against the real `verigate-dev` tables, Rekognition and the face-refs bucket. Environment:
`AWS_PROFILE=hid`, `AWS_REGION=us-east-1`, `FACE_REFERENCE_BUCKET=verigate-dev-face-refs-<account-id>`,
`ALLOW_CLIENT_EVIDENCE=false`, `FACE_REFERENCE_DIR` unset.

`uvicorn backend.app.main:app` alone would not serve these routes: main.py includes only the face-recognition
router. The handler's guarded include adds the decision router and, since this change, Shreya's liveness router.

Shreya's liveness router requires the host app to provide an authenticated user and an ownership store. Unwired, it
answers 503 (covered by `test_mounted_liveness_route_fails_closed_without_integration`). For this local test only, a
harness outside the repo supplied a fixed test user `S1` and an in-memory ownership store that knows one attempt id.
**The deployed route still returns 503 until the team wires real auth and a durable ownership store.**

| # | Call | Result |
|---|------|--------|
| 1 | `POST /api/v1/face-auth/liveness/session` `{"authentication_attempt_id":"LOCAL-ATTEMPT-1"}` | **201**, real Rekognition session `a9c4b75c-3510-415d-98d6-b67f5e0268b6`, status `PENDING` (1.6 s) |
| 1b | same route, attempt id not owned by the user | **404** `Liveness session or authentication attempt was not found.` |
| 2 | `POST /decision/evaluate` `{"person_id":"S1","room_id":"LAB3","evidence":{"liveness_session_id":"a9c4b75c-...","face_person_id":"S1","face_similarity":99.0}}`, with no liveness check done in the session | **REQUEST_VERIFICATION**, not ALLOW. Reasons: `liveness not checked`, `additional verification required`, `liveness session CREATED`. The server asked Rekognition itself. decision_ms 6619.71 (laptop to AWS, first call: credential resolution plus Rekognition and DynamoDB) |
| 2b | same request again (replayed session id) | **DENY** `liveness session was already used (replay suspected)`, without calling Rekognition again |
| 2c | `evidence.liveness: 99` sent by the client, `ALLOW_CLIENT_EVIDENCE=false` | **422** `client-reported liveness is not accepted; send evidence.liveness_session_id instead` |
| 2d | `GET /api/v1/face-auth/liveness/session/{id}/result` (Shreya's route) | **502** `Liveness provider failed.` |
| 3 | `POST /api/v1/face-auth/recognize` (`user_id=S1`, a 1x1 PNG with no face) | **503** `Face reference provider is not configured.` |

Findings:

- **2d is a bug in `rekognition_liveness_client.py:27`.** It calls `get_face_liveness_session_results(livenessSessionId=...)`, and boto3
  rejects that locally (`ParamValidationError`). The same call with `SessionId=` returned `{"Status":"CREATED"}` for this session.
  One-line fix for Shreya: `return self._client.get_face_liveness_session_results(SessionId=session_id)`.
- **3 is not tested yet.** The recognize route still reads only `FACE_REFERENCE_DIR`, so `FACE_REFERENCE_BUCKET` is ignored and the
  S3 path cannot be exercised. No reference photo was uploaded, because doing so would test nothing yet. This needs Shreya's
  `S3ReferenceImageProvider` and a consented reference photo.
- The two audit records from calls 2 and 2b went to the real audit chain with `evidence_source.liveness` = `absent` and
  `liveness_status` = `CREATED` / `REUSED`.

### Lambda role permissions (IAM policy simulator, read-only)

Every AWS call in `backend/modules` was listed (grep): `get_item`, `put_item`, `query` (DynamoDB),
`create_face_liveness_session`, `get_face_liveness_session_results`, `detect_faces`, `compare_faces` (Rekognition),
`converse` (Bedrock, i.e. `bedrock:InvokeModel`), and S3 `get_object` once Shreya's provider lands.
Each was simulated against the **deployed** role and against the **tightened template policy** (not deployed yet).

| Action / resource | Deployed role | Tightened template |
|-------------------|---------------|--------------------|
| GetItem identities; Query identities/index/by-card; Query authorization; GetItem revocations; PutItem + GetItem audit | allowed | allowed |
| CreateFaceLivenessSession, GetFaceLivenessSessionResults, CompareFaces, DetectFaces | allowed | allowed |
| s3:GetObject face-refs/`<person_id>`.jpg | allowed | allowed |
| DeleteItem / UpdateItem / Scan on audit | denied | denied |
| **PutItem / DeleteItem on revocations** | **allowed (over-broad)** | denied |
| **Scan on identities** | **allowed (over-broad)** | denied |
| Query on audit | allowed | denied (code never queries it) |
| s3:PutObject, s3:ListBucket on face-refs | denied | denied |
| SearchFacesByImage, IndexFaces | denied | denied |

Tightened template result: 0 mismatches out of 22 checks. Changes in `aws/template.yaml`:
- SAM `DynamoDBReadPolicy` / `DynamoDBCrudPolicy` are replaced by per-table statements with only the actions above.
- The unused `SearchFacesByImage` statement, the `CollectionId` parameter and the `COLLECTION_ID` env var are removed.

Rekognition liveness, CompareFaces and DetectFaces do not support resource-level permissions, so they stay on `"*"`.
Without `s3:ListBucket`, a missing reference returns AccessDenied rather than NoSuchKey, which the provider must treat as "not found".

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

## Redeploy 5: full deploy, tightened IAM + liveness session route (live)

2026-11-14 08:40 UTC, `UPDATE_COMPLETE`, `AllowClientEvidence=true`, reseeded. ApiUrl: `https://y6v7j9rp2j.execute-api.us-east-1.amazonaws.com`

| Check | Result |
|-------|--------|
| `GET /health` | 200 `{"status":"ok"}` |
| `GET /docs` | 200. OpenAPI paths: `/decision/evaluate`, `/decision/liveness-session`, `/decision/offline-sync`, `/api/v1/face-auth/liveness/session`, `/api/v1/face-auth/liveness/session/{session_id}/result`, `/api/v1/face-auth/recognize`, `/health` |
| `POST /decision/liveness-session` `{"person_id":"S1"}` | **201** `{"session_id":"21140c8d-d6d9-453e-9886-87327bb1fe7e","expires_at":"2026-11-14T08:52:59Z","ttl_seconds":600,"bound_to":"S1"}`, a real Rekognition session |
| Shreya's `POST /api/v1/face-auth/liveness/session` | 503 `Authentication principal is not configured.` (fails closed until auth and ownership are wired) |

Judge scenarios rerun on the deployed code: **8/8 PASS**.

| Case | Decision | decision_ms |
|------|----------|-------------|
| J1 spoof | DENY (spoof suspected, liveness status SPOOF) | 163.04 |
| J2 suspended | DENY (person is suspended) | 26.05 |
| J3 exam + lab pass | ALLOW | 17.01 |
| J3 pass expired | DENY (requires a valid temporary lab pass) | 17.62 |
| J4 stale revocation, EXAMHALL | DENY (sensitive room stays closed) | 30.45 |
| J4 stale revocation, LAB3 | REQUEST_VERIFICATION | 23.96 |
| J5 conflict, LAB3 | REQUEST_VERIFICATION (hr=inactive, registrar=active) | 21.16 |
| J5 conflict, EXAMHALL | DENY | 22.94 |

Audit chain for this run: seq 27-34 verify, and HEAD matches the last record.

Deployed role, checked with the IAM simulator after the deploy: the removed permissions are now denied:
`dynamodb:PutItem` / `DeleteItem` on revocations, `Scan` on identities, `Query` on audit, `rekognition:SearchFacesByImage`.
The needed ones are still allowed: GetItem revocations, Query `identities/index/by-card`, CreateFaceLivenessSession,
CompareFaces, `s3:GetObject` on `verigate-dev-face-refs-<account-id>/*`. 0 mismatches.

Not yet live-tested: server-side face match against an S3 reference photo. No consented reference photo has been
uploaded yet. It is covered by mocked tests: match, mismatch, no reference, reused session, unknown session, spoof.

## Bedrock (live)

2026-11-14 09:07 UTC, deployed (`UPDATE_COMPLETE`). Model: `BEDROCK_MODEL_ID=us.anthropic.claude-haiku-5-5` (inference profile from RECON.md).
IAM: `bedrock:InvokeModel` only on that profile and `anthropic.claude-haiku-5-5` in us-east-1, us-east-2 and us-west-2.
**The SCP does not block InvokeModel.** Haiku 5.5 rejects `temperature` as deprecated, so the code retries without it
(`temperature_applied: false`). Only decision, reasons, mode and computed numbers are sent: no images, evidence or IDs.

| Call | Decision (unchanged) | Explanation / summary | source | latency_ms |
|------|----------------------|-----------------------|--------|-----------|
| `POST /decision/explain {"request_id":"1e0bf395cb6e409d8ce21c1c33364b7f"}` (J1 spoof) | DENY | "The access request was denied because the system flagged a suspected spoof (the liveness check returned SPOOF), and the decision is recorded as DENY in online mode." | bedrock | 1306.6 |
| `POST /decision/explain {"request_id":"331f0ec051d44984b039374c9f6e3540"}` (J3 exam + pass) | ALLOW | "Access is allowed because the person is a live, verified individual who is authorized for this room at this time." | bedrock | 1192.6 |
| `POST /report/summary {}` | n/a | 5 bullets: 38 decisions (12 ALLOW / 19 DENY / 7 REQUEST_VERIFICATION), 4 spoof denials, 2 stale-revocation denials, 4 conflicts, 4 offline-synced, avg 313.87 ms / p95 1500.32 ms (34 samples) | bedrock | 2870.4 |

The metrics are computed in code; Bedrock only words them. Fix found live: the first summary came back cut off,
because Haiku 5.5's reasoning tokens count against maxTokens. Now a `stopReason: max_tokens` response always falls back
to deterministic text, and the budgets are 300 (explain) and 1000 (summary). Any Bedrock error returns
`"source": "fallback"` with deterministic text, and the decision is unchanged (covered by tests).
