# AWS Sandbox Recon

Read-only reconnaissance of the hackathon sandbox, run with `aws\recon.ps1` plus three extra read-only
checks (Lambda account concurrency, S3 buckets, local SAM CLI). Nothing was created, changed or deleted.

- Date: 2026-11-14
- Profile / region: `hid` / `us-east-1`
- Caller: `arn:aws:sts::<account-id>:assumed-role/WSParticipantRole/Participant`
- Account IDs are masked as `<account-id>` / `<org-account-id>`.

## Status of the 9 items

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Caller identity / role | Confirmed | `WSParticipantRole/Participant`. Attached: `AdministratorAccess`, `CloudFrontFullAccess`, `ws-default-policy`. |
| 2 | Region | Confirmed | `us-east-1` |
| 3 | Rekognition | Confirmed (list) / Not yet tested (Face Liveness) | `list-collections` works, 0 collections. `verigate-faces` does not exist yet. Face Liveness session creation needs a write call. |
| 4 | Lambda | Confirmed (list) / Not yet tested (create) | Only `WSConcurrencyCurtailer-DO-NOT-USE` exists. Account concurrency 400, **unreserved 110**. `GetFunctionConcurrency` on the curtailer is **denied by an organization SCP**. |
| 5 | API Gateway (HTTP + REST) | Confirmed (list) / Not yet tested (create) | No APIs exist. |
| 6 | DynamoDB | Confirmed (list) / Not found (our tables) | 0 tables. The 4 `verigate-dev-*` tables will be created by the stack. |
| 7 | Bedrock | Confirmed (list) / Not yet tested (invoke) | Anthropic and Amazon models and `us.`/`global.` inference profiles are listed, e.g. `us.anthropic.claude-haiku-5-5`, `us.anthropic.claude-sonnet-5-5`, `us.amazon.nova-lite-v1:0`. Listing does not prove invoke access. |
| 8 | CloudWatch Logs | Confirmed (list) | 0 log groups. Lambda will create its own. |
| 9 | CloudFormation + IAM (deploy path) | Confirmed (read) / Not yet tested (create) | `list-stacks` returns nothing. `iam list-roles` and `list-attached-role-policies` work. Role creation (needed for the Lambda execution role) is not yet tested, and an org SCP with explicit denies is in force. |

### Extra findings

| Item | Status | Note |
|------|--------|------|
| Cognito identity pools | Confirmed (list) | 0 pools. Not needed for the current design. |
| S3 buckets | Confirmed (list) / Not found | 0 buckets. Packaging needs an artifact bucket, which is a write. |
| SAM CLI (local) | Not found | Not installed. `aws` CLI v2.40.2 is available. |

## Deploy-path recommendation

1. **Primary: `aws cloudformation package` + `deploy` with the existing SAM template.**
   CloudFormation runs the `AWS::Serverless-2016-10-31` transform on the server side, so SAM CLI is not required.
   Steps, after approval: create one S3 artifact bucket, run `aws\build.ps1` (Linux wheels into `aws/.build/`),
   then `package` and `deploy --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND`.
   `AdministratorAccess` should allow this. The first deploy is the real test of the SCP.
2. **Fallback: install SAM CLI into `.venv`** (`pip install aws-sam-cli`) and use `sam deploy --resolve-s3`, if SAM tooling is wanted.
3. **If CloudFormation or IAM role creation is denied by the SCP:** create the function, tables and HTTP API in the console
   (steps to be provided at checkpoint 4).

## Risks to watch

- **Lambda concurrency:** only 110 unreserved. Keep the function without reserved concurrency and keep load tests small.
- **Org SCP explicit denies:** treat `AdministratorAccess` as an upper bound, not a guarantee. Never touch `WSConcurrencyCurtailer-DO-NOT-USE`.
- **Bedrock:** set `BedrockModelId` to an inference profile, e.g. `us.anthropic.claude-haiku-5-5`, and confirm with one invoke at checkpoint 5.
  The report feature stays disabled while the parameter is empty.
- **Rekognition:** the `verigate-faces` collection must be created (seed step) before `SearchFacesByImage` can work.

## Not testable read-only

Face Liveness session creation, Lambda/IAM role creation, API creation and Bedrock invoke.
These are verified during the approved deploy (checkpoint 4) and in live verification (checkpoint 7).
