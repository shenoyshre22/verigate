# VERIGATE Zero Trust Decision Engine

## Scope and architecture

The Zero Trust module evaluates campus access requests by combining identity
evidence with campus authorization records. Identity verification and
authorization remain separate: a successful face, fingerprint, or RFID result
does not grant campus access by itself.

`ZeroTrustDecisionEngine` is independent of FastAPI. Its dependencies are
injected and implement these interfaces:

- `EvidenceClaimsProvider.get_evidence(request)` returns upstream evidence
  claims. It must not execute face, liveness, fingerprint, or RFID processing.
- `EvidenceValidator` validates each claim against its server-side trusted
  issuer provider and evidence freshness policy.
- `CampusRecordProvider.get_authorization_data(request, evaluated_at)` returns
  trusted-provider campus records plus revocation-source health checks.
- `DecisionPolicyProvider.get_policy(request)` supplies the server-owned
  policy version, resource sensitivity, evidence requirements, authorization
  policy, source authority/freshness rules, and revocation policy.
- `CampusRecordConflictResolver`, `CampusAuthorizationEvaluator`,
  `RevocationChecker`, and `PolicyEvaluator` execute the domain checks.
- An injected UTC clock supplies the evaluation timestamp. An injected
  monotonic timer measures the engine's internal evaluation interval.

The engine executes components in this order:

1. Validate the access request and resolve server policy and provider data.
2. Validate upstream evidence and correlate user and authentication attempt.
3. Filter campus records to the requested user/resource/action, then resolve
   each record domain using trusted source configuration.
4. Build an authorization snapshot from resolved winning records and evaluate
   campus identity, permissions, suspensions, schedules, passes, roles, and
   safety requirements.
5. Evaluate scoped revocation status and its freshness.
6. Combine evidence, authorization, conflict, and revocation findings through
   `PolicyEvaluator` to produce the final decision.

Provider data is never accepted from the public request body. Campus records
are typed and validated, then their `source_id` is checked against configured
authority for that record domain. Evidence claims, including `issuer_id`, are
only claims until `EvidenceValidator` authenticates them through an injected
trusted issuer adapter.

## Source authority and conflict precedence

Configure `ConflictResolutionPolicy.sources_by_domain` in server-owned code or
an injected policy provider. Each domain maps to its own list of
`SourceAuthorityRule(source_id, priority)` entries. Lower numeric priority is
more authoritative. A source's priority in one domain does not grant it
authority in another domain. Record models do not accept authority ranks.

For eligible records with the same subject and scope, resolution compares:

1. Configured source authority (stronger authority first).
2. Record version (higher version first).
3. Source update timestamp (newer first).
4. Issuance timestamp (newer first).

Input arrival order is never used. A freshness limit may be configured per
domain with `max_age_by_domain`. Stale, future-dated, invalid, expired, and
not-yet-valid candidates are excluded. A stale or invalid record from an
authority at least as strong as the current candidate blocks fallback to a
lower-authority grant. Unknown and cross-domain sources cannot grant access.
If the expected record set is empty, callers can supply `expected_scope` to
produce an explicit missing-authoritative-record denial.

Contradictory records tied on authority, version, and timestamps remain
unresolved. `conflict_decision_by_sensitivity` may select `REQUEST_VERIFICATION`
or `DENY`; `ALLOW` is rejected by policy validation. `PolicyEvaluator` applies
all conflict decisions as mandatory constraints.

## Decision precedence

`PolicyEvaluator` enforces these rules:

1. Failed campus authorization, confirmed spoof, confirmed revocation, or a
   denied record resolution results in `DENY`.
2. An unresolved conflict configured for `REQUEST_VERIFICATION` can request
   further action only when campus authorization has not already failed.
3. Incomplete identity evidence yields `REQUEST_VERIFICATION` only when the
   validator says further evidence can resolve it; otherwise it yields `DENY`.
4. `ALLOW` requires sufficient correlated identity evidence, a permitted
   campus authorization result, no blocking conflict, and no blocking
   revocation finding.
5. `access_granted` is true if and only if the decision is `ALLOW`.

There is no majority voting. A successful module cannot override a failed
mandatory module, suspension, revoked permission, missing permission, failed
safety requirement, or stale/unavailable required revocation status. Exceptions
and unavailable provider data fail closed.

## Result contract

The engine returns `ZeroTrustDecisionResult`, which extends the existing
`AccessDecisionResponse` fields:

- Request, user, and resource identifiers.
- `decision`, `access_granted`, `reason_codes`, and explanation.
- `evaluated_at`, `policy_version`, and `decision_latency_ms`.
- `evidence_summary`: accepted evidence count, accepted outcome counts, and
  validated module names. No scores, images, templates, or provider provenance
  are exposed in this API summary.
- `authorization_summary`: permitted flag, reason codes, and explanation.
- `conflict_resolution_summary`: domains evaluated, resolution count,
  unresolved conflict count, and reason codes. It omits record contents and
  source identifiers.
- `revocation_summary`: finding state, whether it was required, whether it
  blocks, and reason codes.

The API summary intentionally avoids returning the resolver's internal record
trace, which can contain source and record identifiers. That trace remains
available to trusted server-side code for later audit integration.

The measured decision interval starts after the policy, campus data, and
upstream evidence claims have been retrieved. It includes evidence validation,
record resolution, authorization, revocation, and policy combination. It does
not include execution time for face recognition, liveness, fingerprint, or RFID
modules. No performance claims are made by this implementation.

## API endpoint

`backend/modules/zero_trust/router.py` exports a standalone `APIRouter`. The
owning application can mount it at a later integration step; this phase does
not change `backend/app/main.py`.

### `POST /api/v1/access/decide`

The JSON body uses the existing `AccessRequest` schema:

```json
{
  "request_id": "request-123",
  "user_id": "user-456",
  "authentication_attempt_id": "attempt-789",
  "resource": {"resource_id": "LAB_101"},
  "action": {"action_id": "ENTER"},
  "requested_at": "2026-11-14T12:00:00Z"
}
```

The request does not accept evidence claims, campus records, issuer/source
authority, or a precomputed decision. Those values come from injected server
dependencies. A normal evaluation returns a `ZeroTrustDecisionResult` with
HTTP 200 for `ALLOW`, `REQUEST_VERIFICATION`, or `DENY`.

The host application must authenticate the caller and bind or authorize the
submitted `user_id` before mounting this router. This module does not implement
caller authentication or a campus principal-to-user binding policy.

Errors use `{ "error": { "code": "...", "message": "..." } }`:

- 400 `INVALID_JSON` for malformed JSON.
- 422 `INVALID_ACCESS_REQUEST` for a body that violates the request schema or
  includes unsupported trusted-data fields.
- 503 `DECISION_ENGINE_UNAVAILABLE` when the host has not configured an engine.
- 503 `DECISION_UNAVAILABLE` if an injected engine raises unexpectedly.

Provider failures handled inside the engine return a structured fail-closed
`DENY` result with a safe reason code. Provider exception details are not
included in responses.

## Testing and integrations still needed

Tests use synthetic campus records, in-memory evidence/campus/policy providers,
and trusted issuer adapters. No AWS persistence, network provider, or live
authentication module is implemented here. Later integration must supply:

- Trusted issuer adapters for each authentication module. They must verify
  upstream results and bind them to the request user and attempt.
- Campus data providers that fetch records and report revocation source
  availability explicitly.
- Reviewed per-domain source authority, freshness windows, sensitivity, and
  role/safety/pass policy configuration.
- A host application that injects the configured engine and mounts the router.
- Persistence and audit integration, including a policy for retaining the
  internal conflict trace without exposing it to ordinary API callers.

The current examination access model uses the existing eligibility record's
assigned resource and schedule window. A separate campus-specific examination
pass record would require a coordinated schema/provider change if campus policy
distinguishes it from exam eligibility.
