# Zero Trust Evidence Validation

This document describes the evidence-validation boundary in
`backend.modules.zero_trust.evidence_validator`. The component validates
authentication evidence for one access request. It does not resolve campus
authorization records, evaluate access policy, make an `ALLOW` decision, or
persist audit data.

## Evidence validation lifecycle

1. Parse each evidence item using the strict `VerificationEvidence` schema.
   Malformed items are represented in `rejected_evidence` with sanitized
   identifiers and reason codes; they are not silently dropped.
2. Reject duplicate evidence IDs as a group. Every occurrence of a duplicate
   ID is rejected, independent of input order.
3. Correlate the claim's user and authentication-attempt IDs to the access
   request. Mismatches are rejected before issuer lookup.
4. Resolve `issuer_id` using an injected, server-configured
   `TrustedIssuerProvider`. Unknown issuers are rejected.
5. Ask the resolved trusted module adapter to authenticate the evidence claim
   and return canonical evidence plus `EvidenceProvenance`. Returned module,
   issuer, evidence ID, outcome, provider identity, and validation time are
   checked before the evidence can be used.
6. Check the canonical evidence timestamp against the supplied
   `EvaluationContext` and per-module `EvidenceFreshnessPolicy`.
7. Interpret the provider-validated module result and compare usable successes
   to explicit `EvidenceRequirements`.
8. Return accepted evidence, every rejection, categorized issues, missing,
   failed and pending mandatory modules, and stable reason codes.

The validator reads no system clock. Callers provide a server-created
evaluation timestamp so the same inputs and policy snapshot produce the same
result.

## Trusted issuer architecture

`issuer_id` identifies the claimed source; it is not a credential or proof of
trust. `TrustedIssuerProvider` resolves that identifier from server-side
configuration. The returned adapter must validate the claim itself, such as by
verifying a signed assertion or looking up the result through an authenticated
module interface. It returns a canonical `TrustedEvidence` object with
`EvidenceProvenance` identifying the validating provider.

An adapter that only echoes client fields is not a trusted implementation.
Issuer authority ranks are not accepted from request data or represented in
the evidence models. Provider exceptions, missing providers, unknown issuers,
and malformed provider responses all reject the evidence.

## Identity and attempt correlation

The evidence user ID must match `AccessRequest.user_id`; the attempt ID must
match `AccessRequest.authentication_attempt_id`. Both the submitted claim and
the provider-returned canonical evidence are checked. A validated evidence ID
may appear only once in a validation request. Reuse across a different user or
attempt fails correlation.

## Freshness policy

Supply a positive maximum age for each module that a policy may use. Evidence
from a module without a configured age is rejected. Evidence is rejected when
it is older than its module's limit, future-dated beyond the configured clock
skew, or at/after its optional expiry time. `issued_at` and optional
`expires_at` must be timezone-aware, and expiry must follow issue time.

Freshness and policy limits are explicit inputs; this component does not pick
resource-specific durations. A stale or expired success is not accepted as a
current factor.

## Module result adapter contract

The existing face-recognition service returns `MATCH` or `NO_MATCH` in its
`status` field. Its adapter must map those to `SUCCESS` or `FAILURE`, retain the
exact module result in the trusted `TrustedEvidence.module_result`, and map
service errors to `ERROR`. A client-supplied `SUCCESS` is insufficient without
provider validation.

The other modules do not currently expose implemented result contracts. The
following are expected adapter mappings for future implementations:

| Module | Trusted module result | Normalized outcome | Validation behavior |
|---|---|---|---|
| Face recognition | `MATCH` / `NO_MATCH` / `ERROR` | `SUCCESS` / `FAILURE` / `ERROR` | Only `MATCH` can satisfy an identity requirement. |
| Face liveness | `LIVE` / `SPOOF` / `PENDING` / `EXPIRED` / `INDETERMINATE` / `ERROR` | `SUCCESS` / `FAILURE` / corresponding outcome | `SPOOF` is a confirmed spoof indicator; `INDETERMINATE` never means live. |
| Fingerprint | `MATCH` / `NO_MATCH` / `ERROR` | `SUCCESS` / `FAILURE` / `ERROR` | Only provider-validated successful identity evidence can satisfy a requirement. |
| RFID | `VALID` / `INVALID` / `ERROR` | `SUCCESS` / `FAILURE` / `ERROR` | A valid card can identify a claim; it does not establish campus authorization. |

An unrecognized or outcome-inconsistent adapter result is rejected. The
validator does not invent confidence scores. Confidence and similarity remain
optional schema values and are not treated as provider authentication.

## Evidence sufficiency

`EvidenceRequirements` requires either one or more mandatory modules or one or
more explicit `required_any_of` groups. Every mandatory module must have fresh,
trusted success. At least one module in each `required_any_of` group must have
fresh, trusted success. The groups express policy alternatives; they are not
majority votes. No global requirement for all four modules is imposed.

Missing evidence, explicit module failure, pending/indeterminate evidence, and
stale evidence are reported separately. Optional success cannot repair a
failed mandatory factor. A trusted `FACE_LIVENESS` result of `SPOOF` is reported
as a confirmed spoof indicator even if other modules succeed, and makes
`evidence_sufficient` false. This validator never returns an access decision;
RFID or fingerprint success alone cannot grant access here.

Conflicting fresh results from the same module and attempt are not settled by
counting them. That module is marked conflicting and its otherwise successful
items are removed from accepted evidence.

## Result categories and reason codes

`EvidenceValidationResult` includes accepted and rejected evidence, missing,
failed and pending required modules, stale and expired evidence, unknown
issuers, identity and attempt correlation failures, confirmed spoof
indicators, stable reason codes, and whether additional verification can
resolve the current evidence issue. Confirmed spoof sets
`additional_verification_can_resolve` to false for this attempt.

Reason codes are the `EvidenceValidationReasonCode` enum in
`evidence_validator.py`:

- Issuer/provider: `UNKNOWN_ISSUER`, `ISSUER_PROVIDER_UNAVAILABLE`,
  `INVALID_ISSUER_PROVIDER_RESPONSE`, `EVIDENCE_NOT_VERIFIED`.
- Input/correlation: `INVALID_EVIDENCE`, `UNSUPPORTED_FIELD`, `MISSING_ISSUER`,
  `MISSING_USER_ID`, `MISSING_ATTEMPT_ID`, `MISSING_EVIDENCE_ID`,
  `UNKNOWN_MODULE`, `IDENTITY_CORRELATION_FAILURE`,
  `ATTEMPT_CORRELATION_FAILURE`, `DUPLICATE_EVIDENCE`.
- Time: `MISSING_TIMESTAMP`, `INVALID_TIMESTAMP`, `FUTURE_DATED_EVIDENCE`,
  `STALE_EVIDENCE`, `EXPIRED_EVIDENCE`, `FRESHNESS_POLICY_MISSING`.
- Module result: `MODULE_FAILURE`, `MODULE_ERROR`, `EVIDENCE_PENDING`,
  `EVIDENCE_INDETERMINATE`, `CONFIRMED_SPOOF`, `MODULE_RESULT_INVALID`,
  `MODULE_RESULT_CONFLICT`, `EVIDENCE_ACCEPTED`.
- Requirements: `MISSING_REQUIRED_EVIDENCE`, `FAILED_REQUIRED_EVIDENCE`.

## Security limitations and integration requirements

- The validator is not an access-control engine. Authorization records,
  permissions, suspension, exam schedules, lab safety, temporary passes, and
  revocation policy are evaluated in a later phase.
- Trusted adapters and issuer configuration must be implemented and protected
  server-side. A provider that trusts an issuer string or echoes caller fields
  defeats this boundary.
- Face liveness, fingerprint, and RFID implementations are not present. Their
  table entries are expected adapter contracts, not claims that those modules
  exist.
- The current face-recognition endpoint returns a response to its caller but
  does not yet provide a signed or server-to-server evidence handoff. An
  authenticated adapter contract is required before using that response as
  trusted evidence.
- Provider metadata and evidence scores can still be sensitive. Do not log raw
  images, fingerprint templates, credentials, or full evidence payloads.
- `additional_verification_can_resolve` is an evidence workflow hint, not an
  access decision. A confirmed spoof must remain a denial condition in the
  eventual decision engine regardless of other successful factors.
