"""Safe deterministic audit-event construction and reason-code explanations."""

from __future__ import annotations

from collections.abc import Iterable

from .engine import ZeroTrustDecisionResult
from .enums import AccessReasonCode
from .schemas import (
    AccessRequest,
    AuthorizationAuditSummary,
    ConflictAuditSummary,
    EvidenceSummary,
    RevocationAuditSummary,
    ZeroTrustAuditEvent,
)

_EXPLANATIONS = {
    AccessReasonCode.ACCESS_POLICY_SATISFIED: "All configured identity and access checks passed.",
    AccessReasonCode.CONFIRMED_SPOOF: "The liveness check detected a spoof.",
    AccessReasonCode.IDENTITY_SUSPENDED: "The campus identity is suspended.",
    AccessReasonCode.IDENTITY_REVOKED: "The identity or requested access is revoked.",
    AccessReasonCode.REVOCATION_CONFIRMED: "A revocation is confirmed for this request.",
    AccessReasonCode.PERMISSION_NOT_FOUND: "No permission exists for this resource and action.",
    AccessReasonCode.PERMISSION_REVOKED: "Permission for this resource and action was revoked.",
    AccessReasonCode.PERMISSION_EXPIRED: "Permission for this resource and action has expired.",
    AccessReasonCode.RECORD_CONFLICT: "Campus records conflict and require resolution.",
    AccessReasonCode.RECORD_STALE: "Required campus authorization data is stale.",
    AccessReasonCode.REVOCATION_STALE: "Revocation information is stale.",
    AccessReasonCode.REVOCATION_UNAVAILABLE: "Required revocation information is unavailable.",
    AccessReasonCode.IDENTITY_UNVERIFIED: "Additional identity verification is required.",
    AccessReasonCode.LAB_SAFETY_CLEARANCE_REQUIRED: "A required lab safety clearance is missing.",
    AccessReasonCode.OUTSIDE_EXAM_SCHEDULE: "The request is outside the permitted examination schedule.",
}


def explain_reason_codes(reason_codes: Iterable[AccessReasonCode]) -> str:
    """Return concise deterministic text; this function has no decision side effects."""

    codes = tuple(sorted(set(reason_codes), key=lambda code: code.value))
    if not codes:
        return "No decision reason was supplied."
    return " ".join(
        _EXPLANATIONS.get(code, f"Access check reported {code.value.lower().replace('_', ' ')}.")
        for code in codes
    )


def build_audit_event(
    request: AccessRequest,
    result: ZeroTrustDecisionResult,
) -> ZeroTrustAuditEvent:
    """Build a minimal audit event from a matched request and engine result.

    The event contains only outcome summaries. It intentionally drops evidence
    provenance and record-level provenance, and never copies arbitrary payloads.
    """

    request = AccessRequest.model_validate(request)
    result = ZeroTrustDecisionResult.model_validate(result)
    if (
        result.request_id != request.request_id
        or result.user_id != request.user_id
        or result.resource_id != request.resource.resource_id
    ):
        raise ValueError("audit request identifiers must match the decision result")

    evidence = EvidenceSummary.model_validate(
        {**result.evidence_summary.model_dump(), "provenance": ()}
    )
    codes = tuple(sorted(set(result.reason_codes), key=lambda code: code.value))
    return ZeroTrustAuditEvent(
        request_id=request.request_id,
        user_id=request.user_id,
        resource_id=request.resource.resource_id,
        authentication_attempt_id=request.authentication_attempt_id,
        decision=result.decision,
        reason_codes=codes,
        policy_version=result.policy_version,
        evaluated_at=result.evaluated_at,
        evidence_summary=evidence,
        authorization_summary=AuthorizationAuditSummary(
            permitted=result.authorization_summary.permitted,
            reason_codes=tuple(sorted(set(result.authorization_summary.reason_codes), key=lambda code: code.value)),
        ),
        conflict_resolution_summary=ConflictAuditSummary(
            resolution_count=result.conflict_resolution_summary.resolution_count,
            unresolved_conflict_count=result.conflict_resolution_summary.unresolved_conflict_count,
            reason_codes=tuple(sorted(set(result.conflict_resolution_summary.reason_codes), key=lambda code: code.value)),
        ),
        revocation_summary=RevocationAuditSummary(
            state=result.revocation_summary.state,
            required=result.revocation_summary.required,
            blocking=result.revocation_summary.blocking,
            reason_codes=tuple(sorted(set(result.revocation_summary.reason_codes), key=lambda code: code.value)),
        ),
        explanation=explain_reason_codes(codes),
        record_provenance_summary=(),
    )
