"""Deterministically combine evidence sufficiency and campus authorization outcomes."""

from math import isfinite

from .authorization import AuthorizationEvaluationResult
from .conflict_resolver import RecordResolutionBatch
from .enums import AccessDecision, AccessReasonCode, RevocationFindingState, VerificationModule
from .evidence_validator import (
    EvidenceValidationReasonCode,
    EvidenceValidationResult,
)
from .schemas import AccessDecisionResponse, AccessRequest, EvaluationContext
from .revocation import RevocationEvaluationResult


class PolicyEvaluator:
    """Apply decision precedence without retrieving records or persisting decisions."""

    def evaluate(
        self,
        request: AccessRequest,
        evidence: EvidenceValidationResult,
        authorization: AuthorizationEvaluationResult,
        context: EvaluationContext,
        *,
        decision_latency_ms: float = 0.0,
        audit_reference: str | None = None,
        record_resolutions: tuple[RecordResolutionBatch, ...] = (),
        revocation: RevocationEvaluationResult | None = None,
    ) -> AccessDecisionResponse:
        request = AccessRequest.model_validate(request)
        evidence = EvidenceValidationResult.model_validate(evidence)
        authorization = AuthorizationEvaluationResult.model_validate(authorization)
        context = EvaluationContext.model_validate(context)
        record_resolutions = tuple(RecordResolutionBatch.model_validate(item) for item in record_resolutions)
        if revocation is not None:
            revocation = RevocationEvaluationResult.model_validate(revocation)
        if (
            request.request_id != context.request_id
            or request.request_id != authorization.request_id
            or request.user_id != authorization.user_id
            or request.resource.resource_id != authorization.resource_id
        ):
            raise ValueError("request, evaluation context, and authorization result identifiers must match")
        if not isfinite(decision_latency_ms) or decision_latency_ms < 0:
            raise ValueError("decision_latency_ms must be a finite, non-negative value")

        reason_codes = set(authorization.reason_codes)
        resolution_denied = False
        resolution_requires_verification = False
        for batch in record_resolutions:
            if batch.evaluated_at != context.evaluated_at:
                raise ValueError("record resolution timestamp must match evaluation context")
            for resolution in batch.resolutions:
                reason_codes.update(resolution.reason_codes)
                resolution_denied |= resolution.decision is AccessDecision.DENY
                resolution_requires_verification |= resolution.decision is AccessDecision.REQUEST_VERIFICATION
        revocation_denied = False
        if revocation is not None:
            if (
                revocation.subject_id != request.user_id
                or revocation.resource_id != request.resource.resource_id
                or revocation.evaluated_at != context.evaluated_at
            ):
                raise ValueError("revocation result must match request subject, resource, and evaluation time")
            reason_codes.update(revocation.reason_codes)
            if revocation.state is RevocationFindingState.CONFIRMED_REVOCATION:
                reason_codes.add(AccessReasonCode.IDENTITY_REVOKED)
            revocation_denied = (
                revocation.blocking
                or revocation.state is RevocationFindingState.CONFIRMED_REVOCATION
            )
        accepted_evidence_is_correlated = all(
            item.evidence.user_id == request.user_id
            and item.evidence.authentication_attempt_id == request.authentication_attempt_id
            for item in evidence.accepted_evidence
        )
        has_spoof = bool(evidence.confirmed_spoof_indicators) or any(
            item.evidence.module is VerificationModule.FACE_LIVENESS
            and item.module_result == "SPOOF"
            for item in evidence.accepted_evidence
        )

        if has_spoof:
            reason_codes.add(AccessReasonCode.CONFIRMED_SPOOF)
        evidence_is_sufficient = (
            evidence.evidence_sufficient
            and accepted_evidence_is_correlated
            and bool(evidence.accepted_evidence)
            and not evidence.missing_required_modules
            and not evidence.failed_required_modules
            and not evidence.pending_required_modules
            and not evidence.conflicting_modules
        )
        if not evidence_is_sufficient:
            reason_codes.add(self._evidence_reason(evidence))

        if not authorization.permitted or has_spoof or resolution_denied or revocation_denied:
            decision = AccessDecision.DENY
        elif resolution_requires_verification:
            decision = AccessDecision.REQUEST_VERIFICATION
        elif not evidence_is_sufficient:
            decision = (
                AccessDecision.REQUEST_VERIFICATION
                if evidence.additional_verification_can_resolve
                else AccessDecision.DENY
            )
        else:
            decision = AccessDecision.ALLOW

        if decision is AccessDecision.ALLOW:
            reason_codes.add(AccessReasonCode.ACCESS_POLICY_SATISFIED)

        return AccessDecisionResponse(
            request_id=request.request_id,
            user_id=request.user_id,
            resource_id=request.resource.resource_id,
            decision=decision,
            access_granted=decision is AccessDecision.ALLOW,
            reason_codes=tuple(sorted(reason_codes, key=lambda code: code.value)),
            explanation=self._explanation(decision, reason_codes),
            policy_version=context.policy_version,
            evaluated_at=context.evaluated_at,
            decision_latency_ms=decision_latency_ms,
            audit_reference=audit_reference,
        )

    @staticmethod
    def _evidence_reason(evidence: EvidenceValidationResult) -> AccessReasonCode:
        codes = set(evidence.reason_codes)
        if EvidenceValidationReasonCode.CONFIRMED_SPOOF in codes:
            return AccessReasonCode.CONFIRMED_SPOOF
        if (
            EvidenceValidationReasonCode.EVIDENCE_PENDING in codes
            or EvidenceValidationReasonCode.EVIDENCE_INDETERMINATE in codes
        ):
            return AccessReasonCode.EVIDENCE_PENDING
        if EvidenceValidationReasonCode.EXPIRED_EVIDENCE in codes:
            return AccessReasonCode.EVIDENCE_EXPIRED
        if any(
            code in codes
            for code in (
                EvidenceValidationReasonCode.UNKNOWN_ISSUER,
                EvidenceValidationReasonCode.ISSUER_PROVIDER_UNAVAILABLE,
                EvidenceValidationReasonCode.INVALID_ISSUER_PROVIDER_RESPONSE,
                EvidenceValidationReasonCode.EVIDENCE_NOT_VERIFIED,
                EvidenceValidationReasonCode.INVALID_EVIDENCE,
                EvidenceValidationReasonCode.UNSUPPORTED_FIELD,
                EvidenceValidationReasonCode.IDENTITY_CORRELATION_FAILURE,
                EvidenceValidationReasonCode.ATTEMPT_CORRELATION_FAILURE,
                EvidenceValidationReasonCode.DUPLICATE_EVIDENCE,
                EvidenceValidationReasonCode.MODULE_RESULT_INVALID,
                EvidenceValidationReasonCode.MODULE_RESULT_CONFLICT,
            )
        ):
            return AccessReasonCode.EVIDENCE_INVALID
        return AccessReasonCode.IDENTITY_UNVERIFIED

    @staticmethod
    def _explanation(decision: AccessDecision, reason_codes: set[AccessReasonCode]) -> str:
        if decision is AccessDecision.ALLOW:
            return "Identity evidence and all configured campus authorization checks passed."
        if decision is AccessDecision.REQUEST_VERIFICATION:
            if AccessReasonCode.RECORD_CONFLICT in reason_codes:
                return "Conflicting campus records require review; access has not been granted."
            return "Campus authorization passed; additional identity verification is required."
        return "Access denied: " + ", ".join(
            code.value for code in sorted(reason_codes, key=lambda code: code.value)
        )
