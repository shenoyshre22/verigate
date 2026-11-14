"""Central deterministic Zero Trust decision orchestration.

Providers supply untrusted evidence claims and trusted-provider campus records;
this engine validates and resolves them before a decision. Provider calls return
data only: biometric modules must execute upstream and their latency is outside
the engine's measured decision-evaluation interval.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from time import perf_counter
from typing import Annotated, Protocol

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, TypeAdapter

from .authorization import (
    AuthorizationPolicy,
    AuthorizationSnapshot,
    CampusAuthorizationEvaluator,
)
from .conflict_resolver import (
    CampusRecordConflictResolver,
    CampusRecordValue,
    ConflictResolutionPolicy,
    RecordResolutionBatch,
)
from .enums import (
    AccessDecision,
    AccessReasonCode,
    EvidenceOutcome,
    RecordDomain,
    ResourceSensitivity,
    RevocationFindingState,
    VerificationModule,
)
from .evidence_validator import (
    EvidenceRequirements,
    EvidenceValidationResult,
    EvidenceValidator,
)
from .policy_evaluator import PolicyEvaluator
from .revocation import (
    RevocationChecker,
    RevocationEvaluationResult,
    RevocationPolicy,
    RevocationSourceCheck,
)
from .schemas import (
    AccessDecisionResponse,
    AccessRequest,
    CampusRoleRecord,
    DisciplinarySuspensionRecord,
    DomainModel,
    EvidenceSummary,
    ExaminationEligibilityRecord,
    EvaluationContext,
    IdentityStatusRecord,
    Identifier,
    LabSafetyClearanceRecord,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
    VerificationEvidence,
)


class EvidenceClaimsProvider(Protocol):
    """Return upstream evidence claims; this method must not execute biometrics."""

    def get_evidence(
        self, request: AccessRequest
    ) -> Sequence[VerificationEvidence | Mapping[str, object]]:
        """Load claims for the request; EvidenceValidator authenticates each claim."""


class CampusRecordProvider(Protocol):
    """Return campus data obtained through trusted server-side integrations."""

    def get_authorization_data(
        self, request: AccessRequest, evaluated_at: AwareDatetime
    ) -> "TrustedCampusData":
        """Fetch typed campus records and trusted revocation-source health checks."""


class DecisionPolicyProvider(Protocol):
    """Resolve server-owned per-request policy; never derive authority from client fields."""

    def get_policy(self, request: AccessRequest) -> "DecisionEnginePolicy":
        """Return the policy applicable to this request."""


class TrustedCampusData(DomainModel):
    """Provider output that is still checked for source authority and freshness."""

    authorization_snapshot: AuthorizationSnapshot
    revocation_source_checks: tuple[RevocationSourceCheck, ...] = ()


class DecisionEnginePolicy(DomainModel):
    """Server-owned policy bundle for one evaluation."""

    policy_version: Identifier
    resource_sensitivity: ResourceSensitivity
    evidence_requirements: EvidenceRequirements
    authorization_policy: AuthorizationPolicy
    conflict_resolution_policy: ConflictResolutionPolicy
    revocation_policy: RevocationPolicy


class AuthorizationSummary(DomainModel):
    permitted: StrictBool
    reason_codes: tuple[AccessReasonCode, ...]
    explanation: str


class ConflictResolutionSummary(DomainModel):
    domains_evaluated: tuple[RecordDomain, ...] = ()
    resolution_count: Annotated[StrictInt, Field(ge=0)]
    unresolved_conflict_count: Annotated[StrictInt, Field(ge=0)]
    reason_codes: tuple[AccessReasonCode, ...] = ()


class RevocationSummary(DomainModel):
    state: RevocationFindingState
    required: StrictBool
    blocking: StrictBool
    reason_codes: tuple[AccessReasonCode, ...] = ()


class ZeroTrustDecisionResult(AccessDecisionResponse):
    """Decision plus sanitized summaries; no raw evidence or provider payloads."""

    evidence_summary: EvidenceSummary
    authorization_summary: AuthorizationSummary
    conflict_resolution_summary: ConflictResolutionSummary
    revocation_summary: RevocationSummary


class ZeroTrustDecisionEngine:
    """Coordinate the Phase 2–4 components using only injected dependencies."""

    def __init__(
        self,
        *,
        evidence_validator: EvidenceValidator,
        evidence_provider: EvidenceClaimsProvider,
        campus_record_provider: CampusRecordProvider,
        policy_provider: DecisionPolicyProvider,
        authorization_evaluator: CampusAuthorizationEvaluator,
        policy_evaluator: PolicyEvaluator,
        conflict_resolver: CampusRecordConflictResolver,
        revocation_checker: RevocationChecker,
        clock: Callable[[], datetime],
        timer: Callable[[], float] = perf_counter,
    ) -> None:
        self._evidence_validator = evidence_validator
        self._evidence_provider = evidence_provider
        self._campus_record_provider = campus_record_provider
        self._policy_provider = policy_provider
        self._authorization_evaluator = authorization_evaluator
        self._policy_evaluator = policy_evaluator
        self._conflict_resolver = conflict_resolver
        self._revocation_checker = revocation_checker
        self._clock = clock
        self._timer = timer

    def evaluate(self, request: AccessRequest) -> ZeroTrustDecisionResult:
        request = AccessRequest.model_validate(request)
        try:
            evaluated_at = TypeAdapter(AwareDatetime).validate_python(self._clock())
        except Exception:
            raise RuntimeError("evaluation clock is unavailable") from None

        try:
            policy = DecisionEnginePolicy.model_validate(self._policy_provider.get_policy(request))
        except Exception:
            return self._failure_result(
                request,
                AccessReasonCode.POLICY_REQUIREMENTS_UNMET,
                evaluated_at,
            )
        context = EvaluationContext(
            request_id=request.request_id,
            evaluated_at=evaluated_at,
            policy_version=policy.policy_version,
            resource_sensitivity=policy.resource_sensitivity,
        )

        try:
            campus_data = TrustedCampusData.model_validate(
                self._campus_record_provider.get_authorization_data(request, evaluated_at)
            )
        except Exception:
            return self._failure_result(
                request,
                AccessReasonCode.AUTHORIZATION_DATA_UNAVAILABLE,
                evaluated_at,
                policy.policy_version,
                policy.resource_sensitivity,
            )
        try:
            evidence_claims = tuple(self._evidence_provider.get_evidence(request))
        except Exception:
            return self._failure_result(
                request,
                AccessReasonCode.EVIDENCE_PROVIDER_UNAVAILABLE,
                evaluated_at,
                policy.policy_version,
                policy.resource_sensitivity,
            )

        started = self._timer()
        try:
            evidence = self._evidence_validator.validate(
                request,
                evidence_claims,
                policy.evidence_requirements,
                context,
            )
            resolution_batches, resolved_snapshot = self._resolve_records(
                request,
                campus_data.authorization_snapshot,
                policy,
                evaluated_at,
            )
            authorization = self._authorization_evaluator.evaluate(
                request,
                resolved_snapshot,
                policy.authorization_policy,
                context,
            )
            resolved_records = tuple(
                record
                for batch in resolution_batches
                for record in batch.winning_records
            )
            revocation = self._revocation_checker.evaluate(
                subject_id=request.user_id,
                resource_id=request.resource.resource_id,
                records=resolved_records,
                sensitivity=policy.resource_sensitivity,
                evaluated_at=evaluated_at,
                policy=policy.revocation_policy,
                source_checks=campus_data.revocation_source_checks,
            )
            decision = self._policy_evaluator.evaluate(
                request,
                evidence,
                authorization,
                context,
                decision_latency_ms=0.0,
                record_resolutions=resolution_batches,
                revocation=revocation,
            )
            elapsed_ms = max((self._timer() - started) * 1000, 0.0)
            decision = AccessDecisionResponse.model_validate(
                {**decision.model_dump(), "decision_latency_ms": elapsed_ms}
            )
            return ZeroTrustDecisionResult(
                **decision.model_dump(),
                evidence_summary=self._evidence_summary(evidence),
                authorization_summary=AuthorizationSummary(
                    permitted=authorization.permitted,
                    reason_codes=authorization.reason_codes,
                    explanation=authorization.explanation,
                ),
                conflict_resolution_summary=self._conflict_summary(resolution_batches),
                revocation_summary=RevocationSummary(
                    state=revocation.state,
                    required=revocation.required,
                    blocking=revocation.blocking,
                    reason_codes=revocation.reason_codes,
                ),
            )
        except Exception:
            elapsed_ms = max((self._timer() - started) * 1000, 0.0)
            return self._failure_result(
                request,
                AccessReasonCode.POLICY_REQUIREMENTS_UNMET,
                evaluated_at,
                policy.policy_version,
                policy.resource_sensitivity,
                decision_latency_ms=elapsed_ms,
            )

    def _resolve_records(
        self,
        request: AccessRequest,
        snapshot: AuthorizationSnapshot,
        policy: DecisionEnginePolicy,
        evaluated_at: AwareDatetime,
    ) -> tuple[tuple[RecordResolutionBatch, ...], AuthorizationSnapshot]:
        user_id = request.user_id
        resource_id = request.resource.resource_id
        action_id = request.action.action_id
        exam_id = request.action.exam_id
        scoped = {
            RecordDomain.IDENTITY: tuple(r for r in snapshot.identities if r.subject_id == user_id),
            RecordDomain.ROLE: tuple(r for r in snapshot.role_assignments if r.subject_id == user_id),
            RecordDomain.PERMISSION: tuple(
                r for r in snapshot.permissions
                if r.subject_id == user_id and resource_id in r.resource_ids and action_id in r.action_ids
            ),
            RecordDomain.DISCIPLINARY: tuple(
                r for r in snapshot.suspensions
                if r.subject_id == user_id and (not r.resource_ids or resource_id in r.resource_ids)
            ),
            RecordDomain.EXAMINATION: tuple(
                r for r in snapshot.examinations
                if r.subject_id == user_id and exam_id is not None and r.exam_id == exam_id
            ),
            RecordDomain.TEMPORARY_PASS: tuple(
                r for r in snapshot.temporary_lab_passes
                if r.subject_id == user_id
                and r.resource_id == resource_id
                and action_id in r.action_ids
            ),
            RecordDomain.SAFETY_CLEARANCE: tuple(
                r for r in snapshot.safety_clearances
                if r.subject_id == user_id and r.resource_id == resource_id
            ),
            RecordDomain.REVOCATION: tuple(
                r for r in snapshot.revocations
                if r.subject_id == user_id and (r.resource_id is None or r.resource_id == resource_id)
            ),
        }
        batches: list[RecordResolutionBatch] = []
        winners: list[CampusRecordValue] = []
        for domain in RecordDomain:
            records = scoped[domain]
            if not records:
                continue
            batch = self._conflict_resolver.resolve(
                records,
                domain=domain,
                sensitivity=policy.resource_sensitivity,
                policy=policy.conflict_resolution_policy,
                evaluated_at=evaluated_at,
            )
            batches.append(batch)
            winners.extend(batch.winning_records)

        return tuple(batches), AuthorizationSnapshot(
            identities=tuple(r for r in winners if isinstance(r, IdentityStatusRecord)),
            role_assignments=tuple(r for r in winners if isinstance(r, CampusRoleRecord)),
            permissions=tuple(r for r in winners if isinstance(r, ResourcePermissionRecord)),
            suspensions=tuple(r for r in winners if isinstance(r, DisciplinarySuspensionRecord)),
            examinations=tuple(r for r in winners if isinstance(r, ExaminationEligibilityRecord)),
            temporary_lab_passes=tuple(r for r in winners if isinstance(r, TemporaryLabPassRecord)),
            safety_clearances=tuple(r for r in winners if isinstance(r, LabSafetyClearanceRecord)),
            revocations=tuple(r for r in winners if isinstance(r, RevocationStatusRecord)),
        )

    @staticmethod
    def _evidence_summary(evidence: EvidenceValidationResult) -> EvidenceSummary:
        counts = Counter(item.evidence.outcome for item in evidence.accepted_evidence)
        modules = tuple(sorted({item.evidence.module for item in evidence.accepted_evidence}, key=lambda item: item.value))
        return EvidenceSummary(
            evidence_count=len(evidence.accepted_evidence),
            outcome_counts=dict(counts),
            validated_modules=modules,
            provenance=(),
        )

    @staticmethod
    def _conflict_summary(batches: tuple[RecordResolutionBatch, ...]) -> ConflictResolutionSummary:
        resolutions = tuple(result for batch in batches for result in batch.resolutions)
        codes = {
            code
            for result in resolutions
            for code in result.reason_codes
            if code is not AccessReasonCode.ACCESS_POLICY_SATISFIED
        }
        return ConflictResolutionSummary(
            domains_evaluated=tuple(batch.domain for batch in batches),
            resolution_count=len(resolutions),
            unresolved_conflict_count=sum(result.conflict for result in resolutions),
            reason_codes=tuple(sorted(codes, key=lambda item: item.value)),
        )

    @staticmethod
    def _failure_result(
        request: AccessRequest,
        reason: AccessReasonCode,
        evaluated_at: AwareDatetime,
        policy_version: str = "unavailable",
        sensitivity: ResourceSensitivity = ResourceSensitivity.CRITICAL,
        *,
        decision_latency_ms: float = 0.0,
    ) -> ZeroTrustDecisionResult:
        revocation_required = sensitivity in {ResourceSensitivity.HIGH, ResourceSensitivity.CRITICAL}
        revocation_reasons = (
            (AccessReasonCode.REVOCATION_UNAVAILABLE,) if revocation_required else ()
        )
        return ZeroTrustDecisionResult(
            request_id=request.request_id,
            user_id=request.user_id,
            resource_id=request.resource.resource_id,
            decision=AccessDecision.DENY,
            access_granted=False,
            reason_codes=(reason,),
            explanation="Access denied because a safe decision could not be completed.",
            policy_version=policy_version,
            evaluated_at=evaluated_at,
            decision_latency_ms=decision_latency_ms,
            audit_reference=None,
            evidence_summary=EvidenceSummary(evidence_count=0, outcome_counts={}),
            authorization_summary=AuthorizationSummary(
                permitted=False,
                reason_codes=(reason,),
                explanation="Authorization could not be confirmed.",
            ),
            conflict_resolution_summary=ConflictResolutionSummary(
                resolution_count=0,
                unresolved_conflict_count=0,
                reason_codes=(reason,),
            ),
            revocation_summary=RevocationSummary(
                state=RevocationFindingState.MISSING_REVOCATION_INFORMATION,
                required=revocation_required,
                blocking=revocation_required,
                reason_codes=revocation_reasons,
            ),
        )

