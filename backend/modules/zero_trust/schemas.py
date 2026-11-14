"""Validated API and domain schemas for Zero Trust decisions.

Request evidence and record objects describe claims and provider data; their
construction alone does not authenticate their issuer or establish authority.
Those checks belong to trusted server-side provider interfaces.
"""

from typing import Annotated

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    FiniteFloat,
    StrictBool,
    StrictInt,
    StringConstraints,
    model_validator,
)

from .enums import (
    AccessDecision,
    AccessReasonCode,
    EvidenceOutcome,
    PermissionEffect,
    RecordStatus,
    ResourceSensitivity,
    RevocationState,
    VerificationModule,
)

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
Version = Annotated[StrictInt, Field(gt=0)]
Score = Annotated[FiniteFloat, Field(ge=0, le=100)]


class DomainModel(BaseModel):
    """Common strict model configuration: reject unknown fields and freeze values."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class RequestedResource(DomainModel):
    """Resource identifier supplied by the access requester."""

    resource_id: Identifier


class AccessAction(DomainModel):
    """Action identifier; policy determines whether that action is permitted."""

    action_id: Identifier


class AccessRequest(DomainModel):
    """Caller request data, excluding trusted evidence or source-authority claims."""

    request_id: Identifier
    user_id: Identifier
    authentication_attempt_id: Identifier
    resource: RequestedResource
    action: AccessAction
    requested_at: AwareDatetime


class EvaluationContext(DomainModel):
    """Server-constructed policy snapshot and clock context for deterministic evaluation."""

    request_id: Identifier
    evaluated_at: AwareDatetime
    policy_version: Identifier
    resource_sensitivity: ResourceSensitivity


class VerificationEvidence(DomainModel):
    """Untrusted evidence claim that must be checked through a trusted provider."""

    module: VerificationModule
    user_id: Identifier
    authentication_attempt_id: Identifier
    outcome: EvidenceOutcome
    issued_at: AwareDatetime
    issuer_id: Identifier
    evidence_id: Identifier
    expires_at: AwareDatetime | None = None
    similarity: Score | None = None
    confidence: Score | None = None

    @model_validator(mode="after")
    def expiry_must_follow_issue_time(self) -> "VerificationEvidence":
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        return self


class EvidenceProvenance(DomainModel):
    """Trusted-provider validation metadata; provider_id is not an authority rank."""

    evidence_id: Identifier
    issuer_id: Identifier
    provider_id: Identifier
    validated_at: AwareDatetime
    validated_outcome: EvidenceOutcome


class EvidenceSummary(DomainModel):
    """Non-biometric summary of evidence validation for a response or audit event."""

    evidence_count: Annotated[StrictInt, Field(ge=0)]
    outcome_counts: dict[EvidenceOutcome, Annotated[StrictInt, Field(ge=0)]]
    validated_modules: tuple[VerificationModule, ...] = ()
    provenance: tuple[EvidenceProvenance, ...] = ()

    @model_validator(mode="after")
    def counts_must_match_total(self) -> "EvidenceSummary":
        if sum(self.outcome_counts.values()) != self.evidence_count:
            raise ValueError("outcome_counts must sum to evidence_count")
        if len(set(self.validated_modules)) != len(self.validated_modules):
            raise ValueError("validated_modules must not contain duplicates")
        return self


class CampusRecord(DomainModel):
    """Common fields returned by trusted campus-record providers."""

    record_id: Identifier
    subject_id: Identifier
    source_id: Identifier
    version: Version
    issued_at: AwareDatetime
    source_updated_at: AwareDatetime
    observed_at: AwareDatetime
    valid_from: AwareDatetime
    valid_until: AwareDatetime | None = None
    status: RecordStatus

    @model_validator(mode="after")
    def validity_interval_must_be_ordered(self) -> "CampusRecord":
        if self.issued_at > self.observed_at:
            raise ValueError("observed_at must not be earlier than issued_at")
        if self.source_updated_at > self.observed_at:
            raise ValueError("observed_at must not be earlier than source_updated_at")
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        return self


class IdentityStatusRecord(CampusRecord):
    """Trusted campus identity lifecycle status for a subject."""


class ResourcePermissionRecord(CampusRecord):
    """Permission effect scoped to explicit resources and actions."""

    effect: PermissionEffect
    resource_ids: tuple[Identifier, ...] = Field(min_length=1)
    action_ids: tuple[Identifier, ...] = Field(min_length=1)


class DisciplinarySuspensionRecord(CampusRecord):
    """Disciplinary suspension; an empty resource scope denotes identity-wide scope."""

    resource_ids: tuple[Identifier, ...] = ()
    reason_code: Identifier


class ExaminationWindow(DomainModel):
    starts_at: AwareDatetime
    ends_at: AwareDatetime

    @model_validator(mode="after")
    def window_must_be_ordered(self) -> "ExaminationWindow":
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be later than starts_at")
        return self


class ExaminationEligibilityRecord(CampusRecord):
    """Subject eligibility and allowed examination time windows."""

    exam_id: Identifier
    eligible: StrictBool
    resource_ids: tuple[Identifier, ...] = Field(min_length=1)
    schedule: tuple[ExaminationWindow, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def schedule_windows_must_be_ordered(self) -> "ExaminationEligibilityRecord":
        for previous, current in zip(self.schedule, self.schedule[1:]):
            if current.starts_at < previous.ends_at:
                raise ValueError("schedule windows must be ordered and non-overlapping")
        return self


class TemporaryLabPassRecord(CampusRecord):
    """Temporary authorization scoped to one lab resource and explicit actions."""

    resource_id: Identifier
    action_ids: tuple[Identifier, ...] = Field(min_length=1)
    valid_until: AwareDatetime


class LabSafetyClearanceRecord(CampusRecord):
    """Safety clearance scoped to a lab and the required completed clearances."""

    resource_id: Identifier
    cleared: StrictBool
    requirement_ids: tuple[Identifier, ...] = Field(min_length=1)


class RevocationStatusRecord(CampusRecord):
    """Provider-sourced revocation state; freshness is evaluated by trusted policy."""

    revocation_state: RevocationState
    resource_id: Identifier | None = None


class RecordProvenanceSummary(DomainModel):
    """Non-secret provenance for a campus record used in a decision."""

    record_id: Identifier
    source_id: Identifier
    version: Version
    observed_at: AwareDatetime
    status: RecordStatus


class AccessDecisionResponse(DomainModel):
    request_id: Identifier
    user_id: Identifier
    resource_id: Identifier
    decision: AccessDecision
    access_granted: StrictBool
    reason_codes: tuple[AccessReasonCode, ...] = Field(min_length=1)
    explanation: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    policy_version: Identifier
    evaluated_at: AwareDatetime
    decision_latency_ms: Annotated[FiniteFloat, Field(ge=0)]
    audit_reference: Identifier | None = None

    @model_validator(mode="after")
    def grant_must_match_allow_decision(self) -> "AccessDecisionResponse":
        if self.access_granted != (self.decision is AccessDecision.ALLOW):
            raise ValueError("access_granted must be true if and only if decision is ALLOW")
        return self


class ZeroTrustAuditEvent(DomainModel):
    """Structured audit summary with no raw biometric data or credentials."""

    request_id: Identifier
    user_id: Identifier
    resource_id: Identifier
    decision: AccessDecision
    reason_codes: tuple[AccessReasonCode, ...] = Field(min_length=1)
    policy_version: Identifier
    evaluated_at: AwareDatetime
    evidence_summary: EvidenceSummary
    record_provenance_summary: tuple[RecordProvenanceSummary, ...] = ()


# Common public schema names retained as aliases to the more specific models.
DecisionResponse = AccessDecisionResponse
AuditEvent = ZeroTrustAuditEvent
