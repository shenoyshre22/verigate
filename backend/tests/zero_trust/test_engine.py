from datetime import datetime, timedelta, timezone

import pytest

from backend.modules.zero_trust.authorization import (
    AuthorizationPolicy,
    AuthorizationSnapshot,
    CampusAuthorizationEvaluator,
)
from backend.modules.zero_trust.conflict_resolver import (
    CampusRecordConflictResolver,
    ConflictResolutionPolicy,
    SourceAuthorityRule,
)
from backend.modules.zero_trust.engine import (
    DecisionEnginePolicy,
    TrustedCampusData,
    ZeroTrustDecisionEngine,
)
from backend.modules.zero_trust.enums import (
    AccessDecision,
    AccessReasonCode,
    EvidenceOutcome,
    PermissionEffect,
    RecordDomain,
    RecordStatus,
    ResourceSensitivity,
    RevocationState,
    VerificationModule,
)
from backend.modules.zero_trust.evidence_validator import (
    EvidenceFreshnessPolicy,
    EvidenceRequirements,
    EvidenceValidator,
    TrustedEvidence,
)
from backend.modules.zero_trust.policy_evaluator import PolicyEvaluator
from backend.modules.zero_trust.revocation import (
    RevocationChecker,
    RevocationPolicy,
    RevocationSourceCheck,
)
from backend.modules.zero_trust.schemas import (
    AccessAction,
    AccessRequest,
    CampusRoleRecord,
    DisciplinarySuspensionRecord,
    EvidenceProvenance,
    ExaminationEligibilityRecord,
    ExaminationWindow,
    IdentityStatusRecord,
    ResourcePermissionRecord,
    TemporaryLabPassRecord,
    VerificationEvidence,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def record_fields(**overrides):
    fields = {
        "record_id": "record-1",
        "subject_id": "user-1",
        "source_id": "sis",
        "version": 1,
        "issued_at": NOW - timedelta(hours=2),
        "source_updated_at": NOW - timedelta(hours=1),
        "observed_at": NOW - timedelta(minutes=5),
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "status": RecordStatus.ACTIVE,
    }
    fields.update(overrides)
    return fields


def make_request(**kwargs):
    values = {
        "request_id": "request-1",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "resource": {"resource_id": "LAB_101"},
        "action": {"action_id": "ENTER"},
        "requested_at": NOW,
    }
    values.update(kwargs)
    return AccessRequest.model_validate(values)


def make_evidence(module, *, outcome=EvidenceOutcome.SUCCESS, user_id="user-1", attempt_id="attempt-1", evidence_id=None):
    issuer = f"issuer-{module.value}"
    return VerificationEvidence(
        module=module,
        user_id=user_id,
        authentication_attempt_id=attempt_id,
        outcome=outcome,
        issued_at=NOW,
        issuer_id=issuer,
        evidence_id=evidence_id or f"evidence-{module.value}-{outcome.value}",
    )


class InMemoryEvidenceProvider:
    def __init__(self, claims=(), *, error=None):
        self.claims = tuple(claims)
        self.error = error

    def get_evidence(self, request):
        if self.error:
            raise self.error
        return self.claims


class TrustedAdapter:
    def __init__(self, module):
        self.module = module
        self.issuer_id = f"issuer-{module.value}"
        self.provider_id = f"trusted-{module.value.lower()}-provider"

    def validate_evidence(self, claim):
        if claim.module is VerificationModule.FACE_RECOGNITION:
            result = "MATCH" if claim.outcome is EvidenceOutcome.SUCCESS else "NO_MATCH"
        elif claim.module is VerificationModule.FACE_LIVENESS:
            result = "LIVE" if claim.outcome is EvidenceOutcome.SUCCESS else "SPOOF"
        elif claim.module is VerificationModule.FINGERPRINT:
            result = "MATCH" if claim.outcome is EvidenceOutcome.SUCCESS else "NO_MATCH"
        else:
            result = "VALID" if claim.outcome is EvidenceOutcome.SUCCESS else "INVALID"
        return TrustedEvidence(
            evidence=claim,
            provenance=EvidenceProvenance(
                evidence_id=claim.evidence_id,
                issuer_id=claim.issuer_id,
                provider_id=self.provider_id,
                validated_at=NOW,
                validated_outcome=claim.outcome,
            ),
            module_result=result,
        )


class InMemoryIssuerProvider:
    def __init__(self, *, modules=tuple(VerificationModule), unavailable=False):
        self.issuers = {f"issuer-{module.value}": TrustedAdapter(module) for module in modules}
        self.unavailable = unavailable

    def get_trusted_issuer(self, issuer_id):
        if self.unavailable:
            raise RuntimeError("internal provider detail")
        return self.issuers.get(issuer_id)


class InMemoryCampusProvider:
    def __init__(self, snapshot=None, *, error=None):
        self.snapshot = snapshot or valid_snapshot()
        self.error = error

    def get_authorization_data(self, request, evaluated_at):
        if self.error:
            raise self.error
        return TrustedCampusData(
            authorization_snapshot=self.snapshot,
            revocation_source_checks=(
                RevocationSourceCheck(source_id="revocation", checked_at=evaluated_at, available=True),
            ),
        )


class InMemoryPolicyProvider:
    def __init__(self, policy=None, *, error=None):
        self.policy = policy or make_policy()
        self.error = error

    def get_policy(self, request):
        if self.error:
            raise self.error
        return self.policy


def valid_snapshot():
    return AuthorizationSnapshot(
        identities=(IdentityStatusRecord(**record_fields(source_id="sis")),),
        permissions=(
            ResourcePermissionRecord(
                **record_fields(
                    source_id="access-control",
                    effect=PermissionEffect.GRANT,
                    resource_ids=("LAB_101",),
                    action_ids=("ENTER",),
                )
            ),
        ),
    )


def make_policy(*, sensitivity=ResourceSensitivity.LOW, evidence_requirements=None, authorization_policy=None, conflict_policy=None):
    sources = {
        RecordDomain.IDENTITY: (SourceAuthorityRule(source_id="sis", priority=0),),
        RecordDomain.ROLE: (SourceAuthorityRule(source_id="roles", priority=0),),
        RecordDomain.PERMISSION: (SourceAuthorityRule(source_id="access-control", priority=0),),
        RecordDomain.DISCIPLINARY: (SourceAuthorityRule(source_id="conduct", priority=0),),
        RecordDomain.EXAMINATION: (SourceAuthorityRule(source_id="exam-office", priority=0),),
        RecordDomain.TEMPORARY_PASS: (SourceAuthorityRule(source_id="lab-office", priority=0),),
        RecordDomain.SAFETY_CLEARANCE: (SourceAuthorityRule(source_id="safety", priority=0),),
        RecordDomain.REVOCATION: (SourceAuthorityRule(source_id="revocation", priority=0),),
    }
    return DecisionEnginePolicy(
        policy_version="test-policy-v1",
        resource_sensitivity=sensitivity,
        evidence_requirements=evidence_requirements or EvidenceRequirements(
            required_modules=(VerificationModule.FACE_RECOGNITION, VerificationModule.FACE_LIVENESS)
        ),
        authorization_policy=authorization_policy or AuthorizationPolicy(),
        conflict_resolution_policy=conflict_policy or ConflictResolutionPolicy(
            sources_by_domain=sources,
            max_age_by_domain={domain: timedelta(days=2) for domain in RecordDomain},
        ),
        revocation_policy=RevocationPolicy(
            max_age_by_sensitivity={
                ResourceSensitivity.HIGH: timedelta(minutes=5),
                ResourceSensitivity.CRITICAL: timedelta(minutes=5),
            },
            authoritative_sources=("revocation",),
        ),
    )


def build_engine(*, claims=None, snapshot=None, policy=None, evidence_error=None, campus_error=None, policy_error=None, issuer_unavailable=False, authorization_evaluator=None):
    return ZeroTrustDecisionEngine(
        evidence_validator=EvidenceValidator(
            InMemoryIssuerProvider(unavailable=issuer_unavailable),
            EvidenceFreshnessPolicy(
                max_age_by_module={module: timedelta(hours=1) for module in VerificationModule}
            ),
        ),
        evidence_provider=InMemoryEvidenceProvider(
            claims if claims is not None else (
                make_evidence(VerificationModule.FACE_RECOGNITION),
                make_evidence(VerificationModule.FACE_LIVENESS),
            ),
            error=evidence_error,
        ),
        campus_record_provider=InMemoryCampusProvider(snapshot, error=campus_error),
        policy_provider=InMemoryPolicyProvider(policy, error=policy_error),
        authorization_evaluator=authorization_evaluator or CampusAuthorizationEvaluator(),
        policy_evaluator=PolicyEvaluator(),
        conflict_resolver=CampusRecordConflictResolver(),
        revocation_checker=RevocationChecker(),
        clock=lambda: NOW,
    )


def test_valid_identity_and_authorization_allow_with_sanitized_summaries():
    result = build_engine().evaluate(make_request())
    assert result.decision is AccessDecision.ALLOW
    assert result.access_granted is True
    assert result.evidence_summary.evidence_count == 2
    assert result.authorization_summary.permitted is True
    assert result.revocation_summary.state.value == "MISSING_REVOCATION_INFORMATION"
    assert result.decision_latency_ms >= 0
    assert result.model_dump(mode="json").get("face_image") is None


def test_face_match_and_confirmed_spoof_deny():
    claims = (
        make_evidence(VerificationModule.FACE_RECOGNITION),
        make_evidence(VerificationModule.FACE_LIVENESS, outcome=EvidenceOutcome.FAILURE),
    )
    result = build_engine(claims=claims).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert result.access_granted is False
    assert AccessReasonCode.CONFIRMED_SPOOF in result.reason_codes


def test_valid_fingerprint_never_overrides_suspension():
    snapshot = AuthorizationSnapshot(
        identities=(IdentityStatusRecord(**record_fields(source_id="sis")),),
        permissions=(
            ResourcePermissionRecord(
                **record_fields(source_id="access-control", effect=PermissionEffect.GRANT, resource_ids=("LAB_101",), action_ids=("ENTER",))
            ),
        ),
        suspensions=(
            DisciplinarySuspensionRecord(
                **record_fields(source_id="conduct", status=RecordStatus.SUSPENDED, reason_code="conduct-hold")
            ),
        ),
    )
    policy = make_policy(evidence_requirements=EvidenceRequirements(required_modules=(VerificationModule.FINGERPRINT,)))
    result = build_engine(
        claims=(make_evidence(VerificationModule.FINGERPRINT),), snapshot=snapshot, policy=policy
    ).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.IDENTITY_SUSPENDED in result.reason_codes


def test_valid_rfid_never_overrides_revoked_permission():
    snapshot = AuthorizationSnapshot(
        identities=(IdentityStatusRecord(**record_fields(source_id="sis")),),
        permissions=(
            ResourcePermissionRecord(
                **record_fields(
                    source_id="access-control",
                    status=RecordStatus.REVOKED,
                    effect=PermissionEffect.GRANT,
                    resource_ids=("LAB_101",),
                    action_ids=("ENTER",),
                )
            ),
        ),
    )
    policy = make_policy(evidence_requirements=EvidenceRequirements(required_modules=(VerificationModule.RFID,)))
    result = build_engine(claims=(make_evidence(VerificationModule.RFID),), snapshot=snapshot, policy=policy).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.PERMISSION_REVOKED in result.reason_codes


def test_missing_required_liveness_requests_verification_without_grant():
    result = build_engine(claims=(make_evidence(VerificationModule.FACE_RECOGNITION),)).evaluate(make_request())
    assert result.decision is AccessDecision.REQUEST_VERIFICATION
    assert result.access_granted is False


def test_stale_sensitive_authorization_fails_closed():
    stale_identity = IdentityStatusRecord(
        **record_fields(
            source_id="sis",
            issued_at=NOW - timedelta(days=10),
            source_updated_at=NOW - timedelta(days=9),
            observed_at=NOW - timedelta(days=8),
            valid_from=NOW - timedelta(days=20),
        )
    )
    snapshot = AuthorizationSnapshot(
        identities=(stale_identity,),
        permissions=valid_snapshot().permissions,
    )
    result = build_engine(snapshot=snapshot, policy=make_policy(sensitivity=ResourceSensitivity.HIGH)).evaluate(make_request())
    assert result.decision in {AccessDecision.DENY, AccessDecision.REQUEST_VERIFICATION}
    assert result.decision is not AccessDecision.ALLOW
    assert AccessReasonCode.RECORD_STALE in result.reason_codes


def test_unresolved_high_authority_conflict_never_allows():
    policy = make_policy(
        sensitivity=ResourceSensitivity.HIGH,
        conflict_policy=ConflictResolutionPolicy(
            sources_by_domain={
                **make_policy().conflict_resolution_policy.sources_by_domain,
                RecordDomain.IDENTITY: (
                    SourceAuthorityRule(source_id="sis", priority=0),
                    SourceAuthorityRule(source_id="registrar", priority=0),
                ),
            },
            max_age_by_domain={domain: timedelta(days=2) for domain in RecordDomain},
            conflict_decision_by_sensitivity={ResourceSensitivity.HIGH: AccessDecision.REQUEST_VERIFICATION},
        ),
    )
    snapshot = AuthorizationSnapshot(
        identities=(
            IdentityStatusRecord(**record_fields(source_id="sis")),
            IdentityStatusRecord(**record_fields(record_id="identity-2", source_id="registrar", status=RecordStatus.BLOCKED)),
        ),
        permissions=valid_snapshot().permissions,
    )
    result = build_engine(snapshot=snapshot, policy=policy).evaluate(make_request())
    assert result.decision is not AccessDecision.ALLOW
    assert result.conflict_resolution_summary.unresolved_conflict_count == 1


def test_expired_temporary_lab_pass_denies():
    snapshot = AuthorizationSnapshot(
        identities=(IdentityStatusRecord(**record_fields(source_id="sis")),),
        temporary_lab_passes=(
            TemporaryLabPassRecord(
                **record_fields(
                    source_id="lab-office",
                    resource_id="LAB_101",
                    action_ids=("ENTER",),
                    purpose_id="MAINTENANCE",
                    valid_until=NOW,
                )
            ),
        ),
    )
    policy = make_policy(
        authorization_policy=AuthorizationPolicy(temporary_pass_required_resources=("LAB_101",))
    )
    result = build_engine(snapshot=snapshot, policy=policy).evaluate(
        make_request(action={"action_id": "ENTER", "purpose_id": "MAINTENANCE"})
    )
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_EXPIRED in result.reason_codes


def test_valid_temporary_examination_eligibility_allows_at_assigned_time_and_location():
    exam = ExaminationEligibilityRecord(
        **record_fields(
            source_id="exam-office",
            exam_id="EXAM-1",
            eligible=True,
            resource_ids=("EXAM_HALL",),
            schedule=(ExaminationWindow(starts_at=NOW - timedelta(minutes=30), ends_at=NOW + timedelta(minutes=30)),),
        )
    )
    snapshot = AuthorizationSnapshot(identities=(IdentityStatusRecord(**record_fields(source_id="sis")),), examinations=(exam,))
    request = make_request(
        resource={"resource_id": "EXAM_HALL"},
        action={"action_id": "TAKE_EXAM", "exam_id": "EXAM-1"},
    )
    result = build_engine(snapshot=snapshot).evaluate(request)
    assert result.decision is AccessDecision.ALLOW


def test_permission_for_wrong_resource_denies():
    snapshot = AuthorizationSnapshot(
        identities=(IdentityStatusRecord(**record_fields(source_id="sis")),),
        permissions=(
            ResourcePermissionRecord(
                **record_fields(source_id="access-control", effect=PermissionEffect.GRANT, resource_ids=("LIBRARY",), action_ids=("ENTER",))
            ),
        ),
    )
    result = build_engine(snapshot=snapshot).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.PERMISSION_NOT_FOUND in result.reason_codes


def test_sensitive_access_with_stale_revocation_check_denies():
    class StaleRevocationProvider(InMemoryCampusProvider):
        def get_authorization_data(self, request, evaluated_at):
            return TrustedCampusData(
                authorization_snapshot=self.snapshot,
                revocation_source_checks=(
                    RevocationSourceCheck(source_id="revocation", checked_at=evaluated_at - timedelta(hours=1), available=True),
                ),
            )

    engine = build_engine(policy=make_policy(sensitivity=ResourceSensitivity.CRITICAL))
    engine._campus_record_provider = StaleRevocationProvider()
    result = engine.evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert result.revocation_summary.blocking is True
    assert AccessReasonCode.REVOCATION_STALE in result.reason_codes


@pytest.mark.parametrize("user_id,attempt_id", [("user-2", "attempt-1"), ("user-1", "attempt-2")])
def test_evidence_for_another_user_or_attempt_never_allows(user_id, attempt_id):
    claims = (
        make_evidence(VerificationModule.FACE_RECOGNITION, user_id=user_id, attempt_id=attempt_id),
        make_evidence(VerificationModule.FACE_LIVENESS),
    )
    result = build_engine(claims=claims).evaluate(make_request())
    assert result.decision is not AccessDecision.ALLOW


def test_evidence_provider_unavailable_fails_closed():
    result = build_engine(evidence_error=RuntimeError("secret details")).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.EVIDENCE_PROVIDER_UNAVAILABLE in result.reason_codes
    assert "secret details" not in result.explanation


def test_malformed_campus_provider_response_fails_closed():
    class MalformedProvider:
        def get_authorization_data(self, request, evaluated_at):
            return {"trusted_authority": "caller-claimed"}

    engine = build_engine()
    engine._campus_record_provider = MalformedProvider()
    result = engine.evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.AUTHORIZATION_DATA_UNAVAILABLE in result.reason_codes


def test_campus_provider_unavailable_fails_closed():
    result = build_engine(campus_error=RuntimeError("campus backend detail")).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.AUTHORIZATION_DATA_UNAVAILABLE in result.reason_codes
    assert "campus backend detail" not in result.explanation


def test_policy_provider_unavailable_fails_closed():
    result = build_engine(policy_error=RuntimeError("private policy details")).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.POLICY_REQUIREMENTS_UNMET in result.reason_codes
    assert "private policy details" not in result.explanation


def test_unavailable_evidence_issuer_never_produces_allow():
    result = build_engine(issuer_unavailable=True).evaluate(make_request())
    assert result.decision is not AccessDecision.ALLOW


def test_unauthorized_issuer_claim_never_produces_allow():
    face = make_evidence(VerificationModule.FACE_RECOGNITION)
    untrusted_face = VerificationEvidence.model_validate(
        {**face.model_dump(), "issuer_id": "unregistered-issuer"}
    )
    result = build_engine(
        claims=(untrusted_face, make_evidence(VerificationModule.FACE_LIVENESS))
    ).evaluate(make_request())
    assert result.decision is not AccessDecision.ALLOW


def test_missing_required_campus_identity_denies():
    snapshot = AuthorizationSnapshot(permissions=valid_snapshot().permissions)
    result = build_engine(snapshot=snapshot).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.IDENTITY_INVALID in result.reason_codes


def test_duplicate_evidence_does_not_allow():
    face = make_evidence(VerificationModule.FACE_RECOGNITION, evidence_id="duplicate")
    result = build_engine(
        claims=(face, face, make_evidence(VerificationModule.FACE_LIVENESS))
    ).evaluate(make_request())
    assert result.decision is not AccessDecision.ALLOW


def test_contradictory_evidence_from_one_module_does_not_allow():
    face_success = make_evidence(VerificationModule.FACE_RECOGNITION, evidence_id="face-success")
    face_failure = make_evidence(VerificationModule.FACE_RECOGNITION, outcome=EvidenceOutcome.FAILURE, evidence_id="face-failure")
    result = build_engine(
        claims=(face_success, face_failure, make_evidence(VerificationModule.FACE_LIVENESS))
    ).evaluate(make_request())
    assert result.decision is not AccessDecision.ALLOW


def test_internal_component_exception_fails_closed():
    class FailingAuthorizationEvaluator:
        def evaluate(self, *args, **kwargs):
            raise RuntimeError("private stack detail")

    result = build_engine(authorization_evaluator=FailingAuthorizationEvaluator()).evaluate(make_request())
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.POLICY_REQUIREMENTS_UNMET in result.reason_codes
    assert "private stack detail" not in result.explanation

