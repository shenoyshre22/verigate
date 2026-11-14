from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from backend.modules.zero_trust.authorization import AuthorizationEvaluationResult
from backend.modules.zero_trust.conflict_resolver import (
    CampusRecordConflictResolver,
    ConflictResolutionPolicy,
    SourceAuthorityRule,
)
from backend.modules.zero_trust.enums import (
    AccessDecision,
    AccessReasonCode,
    RecordDomain,
    RecordFreshness,
    RecordStatus,
    ResourceSensitivity,
    RevocationFindingState,
    RevocationState,
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
    DisciplinarySuspensionRecord,
    EvaluationContext,
    IdentityStatusRecord,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def campus_record(**overrides):
    values = {
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
    values.update(overrides)
    return values


def identity(**overrides):
    return IdentityStatusRecord(**campus_record(**overrides))


def permission(**overrides):
    values = campus_record(effect="GRANT", resource_ids=("LAB_101",), action_ids=("ENTER",))
    values.update(overrides)
    return ResourcePermissionRecord(**values)


def resolver_policy(*, identity_sources=(("sis", 0),), permission_sources=(("lab-admin", 0),), max_age=timedelta(days=2), conflict=AccessDecision.DENY):
    return ConflictResolutionPolicy(
        sources_by_domain={
            RecordDomain.IDENTITY: tuple(SourceAuthorityRule(source_id=source, priority=priority) for source, priority in identity_sources),
            RecordDomain.PERMISSION: tuple(SourceAuthorityRule(source_id=source, priority=priority) for source, priority in permission_sources),
            RecordDomain.DISCIPLINARY: (SourceAuthorityRule(source_id="conduct", priority=0),),
            RecordDomain.TEMPORARY_PASS: (SourceAuthorityRule(source_id="lab-admin", priority=0),),
            RecordDomain.REVOCATION: (SourceAuthorityRule(source_id="revocation", priority=0),),
        },
        max_age_by_domain={domain: max_age for domain in RecordDomain},
        conflict_decision_by_sensitivity={ResourceSensitivity.HIGH: conflict, ResourceSensitivity.CRITICAL: conflict},
    )


def resolve(records, domain, policy=None, sensitivity=ResourceSensitivity.LOW):
    return CampusRecordConflictResolver().resolve(
        tuple(records),
        domain=domain,
        sensitivity=sensitivity,
        policy=policy or resolver_policy(),
        evaluated_at=NOW,
    )


def test_active_identity_and_authoritative_suspension_remain_separate_and_suspension_denies():
    active = resolve((identity(),), RecordDomain.IDENTITY)
    suspension = DisciplinarySuspensionRecord(
        **campus_record(source_id="conduct", status=RecordStatus.SUSPENDED, reason_code="disciplinary-hold")
    )
    suspended = resolve((suspension,), RecordDomain.DISCIPLINARY)

    assert active.resolutions[0].decision is AccessDecision.ALLOW
    assert suspended.resolutions[0].decision is AccessDecision.DENY


def test_identity_source_does_not_gain_disciplinary_authority():
    untrusted_discipline = DisciplinarySuspensionRecord(
        **campus_record(source_id="sis", status=RecordStatus.SUSPENDED, reason_code="disciplinary-hold")
    )
    result = resolve((untrusted_discipline,), RecordDomain.DISCIPLINARY)

    assert result.resolutions[0].decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_SOURCE_UNAUTHORIZED in result.resolutions[0].reason_codes


def test_higher_authority_older_record_beats_lower_authority_newer_record():
    policy = resolver_policy(identity_sources=(("registrar", 0), ("imported-feed", 9)))
    high = identity(
        source_id="registrar",
        version=2,
        issued_at=NOW - timedelta(days=2),
        source_updated_at=NOW - timedelta(days=1),
        observed_at=NOW - timedelta(hours=1),
    )
    low = identity(record_id="record-2", source_id="imported-feed", version=8, status=RecordStatus.BLOCKED, source_updated_at=NOW - timedelta(minutes=1), observed_at=NOW)

    result = resolve((low, high), RecordDomain.IDENTITY, policy)

    assert result.resolutions[0].winning_record == high
    assert result.resolutions[0].decision is AccessDecision.ALLOW


def test_newer_authoritative_revocation_beats_older_grant():
    old_grant = permission(source_id="lab-admin", version=1)
    revoked = permission(record_id="record-2", source_id="lab-admin", version=2, status=RecordStatus.REVOKED)

    result = resolve((old_grant, revoked), RecordDomain.PERMISSION)

    assert result.resolutions[0].winning_record == revoked
    assert result.resolutions[0].decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_REVOKED in result.resolutions[0].reason_codes


def test_lower_authority_cannot_override_higher_authority_revocation():
    policy = resolver_policy(permission_sources=(("lab-admin", 0), ("legacy-import", 5)))
    revoked = permission(source_id="lab-admin", version=3, status=RecordStatus.REVOKED)
    newer_grant = permission(record_id="record-2", source_id="legacy-import", version=10, source_updated_at=NOW, observed_at=NOW)

    result = resolve((newer_grant, revoked), RecordDomain.PERMISSION, policy)

    assert result.resolutions[0].winning_record == revoked
    assert result.resolutions[0].decision is AccessDecision.DENY


def test_equal_authority_contradiction_is_unresolved_and_never_allows():
    policy = resolver_policy(identity_sources=(("sis", 0), ("registrar", 0)), conflict=AccessDecision.REQUEST_VERIFICATION)
    records = (
        identity(source_id="sis"),
        identity(record_id="record-2", source_id="registrar", status=RecordStatus.BLOCKED),
    )

    result = resolve(records, RecordDomain.IDENTITY, policy, ResourceSensitivity.HIGH)

    assert result.resolutions[0].conflict is True
    assert result.resolutions[0].winning_record is None
    assert result.resolutions[0].decision is AccessDecision.REQUEST_VERIFICATION
    assert AccessReasonCode.RECORD_CONFLICT in result.resolutions[0].reason_codes


def test_equal_authority_conflict_can_be_configured_to_deny():
    policy = resolver_policy(identity_sources=(("sis", 0), ("registrar", 0)))
    result = resolve(
        (identity(), identity(record_id="record-2", source_id="registrar", status=RecordStatus.BLOCKED)),
        RecordDomain.IDENTITY,
        policy,
    )
    assert result.resolutions[0].decision is AccessDecision.DENY


def test_expired_authorization_record_is_rejected():
    expired = permission(valid_until=NOW)
    resolution = resolve((expired,), RecordDomain.PERMISSION).resolutions[0]

    assert resolution.decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_EXPIRED in resolution.reason_codes


def test_stale_authorization_record_is_rejected_for_sensitive_resource():
    stale = identity(
        issued_at=NOW - timedelta(days=20),
        source_updated_at=NOW - timedelta(days=10),
        observed_at=NOW - timedelta(days=9),
        valid_from=NOW - timedelta(days=30),
    )
    resolution = resolve((stale,), RecordDomain.IDENTITY, sensitivity=ResourceSensitivity.CRITICAL).resolutions[0]

    assert resolution.decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_STALE in resolution.reason_codes
    assert resolution.trace[0].freshness is RecordFreshness.STALE


def test_stale_higher_authority_record_blocks_fresh_lower_authority_grant():
    policy = resolver_policy(identity_sources=(("registrar", 0), ("imported-feed", 5)))
    stale_authority = identity(
        source_id="registrar",
        issued_at=NOW - timedelta(days=20),
        source_updated_at=NOW - timedelta(days=10),
        observed_at=NOW - timedelta(days=9),
        valid_from=NOW - timedelta(days=30),
    )
    lower_grant = identity(record_id="record-2", source_id="imported-feed", version=2)
    result = resolve((lower_grant, stale_authority), RecordDomain.IDENTITY, policy, ResourceSensitivity.CRITICAL)

    assert result.resolutions[0].decision is AccessDecision.DENY
    assert result.resolutions[0].winning_record is None
    assert AccessReasonCode.RECORD_STALE in result.resolutions[0].reason_codes


def test_missing_authoritative_source_is_an_explicit_deny():
    batch = CampusRecordConflictResolver().resolve(
        (),
        domain=RecordDomain.PERMISSION,
        sensitivity=ResourceSensitivity.HIGH,
        policy=resolver_policy(),
        evaluated_at=NOW,
        expected_scope=("user-1", "LAB_101", "ENTER"),
    )
    assert batch.resolutions[0].decision is AccessDecision.DENY
    assert AccessReasonCode.AUTHORITATIVE_SOURCE_MISSING in batch.resolutions[0].reason_codes


def test_unknown_or_cross_domain_source_cannot_grant_access():
    policy = resolver_policy()
    unauthorized = permission(source_id="sis")  # SIS is configured only for IDENTITY.
    result = resolve((unauthorized,), RecordDomain.PERMISSION, policy)

    assert result.resolutions[0].decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_SOURCE_UNAUTHORIZED in result.resolutions[0].reason_codes

    unknown = resolve((permission(source_id="unknown-system"),), RecordDomain.PERMISSION, policy)
    assert AccessReasonCode.RECORD_SOURCE_UNKNOWN in unknown.resolutions[0].reason_codes


def test_caller_cannot_claim_source_authority_or_rank():
    with pytest.raises(ValidationError):
        IdentityStatusRecord(**campus_record(source_authority=100))
    with pytest.raises(ValidationError):
        SourceAuthorityRule(source_id="sis", priority=0, authority_rank=100)


def test_future_dated_record_is_rejected():
    future = identity(
        source_updated_at=NOW + timedelta(minutes=1),
        observed_at=NOW + timedelta(minutes=2),
        issued_at=NOW + timedelta(minutes=1),
    )
    resolution = resolve((future,), RecordDomain.IDENTITY).resolutions[0]
    assert resolution.decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_FUTURE_DATED in resolution.reason_codes


def test_duplicate_records_resolve_deterministically_independent_of_arrival_order():
    one = identity(record_id="record-a")
    two = identity(record_id="record-b")
    forward = resolve((one, two), RecordDomain.IDENTITY).resolutions[0]
    reverse = resolve((two, one), RecordDomain.IDENTITY).resolutions[0]

    assert forward.winning_record.record_id == "record-a"
    assert reverse.winning_record.record_id == "record-a"
    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")


def test_malformed_record_version_is_rejected_at_schema_boundary():
    with pytest.raises(ValidationError):
        identity(version=0)


def test_different_record_domains_are_not_compared_as_conflicting_records():
    resolver = CampusRecordConflictResolver()
    with pytest.raises(ValueError, match="does not match"):
        resolver.resolve(
            (identity(),),
            domain=RecordDomain.DISCIPLINARY,
            sensitivity=ResourceSensitivity.LOW,
            policy=resolver_policy(),
            evaluated_at=NOW,
        )


def test_expired_temporary_pass_does_not_resolve_to_allow():
    pass_record = TemporaryLabPassRecord(
        **campus_record(
            source_id="lab-admin",
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
            valid_until=NOW,
        )
    )
    result = resolve((pass_record,), RecordDomain.TEMPORARY_PASS).resolutions[0]
    assert result.decision is AccessDecision.DENY
    assert AccessReasonCode.RECORD_EXPIRED in result.reason_codes


def test_conflict_resolution_decision_is_applied_by_policy_evaluator():
    request = AccessRequest(
        request_id="req-1",
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        resource={"resource_id": "LAB_101"},
        action=AccessAction(action_id="ENTER"),
        requested_at=NOW,
    )
    context = EvaluationContext(
        request_id="req-1",
        evaluated_at=NOW,
        policy_version="policy-1",
        resource_sensitivity=ResourceSensitivity.HIGH,
    )
    auth = AuthorizationEvaluationResult(
        request_id="req-1",
        user_id="user-1",
        resource_id="LAB_101",
        permitted=True,
        reason_codes=(AccessReasonCode.ACCESS_POLICY_SATISFIED,),
        explanation="authorized",
    )
    resolution = resolve(
        (
            identity(source_id="sis"),
            identity(record_id="record-2", source_id="registrar", status=RecordStatus.BLOCKED),
        ),
        RecordDomain.IDENTITY,
        resolver_policy(identity_sources=(("sis", 0), ("registrar", 0)), conflict=AccessDecision.REQUEST_VERIFICATION),
        ResourceSensitivity.HIGH,
    )
    evidence = _sufficient_evidence()
    decision = PolicyEvaluator().evaluate(
        request,
        evidence,
        auth,
        context,
        record_resolutions=(resolution,),
    )

    assert decision.decision is AccessDecision.REQUEST_VERIFICATION
    assert decision.access_granted is False
    assert AccessReasonCode.RECORD_CONFLICT in decision.reason_codes


def test_active_identity_and_suspension_resolution_combine_to_deny():
    request = AccessRequest(
        request_id="req-1",
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        resource={"resource_id": "LAB_101"},
        action=AccessAction(action_id="ENTER"),
        requested_at=NOW,
    )
    context = EvaluationContext(
        request_id="req-1",
        evaluated_at=NOW,
        policy_version="policy-1",
        resource_sensitivity=ResourceSensitivity.LOW,
    )
    auth = AuthorizationEvaluationResult(
        request_id="req-1",
        user_id="user-1",
        resource_id="LAB_101",
        permitted=True,
        reason_codes=(AccessReasonCode.ACCESS_POLICY_SATISFIED,),
        explanation="authorization fixture",
    )
    identity_result = resolve((identity(),), RecordDomain.IDENTITY)
    suspension_record = DisciplinarySuspensionRecord(
        **campus_record(source_id="conduct", status=RecordStatus.SUSPENDED, reason_code="hold")
    )
    discipline_result = resolve((suspension_record,), RecordDomain.DISCIPLINARY)

    decision = PolicyEvaluator().evaluate(
        request,
        _sufficient_evidence(),
        auth,
        context,
        record_resolutions=(identity_result, discipline_result),
    )

    assert decision.decision is AccessDecision.DENY
    assert decision.access_granted is False
    assert AccessReasonCode.RECORD_STATUS_DENIED in decision.reason_codes


def _sufficient_evidence():
    from backend.modules.zero_trust.evidence_validator import EvidenceValidationResult, EvidenceValidationReasonCode, TrustedEvidence
    from backend.modules.zero_trust.enums import EvidenceOutcome, VerificationModule
    from backend.modules.zero_trust.schemas import EvidenceProvenance, VerificationEvidence

    evidence = VerificationEvidence(
        module=VerificationModule.FACE_RECOGNITION,
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        outcome=EvidenceOutcome.SUCCESS,
        issued_at=NOW,
        issuer_id="face-service",
        evidence_id="evidence-1",
    )
    trusted = TrustedEvidence(
        evidence=evidence,
        provenance=EvidenceProvenance(
            evidence_id="evidence-1",
            issuer_id="face-service",
            provider_id="trusted-face-provider",
            validated_at=NOW,
            validated_outcome=EvidenceOutcome.SUCCESS,
        ),
        module_result="MATCH",
    )
    return EvidenceValidationResult(
        accepted_evidence=(trusted,),
        rejected_evidence=(),
        missing_required_modules=(),
        failed_required_modules=(),
        pending_required_modules=(),
        conflicting_modules=(),
        stale_evidence=(),
        expired_evidence=(),
        unknown_issuers=(),
        identity_correlation_failures=(),
        attempt_correlation_failures=(),
        confirmed_spoof_indicators=(),
        reason_codes=(EvidenceValidationReasonCode.EVIDENCE_ACCEPTED,),
        evidence_sufficient=True,
        additional_verification_can_resolve=False,
    )


def test_confirmed_revocation_overrides_successful_biometrics_in_policy_evaluation():
    request = AccessRequest(
        request_id="req-1",
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        resource={"resource_id": "LAB_101"},
        action=AccessAction(action_id="ENTER"),
        requested_at=NOW,
    )
    context = EvaluationContext(
        request_id="req-1",
        evaluated_at=NOW,
        policy_version="policy-1",
        resource_sensitivity=ResourceSensitivity.LOW,
    )
    auth = AuthorizationEvaluationResult(
        request_id="req-1",
        user_id="user-1",
        resource_id="LAB_101",
        permitted=True,
        reason_codes=(AccessReasonCode.ACCESS_POLICY_SATISFIED,),
        explanation="authorized",
    )
    revocation = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(
            RevocationStatusRecord(
                **campus_record(
                    source_id="revocation",
                    revocation_state=RevocationState.REVOKED,
                    resource_id="LAB_101",
                )
            ),
        ),
        sensitivity=ResourceSensitivity.LOW,
        evaluated_at=NOW,
        policy=RevocationPolicy(),
    )
    result = PolicyEvaluator().evaluate(request, _sufficient_evidence(), auth, context, revocation=revocation)

    assert result.decision is AccessDecision.DENY
    assert result.access_granted is False
    assert AccessReasonCode.IDENTITY_REVOKED in result.reason_codes


def test_stale_revocation_record_blocks_sensitive_access():
    record = RevocationStatusRecord(
        **campus_record(
            source_id="revocation",
            issued_at=NOW - timedelta(days=10),
            source_updated_at=NOW - timedelta(days=9),
            observed_at=NOW - timedelta(days=8),
            valid_from=NOW - timedelta(days=20),
            revocation_state=RevocationState.CLEAR,
            resource_id="LAB_101",
        )
    )
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(record,),
        sensitivity=ResourceSensitivity.CRITICAL,
        evaluated_at=NOW,
        policy=RevocationPolicy(max_age_by_sensitivity={ResourceSensitivity.CRITICAL: timedelta(minutes=5)}),
    )
    assert result.state is RevocationFindingState.STALE_REVOCATION_INFORMATION
    assert result.blocking is True
    assert AccessReasonCode.REVOCATION_STALE in result.reason_codes


def test_missing_revocation_information_is_distinct_from_confirmed_clear():
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(),
        sensitivity=ResourceSensitivity.HIGH,
        evaluated_at=NOW,
        policy=RevocationPolicy(max_age_by_sensitivity={ResourceSensitivity.HIGH: timedelta(minutes=5)}),
    )
    assert result.state is RevocationFindingState.MISSING_REVOCATION_INFORMATION
    assert result.blocking is True
    assert AccessReasonCode.REVOCATION_UNAVAILABLE in result.reason_codes


def test_unavailable_authoritative_revocation_source_is_missing_information():
    policy = RevocationPolicy(
        max_age_by_sensitivity={ResourceSensitivity.HIGH: timedelta(minutes=5)},
        authoritative_sources=("revocation",),
    )
    check = RevocationSourceCheck(source_id="revocation", checked_at=NOW, available=False)
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(),
        sensitivity=ResourceSensitivity.HIGH,
        evaluated_at=NOW,
        policy=policy,
        source_checks=(check,),
    )
    assert result.state is RevocationFindingState.MISSING_REVOCATION_INFORMATION
    assert result.blocking is True


def test_fresh_authoritative_source_check_with_no_revocation_is_distinct_clear_state():
    policy = RevocationPolicy(
        max_age_by_sensitivity={ResourceSensitivity.CRITICAL: timedelta(minutes=5)},
        authoritative_sources=("revocation",),
    )
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(),
        sensitivity=ResourceSensitivity.CRITICAL,
        evaluated_at=NOW,
        policy=policy,
        source_checks=(RevocationSourceCheck(source_id="revocation", checked_at=NOW, available=True),),
    )
    assert result.state is RevocationFindingState.FRESH_AUTHORITATIVE_SOURCE_WITH_NO_REVOCATION
    assert result.blocking is False


def test_stale_authoritative_source_check_is_not_treated_as_clear():
    policy = RevocationPolicy(
        max_age_by_sensitivity={ResourceSensitivity.CRITICAL: timedelta(minutes=5)},
        authoritative_sources=("revocation",),
    )
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(),
        sensitivity=ResourceSensitivity.CRITICAL,
        evaluated_at=NOW,
        policy=policy,
        source_checks=(RevocationSourceCheck(source_id="revocation", checked_at=NOW - timedelta(hours=1), available=True),),
    )
    assert result.state is RevocationFindingState.STALE_REVOCATION_INFORMATION
    assert result.blocking is True


def test_resource_revocation_does_not_apply_to_unrelated_resource():
    revoked = RevocationStatusRecord(
        **campus_record(source_id="revocation", revocation_state=RevocationState.REVOKED, resource_id="LAB_101")
    )
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LIBRARY",
        records=(revoked,),
        sensitivity=ResourceSensitivity.LOW,
        evaluated_at=NOW,
        policy=RevocationPolicy(),
    )
    assert result.state is RevocationFindingState.MISSING_REVOCATION_INFORMATION
    assert result.blocking is False


def test_revoked_temporary_pass_is_detected_with_its_exact_resource_scope():
    revoked_pass = TemporaryLabPassRecord(
        **campus_record(
            source_id="lab-admin",
            status=RecordStatus.REVOKED,
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
        )
    )
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(revoked_pass,),
        sensitivity=ResourceSensitivity.LOW,
        evaluated_at=NOW,
        policy=RevocationPolicy(),
    )
    assert result.state is RevocationFindingState.CONFIRMED_REVOCATION
    assert result.blocking is True


def test_permission_revocation_for_another_resource_does_not_apply():
    revoked_permission = permission(status=RecordStatus.REVOKED, resource_ids=("SERVER_ROOM",))
    result = RevocationChecker().evaluate(
        subject_id="user-1",
        resource_id="LAB_101",
        records=(revoked_permission,),
        sensitivity=ResourceSensitivity.LOW,
        evaluated_at=NOW,
        policy=RevocationPolicy(),
    )
    assert result.state is RevocationFindingState.MISSING_REVOCATION_INFORMATION
    assert result.blocking is False

