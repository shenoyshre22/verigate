from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from backend.modules.zero_trust.authorization import (
    AuthorizationPolicy,
    AuthorizationSnapshot,
    CampusAuthorizationEvaluator,
    RoleRequirement,
)
from backend.modules.zero_trust.enums import (
    AccessDecision,
    AccessReasonCode,
    CampusRole,
    EvidenceOutcome,
    PermissionEffect,
    RecordStatus,
    ResourceSensitivity,
    RevocationState,
    VerificationModule,
)
from backend.modules.zero_trust.evidence_validator import (
    EvidenceIssue,
    EvidenceValidationReasonCode,
    EvidenceValidationResult,
    TrustedEvidence,
)
from backend.modules.zero_trust.policy_evaluator import PolicyEvaluator
from backend.modules.zero_trust.schemas import (
    AccessAction,
    AccessRequest,
    CampusRoleRecord,
    DisciplinarySuspensionRecord,
    EvaluationContext,
    EvidenceProvenance,
    ExaminationEligibilityRecord,
    ExaminationWindow,
    IdentityStatusRecord,
    LabSafetyClearanceRecord,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
    VerificationEvidence,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def record_fields(**overrides):
    fields = {
        "record_id": "record-1",
        "subject_id": "user-1",
        "source_id": "campus-source",
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


def identity(**overrides):
    return IdentityStatusRecord(**record_fields(**overrides))


def permission(resource_id="LAB_101", action_id="ENTER", **overrides):
    values = record_fields(
        effect=PermissionEffect.GRANT,
        resource_ids=(resource_id,),
        action_ids=(action_id,),
        **overrides,
    )
    return ResourcePermissionRecord(**values)


def request(resource_id="LAB_101", action_id="ENTER", **action_values):
    return AccessRequest(
        request_id="request-1",
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        resource={"resource_id": resource_id},
        action=AccessAction(action_id=action_id, **action_values),
        requested_at=NOW - timedelta(seconds=1),
    )


def context(sensitivity=ResourceSensitivity.LOW):
    return EvaluationContext(
        request_id="request-1",
        evaluated_at=NOW,
        policy_version="policy-test-v1",
        resource_sensitivity=sensitivity,
    )


def evaluate(
    *,
    access_request=None,
    identities=None,
    role_assignments=(),
    permissions=(),
    suspensions=(),
    examinations=(),
    temporary_lab_passes=(),
    safety_clearances=(),
    revocations=(),
    policy=None,
    evaluation_context=None,
):
    return CampusAuthorizationEvaluator().evaluate(
        access_request or request(),
        AuthorizationSnapshot(
            identities=tuple(identities if identities is not None else (identity(),)),
            role_assignments=tuple(role_assignments),
            permissions=tuple(permissions),
            suspensions=tuple(suspensions),
            examinations=tuple(examinations),
            temporary_lab_passes=tuple(temporary_lab_passes),
            safety_clearances=tuple(safety_clearances),
            revocations=tuple(revocations),
        ),
        policy or AuthorizationPolicy(),
        evaluation_context or context(),
    )


def evidence_success():
    evidence = VerificationEvidence(
        module=VerificationModule.FACE_RECOGNITION,
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        outcome=EvidenceOutcome.SUCCESS,
        issued_at=NOW - timedelta(minutes=1),
        issuer_id="face-service",
        evidence_id="evidence-1",
    )
    trusted = TrustedEvidence(
        evidence=evidence,
        provenance=EvidenceProvenance(
            evidence_id=evidence.evidence_id,
            issuer_id=evidence.issuer_id,
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


def test_active_identity_with_exact_resource_permission_is_authorized():
    result = evaluate(permissions=(permission(),))

    assert result.permitted is True
    assert result.reason_codes == (AccessReasonCode.ACCESS_POLICY_SATISFIED,)


def test_inactive_identity_is_denied_even_with_permission():
    result = evaluate(
        identities=(identity(status=RecordStatus.INACTIVE),),
        permissions=(permission(),),
    )

    assert result.permitted is False
    assert AccessReasonCode.IDENTITY_INACTIVE in result.reason_codes


def test_blocked_identity_is_denied_even_with_permission():
    result = evaluate(
        identities=(identity(status=RecordStatus.BLOCKED),),
        permissions=(permission(),),
    )

    assert result.permitted is False
    assert AccessReasonCode.IDENTITY_BLOCKED in result.reason_codes


def test_student_cannot_use_permission_for_another_room():
    student = CampusRoleRecord(**record_fields(roles=(CampusRole.STUDENT,)))
    result = evaluate(
        role_assignments=(student,),
        permissions=(permission(resource_id="LIBRARY"),),
    )

    assert result.permitted is False
    assert AccessReasonCode.PERMISSION_NOT_FOUND in result.reason_codes


def test_faculty_role_and_explicit_room_permission_authorize():
    faculty = CampusRoleRecord(**record_fields(roles=(CampusRole.FACULTY,)))
    policy = AuthorizationPolicy(
        role_requirements=(
            RoleRequirement(resource_id="LAB_101", action_id="ENTER", allowed_roles=(CampusRole.FACULTY,)),
        )
    )
    result = evaluate(role_assignments=(faculty,), permissions=(permission(),), policy=policy)

    assert result.permitted is True


def test_role_alone_never_grants_resource_access():
    faculty = CampusRoleRecord(**record_fields(roles=(CampusRole.FACULTY,)))
    policy = AuthorizationPolicy(
        role_requirements=(
            RoleRequirement(resource_id="LAB_101", action_id="ENTER", allowed_roles=(CampusRole.FACULTY,)),
        )
    )
    result = evaluate(role_assignments=(faculty,), policy=policy)

    assert result.permitted is False
    assert AccessReasonCode.PERMISSION_NOT_FOUND in result.reason_codes


def test_active_suspension_denies_access_despite_valid_biometrics():
    suspension = DisciplinarySuspensionRecord(
        **record_fields(status=RecordStatus.SUSPENDED, reason_code="conduct-review")
    )
    authorization = evaluate(permissions=(permission(),), suspensions=(suspension,))
    decision = PolicyEvaluator().evaluate(
        request(), evidence_success(), authorization, context()
    )

    assert authorization.permitted is False
    assert decision.decision is AccessDecision.DENY
    assert decision.access_granted is False
    assert AccessReasonCode.IDENTITY_SUSPENDED in decision.reason_codes


def test_resource_scoped_suspension_does_not_block_unrelated_resource():
    suspension = DisciplinarySuspensionRecord(
        **record_fields(
            status=RecordStatus.SUSPENDED,
            reason_code="lab-hold",
            resource_ids=("SERVER_ROOM",),
        )
    )
    result = evaluate(permissions=(permission(),), suspensions=(suspension,))

    assert result.permitted is True


def test_eligible_examination_with_assigned_location_and_valid_schedule_is_authorized():
    exam_request = request(
        resource_id="EXAM_HALL",
        action_id="TAKE_EXAM",
        exam_id="EXAM_2026_MATH",
    )
    exam = ExaminationEligibilityRecord(
        **record_fields(
            exam_id="EXAM_2026_MATH",
            eligible=True,
            resource_ids=("EXAM_HALL",),
            schedule=(ExaminationWindow(starts_at=NOW - timedelta(minutes=30), ends_at=NOW + timedelta(hours=2)),),
        )
    )
    result = evaluate(access_request=exam_request, examinations=(exam,))

    assert result.permitted is True


def test_examination_outside_schedule_is_denied():
    exam_request = request(resource_id="EXAM_HALL", action_id="TAKE_EXAM", exam_id="EXAM_1")
    exam = ExaminationEligibilityRecord(
        **record_fields(
            exam_id="EXAM_1",
            eligible=True,
            resource_ids=("EXAM_HALL",),
            schedule=(ExaminationWindow(starts_at=NOW - timedelta(hours=3), ends_at=NOW - timedelta(hours=2)),),
        )
    )
    result = evaluate(access_request=exam_request, examinations=(exam,))

    assert result.permitted is False
    assert AccessReasonCode.OUTSIDE_EXAM_SCHEDULE in result.reason_codes


def test_ineligible_student_is_denied_examination_access():
    exam_request = request(resource_id="EXAM_HALL", action_id="TAKE_EXAM", exam_id="EXAM_1")
    exam = ExaminationEligibilityRecord(
        **record_fields(
            exam_id="EXAM_1",
            eligible=False,
            resource_ids=("EXAM_HALL",),
            schedule=(ExaminationWindow(starts_at=NOW - timedelta(minutes=1), ends_at=NOW + timedelta(hours=1)),),
        )
    )
    result = evaluate(access_request=exam_request, examinations=(exam,))

    assert result.permitted is False
    assert AccessReasonCode.EXAM_NOT_ELIGIBLE in result.reason_codes


def test_examination_at_wrong_assigned_location_is_denied():
    exam_request = request(resource_id="EXAM_HALL", action_id="TAKE_EXAM", exam_id="EXAM_1")
    exam = ExaminationEligibilityRecord(
        **record_fields(
            exam_id="EXAM_1",
            eligible=True,
            resource_ids=("OTHER_HALL",),
            schedule=(ExaminationWindow(starts_at=NOW - timedelta(minutes=1), ends_at=NOW + timedelta(hours=1)),),
        )
    )
    result = evaluate(access_request=exam_request, examinations=(exam,))

    assert result.permitted is False
    assert AccessReasonCode.EXAMINATION_LOCATION_MISMATCH in result.reason_codes


def test_temporary_lab_pass_is_exact_user_resource_action_purpose_and_issuer():
    lab_request = request(action_id="ENTER", purpose_id="MAINTENANCE")
    lab_pass = TemporaryLabPassRecord(
        **record_fields(
            source_id="lab-office",
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
        )
    )
    policy = AuthorizationPolicy(trusted_temporary_pass_sources=("lab-office",))
    result = evaluate(access_request=lab_request, temporary_lab_passes=(lab_pass,), policy=policy)

    assert result.permitted is True


def test_expired_temporary_lab_pass_is_denied():
    lab_request = request(action_id="ENTER", purpose_id="MAINTENANCE")
    lab_pass = TemporaryLabPassRecord(
        **record_fields(
            source_id="lab-office",
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
            valid_until=NOW,
        )
    )
    result = evaluate(
        access_request=lab_request,
        temporary_lab_passes=(lab_pass,),
        policy=AuthorizationPolicy(trusted_temporary_pass_sources=("lab-office",)),
    )

    assert result.permitted is False
    assert AccessReasonCode.TEMPORARY_PASS_EXPIRED in result.reason_codes


def test_revoked_temporary_lab_pass_is_denied():
    lab_pass = TemporaryLabPassRecord(
        **record_fields(
            source_id="lab-office",
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
            status=RecordStatus.REVOKED,
        )
    )
    result = evaluate(
        access_request=request(action_id="ENTER", purpose_id="MAINTENANCE"),
        temporary_lab_passes=(lab_pass,),
        policy=AuthorizationPolicy(trusted_temporary_pass_sources=("lab-office",)),
    )

    assert result.permitted is False
    assert AccessReasonCode.TEMPORARY_PASS_REVOKED in result.reason_codes


def test_temporary_lab_pass_for_wrong_lab_is_denied():
    lab_request = request(action_id="ENTER", purpose_id="MAINTENANCE")
    other_lab_pass = TemporaryLabPassRecord(
        **record_fields(
            source_id="lab-office",
            resource_id="RESEARCH_LAB",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
        )
    )
    result = evaluate(
        access_request=lab_request,
        temporary_lab_passes=(other_lab_pass,),
        policy=AuthorizationPolicy(trusted_temporary_pass_sources=("lab-office",)),
    )

    assert result.permitted is False
    assert AccessReasonCode.TEMPORARY_PASS_INVALID in result.reason_codes


def test_temporary_lab_pass_for_wrong_purpose_is_denied():
    lab_request = request(action_id="ENTER", purpose_id="MAINTENANCE")
    wrong_purpose = TemporaryLabPassRecord(
        **record_fields(
            source_id="lab-office",
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="RESEARCH",
        )
    )
    result = evaluate(
        access_request=lab_request,
        temporary_lab_passes=(wrong_purpose,),
        policy=AuthorizationPolicy(trusted_temporary_pass_sources=("lab-office",)),
    )

    assert result.permitted is False
    assert AccessReasonCode.TEMPORARY_PASS_INVALID in result.reason_codes


def test_untrusted_temporary_pass_issuer_is_not_accepted():
    lab_request = request(action_id="ENTER", purpose_id="MAINTENANCE")
    lab_pass = TemporaryLabPassRecord(
        **record_fields(
            source_id="untrusted-office",
            resource_id="LAB_101",
            action_ids=("ENTER",),
            purpose_id="MAINTENANCE",
        )
    )
    result = evaluate(
        access_request=lab_request,
        temporary_lab_passes=(lab_pass,),
        policy=AuthorizationPolicy(trusted_temporary_pass_sources=("lab-office",)),
    )

    assert result.permitted is False
    assert AccessReasonCode.TEMPORARY_PASS_ISSUER_UNTRUSTED in result.reason_codes


def test_missing_mandatory_safety_clearance_denies_access():
    policy = AuthorizationPolicy(required_safety_by_resource={"LAB_101": ("FIRE_TRAINING",)})
    result = evaluate(permissions=(permission(),), policy=policy)

    assert result.permitted is False
    assert AccessReasonCode.LAB_SAFETY_CLEARANCE_REQUIRED in result.reason_codes


def test_expired_safety_clearance_denies_access():
    clearance = LabSafetyClearanceRecord(
        **record_fields(
            resource_id="LAB_101",
            cleared=True,
            requirement_ids=("FIRE_TRAINING",),
            valid_until=NOW,
        )
    )
    policy = AuthorizationPolicy(required_safety_by_resource={"LAB_101": ("FIRE_TRAINING",)})
    result = evaluate(permissions=(permission(),), safety_clearances=(clearance,), policy=policy)

    assert result.permitted is False
    assert AccessReasonCode.SAFETY_CLEARANCE_EXPIRED in result.reason_codes


def test_incomplete_safety_training_denies_access():
    clearance = LabSafetyClearanceRecord(
        **record_fields(
            resource_id="LAB_101",
            cleared=False,
            requirement_ids=("FIRE_TRAINING",),
        )
    )
    policy = AuthorizationPolicy(required_safety_by_resource={"LAB_101": ("FIRE_TRAINING",)})
    result = evaluate(permissions=(permission(),), safety_clearances=(clearance,), policy=policy)

    assert result.permitted is False
    assert AccessReasonCode.SAFETY_TRAINING_INCOMPLETE in result.reason_codes


def test_expired_permission_is_denied():
    result = evaluate(permissions=(permission(valid_until=NOW),))

    assert result.permitted is False
    assert AccessReasonCode.PERMISSION_EXPIRED in result.reason_codes


def test_permission_for_different_resource_does_not_transfer():
    result = evaluate(permissions=(permission(resource_id="SERVER_ROOM"),))

    assert result.permitted is False
    assert AccessReasonCode.PERMISSION_NOT_FOUND in result.reason_codes


def test_permission_valid_in_future_is_not_active_yet():
    result = evaluate(permissions=(permission(valid_from=NOW + timedelta(minutes=1)),))

    assert result.permitted is False
    assert AccessReasonCode.PERMISSION_NOT_YET_VALID in result.reason_codes


def test_explicitly_revoked_permission_is_denied():
    result = evaluate(permissions=(permission(status=RecordStatus.REVOKED),))

    assert result.permitted is False
    assert AccessReasonCode.PERMISSION_REVOKED in result.reason_codes


def test_sensitive_access_fails_closed_without_fresh_revocation_data():
    result = evaluate(
        permissions=(permission(),),
        evaluation_context=context(ResourceSensitivity.CRITICAL),
        policy=AuthorizationPolicy(
            revocation_max_age_by_sensitivity={
                ResourceSensitivity.CRITICAL: timedelta(minutes=5),
            }
        ),
    )

    assert result.permitted is False
    assert AccessReasonCode.REVOCATION_UNAVAILABLE in result.reason_codes


def test_sensitive_access_allows_fresh_clear_revocation_record():
    revocation = RevocationStatusRecord(
        **record_fields(
            resource_id="LAB_101",
            revocation_state=RevocationState.CLEAR,
            observed_at=NOW - timedelta(seconds=30),
        )
    )
    result = evaluate(
        permissions=(permission(),),
        revocations=(revocation,),
        evaluation_context=context(ResourceSensitivity.CRITICAL),
        policy=AuthorizationPolicy(
            revocation_max_age_by_sensitivity={
                ResourceSensitivity.CRITICAL: timedelta(minutes=5),
            }
        ),
    )

    assert result.permitted is True


def test_revoked_identity_resource_is_denied():
    revocation = RevocationStatusRecord(
        **record_fields(resource_id="LAB_101", revocation_state=RevocationState.REVOKED)
    )
    result = evaluate(permissions=(permission(),), revocations=(revocation,))

    assert result.permitted is False
    assert AccessReasonCode.IDENTITY_REVOKED in result.reason_codes


def test_successful_biometrics_do_not_override_unauthorized_campus_access():
    authorization = evaluate(permissions=())
    decision = PolicyEvaluator().evaluate(request(), evidence_success(), authorization, context())

    assert decision.decision is AccessDecision.DENY
    assert decision.access_granted is False
    assert AccessReasonCode.PERMISSION_NOT_FOUND in decision.reason_codes


def test_incomplete_identity_requests_verification_without_granting_access():
    authorization = evaluate(permissions=(permission(),))
    incomplete = EvidenceValidationResult(
        accepted_evidence=(),
        rejected_evidence=(),
        missing_required_modules=(VerificationModule.FACE_RECOGNITION,),
        failed_required_modules=(),
        pending_required_modules=(),
        conflicting_modules=(),
        stale_evidence=(),
        expired_evidence=(),
        unknown_issuers=(),
        identity_correlation_failures=(),
        attempt_correlation_failures=(),
        confirmed_spoof_indicators=(),
        reason_codes=(EvidenceValidationReasonCode.MISSING_REQUIRED_EVIDENCE,),
        evidence_sufficient=False,
        additional_verification_can_resolve=True,
    )
    decision = PolicyEvaluator().evaluate(request(), incomplete, authorization, context())

    assert decision.decision is AccessDecision.REQUEST_VERIFICATION
    assert decision.access_granted is False
    assert AccessReasonCode.IDENTITY_UNVERIFIED in decision.reason_codes


def test_policy_denies_when_authorization_fails_even_if_evidence_is_complete():
    denied_authorization = evaluate(permissions=())
    decision = PolicyEvaluator().evaluate(request(), evidence_success(), denied_authorization, context())

    assert decision.decision is AccessDecision.DENY
    assert decision.access_granted is False


def test_unrelated_users_clearance_cannot_satisfy_lab_safety_requirement():
    other_user_clearance = LabSafetyClearanceRecord(
        **record_fields(
            subject_id="user-2",
            resource_id="LAB_101",
            cleared=True,
            requirement_ids=("FIRE_TRAINING",),
        )
    )
    result = evaluate(
        permissions=(permission(),),
        safety_clearances=(other_user_clearance,),
        policy=AuthorizationPolicy(required_safety_by_resource={"LAB_101": ("FIRE_TRAINING",)}),
    )

    assert result.permitted is False
    assert AccessReasonCode.LAB_SAFETY_CLEARANCE_REQUIRED in result.reason_codes


def test_naive_evaluation_timestamps_are_rejected_by_existing_context_schema():
    with pytest.raises(ValidationError):
        EvaluationContext(
            request_id="request-1",
            evaluated_at=datetime(2026, 11, 14, 12),
            policy_version="policy-test-v1",
            resource_sensitivity=ResourceSensitivity.LOW,
        )
