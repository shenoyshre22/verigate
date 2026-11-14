import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from backend.modules.zero_trust.enums import (
    AccessDecision,
    AccessReasonCode,
    EvidenceOutcome,
    PermissionEffect,
    RecordStatus,
    ResourceSensitivity,
    RevocationState,
    VerificationModule,
)
from backend.modules.zero_trust.schemas import (
    AccessAction,
    AccessDecisionResponse,
    AccessRequest,
    DisciplinarySuspensionRecord,
    ExaminationEligibilityRecord,
    ExaminationWindow,
    EvaluationContext,
    EvidenceProvenance,
    EvidenceSummary,
    IdentityStatusRecord,
    LabSafetyClearanceRecord,
    RecordProvenanceSummary,
    RequestedResource,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
    VerificationEvidence,
    ZeroTrustAuditEvent,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def valid_access_request(**overrides) -> dict:
    values = {
        "request_id": "req-123",
        "user_id": "user-456",
        "authentication_attempt_id": "attempt-789",
        "resource": {"resource_id": "lab-2"},
        "action": {"action_id": "ENTER"},
        "requested_at": NOW,
    }
    values.update(overrides)
    return values


def valid_record(**overrides) -> dict:
    values = {
        "record_id": "record-001",
        "subject_id": "user-456",
        "source_id": "sis-main",
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


def test_access_request_and_nested_models_construct_and_round_trip() -> None:
    request = AccessRequest.model_validate(valid_access_request())

    restored = AccessRequest.model_validate_json(request.model_dump_json())
    assert restored == request
    assert restored.resource == RequestedResource(resource_id="lab-2")
    assert restored.action == AccessAction(action_id="ENTER")


def test_invalid_enum_values_are_rejected() -> None:
    with pytest.raises(ValidationError):
        VerificationEvidence(
            module="FACE_MATCHING",
            user_id="user-456",
            authentication_attempt_id="attempt-789",
            outcome="SUCCESS",
            issued_at=NOW,
            issuer_id="face-service",
            evidence_id="ev-001",
        )

    with pytest.raises(ValidationError):
        AccessDecisionResponse(
            request_id="req-123",
            user_id="user-456",
            resource_id="lab-2",
            decision="GRANT",
            access_granted=True,
            reason_codes=[AccessReasonCode.ACCESS_POLICY_SATISFIED],
            explanation="Allowed.",
            policy_version="v1",
            evaluated_at=NOW,
            decision_latency_ms=1.0,
        )


def test_missing_or_malformed_identifiers_are_rejected() -> None:
    missing = valid_access_request()
    del missing["user_id"]
    with pytest.raises(ValidationError):
        AccessRequest.model_validate(missing)

    with pytest.raises(ValidationError):
        AccessRequest.model_validate(valid_access_request(request_id="  "))


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AccessRequest.model_validate(valid_access_request(requested_at=datetime(2026, 11, 14, 12)))

    with pytest.raises(ValidationError):
        IdentityStatusRecord.model_validate(valid_record(observed_at=datetime(2026, 11, 14, 12)))


def test_invalid_validity_intervals_are_rejected() -> None:
    with pytest.raises(ValidationError, match="valid_until"):
        IdentityStatusRecord.model_validate(
            valid_record(valid_until=NOW - timedelta(days=2))
        )

    with pytest.raises(ValidationError, match="ends_at"):
        ExaminationWindow(starts_at=NOW, ends_at=NOW)

    with pytest.raises(ValidationError, match="ordered and non-overlapping"):
        ExaminationEligibilityRecord.model_validate(
            valid_record(
                exam_id="exam-1",
                eligible=True,
                resource_ids=("exam-hall-1",),
                schedule=(
                    ExaminationWindow(starts_at=NOW, ends_at=NOW + timedelta(hours=2)),
                    ExaminationWindow(
                        starts_at=NOW + timedelta(hours=1),
                        ends_at=NOW + timedelta(hours=3),
                    ),
                ),
            )
        )

    with pytest.raises(ValidationError, match="expires_at"):
        VerificationEvidence(
            module=VerificationModule.FACE_RECOGNITION,
            user_id="user-456",
            authentication_attempt_id="attempt-789",
            outcome=EvidenceOutcome.SUCCESS,
            issued_at=NOW,
            expires_at=NOW,
            issuer_id="face-service",
            evidence_id="ev-001",
        )


@pytest.mark.parametrize("version", [0, -1, True, 1.5])
def test_invalid_record_versions_are_rejected(version) -> None:
    with pytest.raises(ValidationError):
        IdentityStatusRecord.model_validate(valid_record(version=version))


def test_source_timestamps_cannot_postdate_observation() -> None:
    with pytest.raises(ValidationError, match="observed_at must not be earlier"):
        IdentityStatusRecord.model_validate(
            valid_record(source_updated_at=NOW, observed_at=NOW - timedelta(minutes=1))
        )


@pytest.mark.parametrize(
    ("decision", "access_granted"),
    [
        (AccessDecision.ALLOW, False),
        (AccessDecision.DENY, True),
        (AccessDecision.REQUEST_VERIFICATION, True),
    ],
)
def test_decision_and_access_granted_must_be_consistent(decision, access_granted) -> None:
    with pytest.raises(ValidationError, match="access_granted"):
        AccessDecisionResponse(
            request_id="req-123",
            user_id="user-456",
            resource_id="lab-2",
            decision=decision,
            access_granted=access_granted,
            reason_codes=(AccessReasonCode.ACCESS_POLICY_SATISFIED,),
            explanation="Decision explanation.",
            policy_version="policy-v1",
            evaluated_at=NOW,
            decision_latency_ms=3.25,
        )


def test_decision_response_serialization_and_deserialization() -> None:
    response = AccessDecisionResponse(
        request_id="req-123",
        user_id="user-456",
        resource_id="lab-2",
        decision=AccessDecision.ALLOW,
        access_granted=True,
        reason_codes=(AccessReasonCode.ACCESS_POLICY_SATISFIED,),
        explanation="Evidence and authorization requirements were satisfied.",
        policy_version="policy-v1",
        evaluated_at=NOW,
        decision_latency_ms=3.25,
        audit_reference="audit-42",
    )

    restored = AccessDecisionResponse.model_validate_json(response.model_dump_json())
    assert restored == response
    assert json.loads(response.model_dump_json())["decision"] == "ALLOW"


def test_confidence_fields_are_optional_and_range_validated() -> None:
    base = {
        "module": VerificationModule.FINGERPRINT,
        "user_id": "user-456",
        "authentication_attempt_id": "attempt-789",
        "outcome": EvidenceOutcome.SUCCESS,
        "issued_at": NOW,
        "issuer_id": "fingerprint-service",
        "evidence_id": "ev-fp-1",
    }
    assert VerificationEvidence(**base).confidence is None
    assert VerificationEvidence(**base, confidence=87.5, similarity=99).confidence == 87.5

    with pytest.raises(ValidationError):
        VerificationEvidence(**base, confidence=101)


def test_caller_cannot_add_authority_or_trust_fields() -> None:
    with pytest.raises(ValidationError, match="source_authority"):
        AccessRequest.model_validate(valid_access_request(source_authority="highest"))

    with pytest.raises(ValidationError, match="issuer_authority"):
        VerificationEvidence(
            module=VerificationModule.RFID,
            user_id="user-456",
            authentication_attempt_id="attempt-789",
            outcome=EvidenceOutcome.SUCCESS,
            issued_at=NOW,
            issuer_id="rfid-reader",
            evidence_id="ev-rfid-1",
            issuer_authority="trusted",
        )

    with pytest.raises(ValidationError, match="authority_rank"):
        IdentityStatusRecord.model_validate(valid_record(authority_rank=100))


def test_campus_record_schemas_cover_requested_record_types() -> None:
    identity = IdentityStatusRecord.model_validate(valid_record(status=RecordStatus.ACTIVE))
    permission = ResourcePermissionRecord.model_validate(
        valid_record(effect=PermissionEffect.GRANT, resource_ids=("lab-2",), action_ids=("ENTER",))
    )
    suspension = DisciplinarySuspensionRecord.model_validate(
        valid_record(status=RecordStatus.SUSPENDED, reason_code="disciplinary-hold")
    )
    examination = ExaminationEligibilityRecord.model_validate(
        valid_record(
            exam_id="exam-1",
            eligible=True,
            resource_ids=("exam-hall-1",),
            schedule=(ExaminationWindow(starts_at=NOW, ends_at=NOW + timedelta(hours=2)),),
        )
    )
    temporary_pass = TemporaryLabPassRecord.model_validate(
        valid_record(resource_id="lab-2", action_ids=("ENTER",))
    )
    safety_clearance = LabSafetyClearanceRecord.model_validate(
        valid_record(resource_id="lab-2", cleared=True, requirement_ids=("training-a",))
    )
    revocation = RevocationStatusRecord.model_validate(
        valid_record(revocation_state=RevocationState.CLEAR, resource_id="lab-2")
    )

    assert identity.subject_id == permission.subject_id == suspension.subject_id
    assert examination.schedule[0].starts_at == NOW
    assert temporary_pass.valid_until == NOW + timedelta(days=1)
    assert safety_clearance.cleared is True
    assert revocation.revocation_state is RevocationState.CLEAR


def test_evaluation_context_requires_server_policy_and_aware_time() -> None:
    context = EvaluationContext(
        request_id="req-123",
        evaluated_at=NOW,
        policy_version="policy-v4",
        resource_sensitivity=ResourceSensitivity.CRITICAL,
    )
    assert context.resource_sensitivity is ResourceSensitivity.CRITICAL


def test_audit_event_is_structured_and_contains_only_summaries() -> None:
    evidence_summary = EvidenceSummary(
        evidence_count=1,
        outcome_counts={EvidenceOutcome.SUCCESS: 1},
        validated_modules=(VerificationModule.FACE_RECOGNITION,),
        provenance=(
            EvidenceProvenance(
                evidence_id="ev-face-1",
                issuer_id="face-service",
                provider_id="trusted-face-adapter",
                validated_at=NOW,
                validated_outcome=EvidenceOutcome.SUCCESS,
            ),
        ),
    )
    event = ZeroTrustAuditEvent(
        request_id="req-123",
        user_id="user-456",
        resource_id="lab-2",
        decision=AccessDecision.DENY,
        reason_codes=(AccessReasonCode.CONFIRMED_SPOOF,),
        policy_version="policy-v1",
        evaluated_at=NOW,
        evidence_summary=evidence_summary,
        record_provenance_summary=(
            RecordProvenanceSummary(
                record_id="record-1",
                source_id="sis-main",
                version=2,
                observed_at=NOW,
                status=RecordStatus.ACTIVE,
            ),
        ),
    )

    assert ZeroTrustAuditEvent.model_validate_json(event.model_dump_json()) == event
    with pytest.raises(ValidationError, match="raw_biometric"):
        ZeroTrustAuditEvent.model_validate({**event.model_dump(), "raw_biometric": "forbidden"})


def test_evidence_summary_counts_must_be_consistent() -> None:
    with pytest.raises(ValidationError, match="sum to evidence_count"):
        EvidenceSummary(evidence_count=2, outcome_counts={EvidenceOutcome.SUCCESS: 1})
