import json

import pytest
from pydantic import ValidationError

from backend.modules.zero_trust.audit import build_audit_event, explain_reason_codes
from backend.modules.zero_trust.enums import AccessReasonCode
from backend.tests.zero_trust.test_engine import build_engine, make_request


def test_audit_builder_captures_identifiers_decision_and_safe_summaries():
    request = make_request()
    result = build_engine().evaluate(request)

    event = build_audit_event(request, result)

    assert event.request_id == request.request_id
    assert event.user_id == request.user_id
    assert event.resource_id == request.resource.resource_id
    assert event.authentication_attempt_id == request.authentication_attempt_id
    assert event.decision == result.decision
    assert event.reason_codes == result.reason_codes
    assert event.policy_version == result.policy_version
    assert event.evaluated_at == result.evaluated_at
    assert event.authorization_summary is not None
    assert event.conflict_resolution_summary is not None
    assert event.revocation_summary is not None


def test_audit_event_excludes_biometrics_secrets_and_raw_provenance():
    request = make_request()
    event = build_audit_event(request, build_engine().evaluate(request))
    payload = json.dumps(event.model_dump(mode="json")).lower()

    assert event.evidence_summary.provenance == ()
    assert event.record_provenance_summary == ()
    for forbidden in ("face_image", "fingerprint_template", "credential", "token", "secret"):
        assert forbidden not in payload
    with pytest.raises(ValidationError):
        type(event).model_validate({**event.model_dump(), "raw_biometric": "must-not-be-stored"})


def test_reason_explanation_is_deterministic_and_does_not_change_decision():
    request = make_request()
    result = build_engine().evaluate(request)
    original_decision = result.decision
    codes = (AccessReasonCode.PERMISSION_NOT_FOUND, AccessReasonCode.RECORD_CONFLICT)

    first = explain_reason_codes(codes)
    second = explain_reason_codes(reversed(codes))

    assert first == second
    assert "No permission exists" in first
    assert "records conflict" in first
    assert result.decision is original_decision

