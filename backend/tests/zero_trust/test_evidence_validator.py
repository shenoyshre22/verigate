from datetime import datetime, timedelta, timezone

import pytest

from backend.modules.zero_trust.enums import (
    EvidenceOutcome,
    ResourceSensitivity,
    VerificationModule,
)
from backend.modules.zero_trust.evidence_validator import (
    EvidenceFreshnessPolicy,
    EvidenceRequirements,
    EvidenceValidationReasonCode as Reason,
    EvidenceValidator,
    TrustedEvidence,
)
from backend.modules.zero_trust.schemas import (
    AccessAction,
    AccessRequest,
    EvaluationContext,
    EvidenceProvenance,
    RequestedResource,
    VerificationEvidence,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
ISSUERS = {
    "face-issuer": VerificationModule.FACE_RECOGNITION,
    "live-issuer": VerificationModule.FACE_LIVENESS,
    "fingerprint-issuer": VerificationModule.FINGERPRINT,
    "rfid-issuer": VerificationModule.RFID,
}
MODULE_ISSUERS = {module: issuer for issuer, module in ISSUERS.items()}


class FakeTrustedIssuer:
    def __init__(self, issuer_id, module, *, mode="valid"):
        self.issuer_id = issuer_id
        self.module = module
        self.provider_id = "trusted-test-provider"
        self.mode = mode

    def validate_evidence(self, claim):
        if self.mode == "raise":
            raise RuntimeError("synthetic provider failure")
        if self.mode == "invalid":
            return {"trusted": True}
        if self.mode == "invalid_model":
            return TrustedEvidence.model_construct(
                evidence=claim,
                provenance=EvidenceProvenance(
                    evidence_id=claim.evidence_id,
                    issuer_id=claim.issuer_id,
                    provider_id=self.provider_id,
                    validated_at=NOW,
                    validated_outcome=claim.outcome,
                ),
            )
        if self.mode == "unverified":
            return None
        canonical = claim
        module_result = module_result_for(claim.module, claim.outcome)
        if self.mode == "conflicting_claim":
            canonical = claim.model_copy(update={"outcome": EvidenceOutcome.FAILURE})
            module_result = module_result_for(claim.module, EvidenceOutcome.FAILURE)
        return TrustedEvidence(
            evidence=canonical,
            provenance=EvidenceProvenance(
                evidence_id=canonical.evidence_id,
                issuer_id=canonical.issuer_id,
                provider_id=self.provider_id,
                validated_at=NOW,
                validated_outcome=canonical.outcome,
            ),
            module_result=module_result,
        )


class FakeTrustedIssuerProvider:
    def __init__(self, *, mode="valid", issuer_modes=None):
        self.mode = mode
        self.issuer_modes = issuer_modes or {}

    def get_trusted_issuer(self, issuer_id):
        if self.mode == "raise":
            raise RuntimeError("synthetic registry unavailable")
        if self.mode == "invalid":
            return {"issuer_id": issuer_id}
        module = ISSUERS.get(issuer_id)
        if module is None:
            return None
        return FakeTrustedIssuer(
            issuer_id,
            module,
            mode=self.issuer_modes.get(issuer_id, "valid"),
        )


def module_result_for(module, outcome):
    if module is VerificationModule.FACE_RECOGNITION:
        return {
            EvidenceOutcome.SUCCESS: "MATCH",
            EvidenceOutcome.FAILURE: "NO_MATCH",
            EvidenceOutcome.ERROR: "ERROR",
        }[outcome]
    if module is VerificationModule.FACE_LIVENESS:
        return {
            EvidenceOutcome.SUCCESS: "LIVE",
            EvidenceOutcome.FAILURE: "SPOOF",
            EvidenceOutcome.PENDING: "PENDING",
            EvidenceOutcome.EXPIRED: "EXPIRED",
            EvidenceOutcome.INDETERMINATE: "INDETERMINATE",
            EvidenceOutcome.ERROR: "ERROR",
        }[outcome]
    if module is VerificationModule.FINGERPRINT:
        return {
            EvidenceOutcome.SUCCESS: "MATCH",
            EvidenceOutcome.FAILURE: "NO_MATCH",
            EvidenceOutcome.ERROR: "ERROR",
        }[outcome]
    return {
        EvidenceOutcome.SUCCESS: "VALID",
        EvidenceOutcome.FAILURE: "INVALID",
        EvidenceOutcome.ERROR: "ERROR",
    }[outcome]


def make_evidence(
    module=VerificationModule.FACE_RECOGNITION,
    outcome=EvidenceOutcome.SUCCESS,
    *,
    evidence_id="evidence-1",
    user_id="user-1",
    attempt_id="attempt-1",
    issuer_id=None,
    issued_at=None,
    expires_at=None,
):
    return VerificationEvidence(
        module=module,
        user_id=user_id,
        authentication_attempt_id=attempt_id,
        outcome=outcome,
        issued_at=issued_at or NOW - timedelta(minutes=5),
        issuer_id=issuer_id or MODULE_ISSUERS[module],
        evidence_id=evidence_id,
        expires_at=expires_at,
    )


def make_validator(*, provider=None, max_age=timedelta(minutes=30)):
    freshness = EvidenceFreshnessPolicy(
        max_age_by_module={module: max_age for module in VerificationModule},
    )
    return EvidenceValidator(provider or FakeTrustedIssuerProvider(), freshness)


def make_request(**overrides):
    values = {
        "request_id": "request-1",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "resource": RequestedResource(resource_id="lab-1"),
        "action": AccessAction(action_id="ENTER"),
        "requested_at": NOW - timedelta(seconds=1),
    }
    values.update(overrides)
    return AccessRequest(**values)


def make_context(**overrides):
    values = {
        "request_id": "request-1",
        "evaluated_at": NOW,
        "policy_version": "policy-1",
        "resource_sensitivity": ResourceSensitivity.LOW,
    }
    values.update(overrides)
    return EvaluationContext(**values)


def validate(items, *, required=(VerificationModule.FACE_RECOGNITION,), provider=None, request=None):
    return make_validator(provider=provider).validate(
        request or make_request(),
        items,
        EvidenceRequirements(required_modules=required),
        make_context(),
    )


def test_valid_face_recognition_match_is_accepted():
    result = validate([make_evidence()])

    assert result.evidence_sufficient is True
    assert len(result.accepted_evidence) == 1
    assert result.accepted_evidence[0].module_result == "MATCH"


def test_valid_face_liveness_live_is_accepted():
    evidence = make_evidence(
        VerificationModule.FACE_LIVENESS,
        evidence_id="live-1",
    )
    result = validate([evidence], required=(VerificationModule.FACE_LIVENESS,))

    assert result.evidence_sufficient is True
    assert result.accepted_evidence[0].module_result == "LIVE"


def test_confirmed_spoof_is_rejected_and_cannot_be_resolved_in_attempt():
    spoof = make_evidence(
        VerificationModule.FACE_LIVENESS,
        EvidenceOutcome.FAILURE,
        evidence_id="spoof-1",
    )
    result = validate([spoof], required=(VerificationModule.FACE_LIVENESS,))

    assert result.evidence_sufficient is False
    assert len(result.confirmed_spoof_indicators) == 1
    assert Reason.CONFIRMED_SPOOF in result.reason_codes
    assert result.additional_verification_can_resolve is False


def test_face_match_cannot_override_confirmed_spoof():
    match = make_evidence(evidence_id="face-1")
    spoof = make_evidence(
        VerificationModule.FACE_LIVENESS,
        EvidenceOutcome.FAILURE,
        evidence_id="spoof-1",
    )
    result = validate(
        [match, spoof],
        required=(VerificationModule.FACE_RECOGNITION, VerificationModule.FACE_LIVENESS),
    )

    assert len(result.accepted_evidence) == 1
    assert result.accepted_evidence[0].evidence.module is VerificationModule.FACE_RECOGNITION
    assert result.confirmed_spoof_indicators
    assert not result.evidence_sufficient


def test_valid_rfid_is_identity_evidence_not_an_automatic_access_decision():
    rfid = make_evidence(VerificationModule.RFID, evidence_id="rfid-1")
    result = validate([rfid], required=(VerificationModule.RFID,))

    assert result.evidence_sufficient is True
    assert result.accepted_evidence[0].module_result == "VALID"
    # This component validates factor requirements only; it does not return ALLOW.
    assert not hasattr(result, "decision")


def test_unknown_issuer_is_not_trusted():
    evidence = make_evidence(issuer_id="unknown-issuer")
    result = validate([evidence])

    assert result.unknown_issuers
    assert Reason.UNKNOWN_ISSUER in result.reason_codes
    assert result.accepted_evidence == ()


def test_trusted_issuer_is_resolved_from_injected_provider():
    result = validate([make_evidence()], provider=FakeTrustedIssuerProvider())

    assert result.accepted_evidence[0].provenance.provider_id == "trusted-test-provider"


def test_trusted_issuer_provider_unavailable_fails_closed():
    result = validate([make_evidence()], provider=FakeTrustedIssuerProvider(mode="raise"))

    assert result.accepted_evidence == ()
    assert Reason.ISSUER_PROVIDER_UNAVAILABLE in result.reason_codes


def test_evidence_from_another_user_is_rejected():
    result = validate([make_evidence(user_id="user-2")])

    assert result.identity_correlation_failures
    assert Reason.IDENTITY_CORRELATION_FAILURE in result.reason_codes
    assert result.accepted_evidence == ()


def test_evidence_from_another_authentication_attempt_is_rejected():
    result = validate([make_evidence(attempt_id="attempt-2")])

    assert result.attempt_correlation_failures
    assert Reason.ATTEMPT_CORRELATION_FAILURE in result.reason_codes
    assert result.accepted_evidence == ()


def test_missing_attempt_identifier_is_reported_without_raising():
    missing_attempt = {
        "module": "FACE_RECOGNITION",
        "user_id": "user-1",
        "outcome": "SUCCESS",
        "issued_at": NOW,
        "issuer_id": "face-issuer",
        "evidence_id": "missing-attempt",
    }
    result = validate([missing_attempt])

    assert Reason.MISSING_ATTEMPT_ID in result.rejected_evidence[0].reason_codes
    assert result.accepted_evidence == ()


def test_stale_evidence_is_reported_and_not_accepted():
    stale = make_evidence(issued_at=NOW - timedelta(hours=2))
    result = validate([stale])

    assert result.stale_evidence
    assert Reason.STALE_EVIDENCE in result.reason_codes
    assert result.accepted_evidence == ()
    assert result.additional_verification_can_resolve is True


def test_future_dated_evidence_is_rejected():
    future = make_evidence(issued_at=NOW + timedelta(seconds=1))
    result = validate([future])

    assert Reason.FUTURE_DATED_EVIDENCE in result.reason_codes
    assert result.accepted_evidence == ()


def test_expired_evidence_is_reported_and_not_accepted():
    expired = make_evidence(expires_at=NOW)
    result = validate([expired])

    assert result.expired_evidence
    assert Reason.EXPIRED_EVIDENCE in result.reason_codes
    assert result.accepted_evidence == ()


def test_missing_required_evidence_is_distinct_from_failure():
    result = validate([])

    assert result.missing_required_modules == (VerificationModule.FACE_RECOGNITION,)
    assert result.failed_required_modules == ()
    assert Reason.MISSING_REQUIRED_EVIDENCE in result.reason_codes
    assert result.additional_verification_can_resolve is True


def test_pending_liveness_is_not_success_or_failure():
    pending = make_evidence(
        VerificationModule.FACE_LIVENESS,
        EvidenceOutcome.PENDING,
        evidence_id="live-pending",
    )
    result = validate([pending], required=(VerificationModule.FACE_LIVENESS,))

    assert result.accepted_evidence == ()
    assert result.pending_required_modules == (VerificationModule.FACE_LIVENESS,)
    assert Reason.EVIDENCE_PENDING in result.reason_codes
    assert result.additional_verification_can_resolve is True


def test_indeterminate_liveness_is_not_live():
    indeterminate = make_evidence(
        VerificationModule.FACE_LIVENESS,
        EvidenceOutcome.INDETERMINATE,
        evidence_id="live-indeterminate",
    )
    result = validate([indeterminate], required=(VerificationModule.FACE_LIVENESS,))

    assert result.accepted_evidence == ()
    assert Reason.EVIDENCE_INDETERMINATE in result.reason_codes
    assert not result.evidence_sufficient


def test_module_error_is_never_accepted_and_mandatory_error_is_reported():
    error = make_evidence(outcome=EvidenceOutcome.ERROR)
    result = validate([error])

    assert result.accepted_evidence == ()
    assert result.failed_required_modules == (VerificationModule.FACE_RECOGNITION,)
    assert Reason.MODULE_ERROR in result.reason_codes


def test_missing_timestamp_is_reported_without_dropping_the_item():
    missing_timestamp = {
        "module": "FACE_RECOGNITION",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "outcome": "SUCCESS",
        "issuer_id": "face-issuer",
        "evidence_id": "missing-time",
    }
    result = validate([missing_timestamp])

    assert result.rejected_evidence[0].evidence_id == "missing-time"
    assert Reason.MISSING_TIMESTAMP in result.rejected_evidence[0].reason_codes
    assert result.missing_required_modules == (VerificationModule.FACE_RECOGNITION,)


def test_preconstructed_unvalidated_model_is_revalidated():
    forged = VerificationEvidence.model_construct(
        module="IRIS_SCAN",
        user_id="user-1",
        authentication_attempt_id="attempt-1",
        outcome="SUCCESS",
        issued_at=NOW,
        issuer_id="face-issuer",
        evidence_id="forged-model",
    )
    result = validate([forged])

    assert result.accepted_evidence == ()
    assert Reason.UNKNOWN_MODULE in result.reason_codes


def test_unrecognized_module_is_reported():
    unknown_module = {
        "module": "IRIS_SCAN",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "outcome": "SUCCESS",
        "issued_at": NOW,
        "issuer_id": "face-issuer",
        "evidence_id": "unknown-module",
    }
    result = validate([unknown_module])

    assert result.rejected_evidence[0].module_claim == "IRIS_SCAN"
    assert Reason.UNKNOWN_MODULE in result.reason_codes


def test_duplicate_evidence_ids_reject_all_duplicates():
    one = make_evidence(evidence_id="duplicate-1")
    two = make_evidence(evidence_id="duplicate-1")
    result = validate([one, two])

    assert result.accepted_evidence == ()
    assert len(result.rejected_evidence) == 2
    assert all(Reason.DUPLICATE_EVIDENCE in item.reason_codes for item in result.rejected_evidence)


def test_missing_issuer_is_reported():
    missing_issuer = {
        "module": "FACE_RECOGNITION",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "outcome": "SUCCESS",
        "issued_at": NOW,
        "evidence_id": "missing-issuer",
    }
    result = validate([missing_issuer])

    assert Reason.MISSING_ISSUER in result.rejected_evidence[0].reason_codes


def test_caller_authority_fields_are_rejected_not_trusted():
    claimed_authority = {
        **make_evidence().model_dump(mode="json"),
        "authority_rank": 999,
        "module_result": "MATCH",
    }
    result = validate([claimed_authority])

    assert result.accepted_evidence == ()
    assert Reason.UNSUPPORTED_FIELD in result.rejected_evidence[0].reason_codes


def test_invalid_trusted_provider_response_is_rejected():
    result = validate([make_evidence()], provider=FakeTrustedIssuerProvider(mode="invalid"))

    assert result.accepted_evidence == ()
    assert Reason.INVALID_ISSUER_PROVIDER_RESPONSE in result.reason_codes


def test_invalid_evidence_validation_response_is_rejected():
    provider = FakeTrustedIssuerProvider(issuer_modes={"face-issuer": "invalid"})
    result = validate([make_evidence()], provider=provider)

    assert result.accepted_evidence == ()
    assert Reason.INVALID_ISSUER_PROVIDER_RESPONSE in result.reason_codes


def test_preconstructed_invalid_provider_model_is_revalidated():
    provider = FakeTrustedIssuerProvider(issuer_modes={"face-issuer": "invalid_model"})
    result = validate([make_evidence()], provider=provider)

    assert result.accepted_evidence == ()
    assert Reason.INVALID_ISSUER_PROVIDER_RESPONSE in result.reason_codes


def test_claimed_success_is_not_accepted_when_trusted_provider_disagrees():
    provider = FakeTrustedIssuerProvider(issuer_modes={"face-issuer": "conflicting_claim"})
    result = validate([make_evidence()], provider=provider)

    assert result.accepted_evidence == ()
    assert Reason.EVIDENCE_NOT_VERIFIED in result.reason_codes


def test_evaluation_context_must_match_request():
    validator = make_validator()

    with pytest.raises(ValueError, match="request_id must match"):
        validator.validate(
            make_request(),
            [make_evidence()],
            EvidenceRequirements(required_modules=(VerificationModule.FACE_RECOGNITION,)),
            make_context(request_id="another-request"),
        )


def test_successful_optional_factor_cannot_override_failed_mandatory_factor():
    recognition_failure = make_evidence(
        outcome=EvidenceOutcome.FAILURE,
        evidence_id="face-no-match",
    )
    optional_rfid_success = make_evidence(
        VerificationModule.RFID,
        evidence_id="rfid-valid",
    )
    result = validate(
        [recognition_failure, optional_rfid_success],
        required=(VerificationModule.FACE_RECOGNITION,),
    )

    assert result.accepted_evidence[0].evidence.module is VerificationModule.RFID
    assert result.failed_required_modules == (VerificationModule.FACE_RECOGNITION,)
    assert result.evidence_sufficient is False


def test_conflicting_results_from_one_mandatory_module_are_not_voted():
    match = make_evidence(evidence_id="face-match")
    mismatch = make_evidence(
        outcome=EvidenceOutcome.FAILURE,
        evidence_id="face-mismatch",
    )
    result = validate([match, mismatch])

    assert result.conflicting_modules == (VerificationModule.FACE_RECOGNITION,)
    assert result.accepted_evidence == ()
    assert result.failed_required_modules == (VerificationModule.FACE_RECOGNITION,)
    assert Reason.MODULE_RESULT_CONFLICT in result.reason_codes
    assert result.evidence_sufficient is False


def test_identical_inputs_produce_identical_results():
    items = [
        make_evidence(evidence_id="face-1"),
        make_evidence(VerificationModule.RFID, evidence_id="rfid-1"),
    ]
    validator = make_validator()
    request = make_request()
    requirements = EvidenceRequirements(
        required_any_of=((VerificationModule.FACE_RECOGNITION, VerificationModule.RFID),)
    )
    context = make_context()

    first = validator.validate(request, items, requirements, context)
    second = validator.validate(request, items, requirements, context)

    assert first == second
