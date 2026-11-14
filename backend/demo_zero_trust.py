"""Offline, synthetic demonstration of the implemented VERIGATE decision engine."""

from datetime import datetime, timedelta, timezone

from modules.zero_trust.authorization import (
    AuthorizationPolicy,
    AuthorizationSnapshot,
    CampusAuthorizationEvaluator,
)
from modules.zero_trust.conflict_resolver import (
    CampusRecordConflictResolver,
    ConflictResolutionPolicy,
    SourceAuthorityRule,
)
from modules.zero_trust.engine import (
    DecisionEnginePolicy,
    TrustedCampusData,
    ZeroTrustDecisionEngine,
)
from modules.zero_trust.enums import (
    AccessDecision,
    EvidenceOutcome,
    PermissionEffect,
    RecordDomain,
    RecordStatus,
    ResourceSensitivity,
    VerificationModule,
)
from modules.zero_trust.evidence_validator import (
    EvidenceFreshnessPolicy,
    EvidenceRequirements,
    EvidenceValidator,
    TrustedEvidence,
)
from modules.zero_trust.policy_evaluator import PolicyEvaluator
from modules.zero_trust.revocation import (
    RevocationChecker,
    RevocationPolicy,
    RevocationSourceCheck,
)
from modules.zero_trust.schemas import (
    AccessRequest,
    DisciplinarySuspensionRecord,
    EvidenceProvenance,
    IdentityStatusRecord,
    ResourcePermissionRecord,
    VerificationEvidence,
)


# Every identity, record, evidence claim, and provider in this demo is synthetic.
NOW = datetime.now(timezone.utc)
USER_ID = "synthetic-student-001"
ATTEMPT_ID = "synthetic-attempt-001"
RESOURCE_ID = "SYNTHETIC-LAB-101"
ACTION_ID = "ENTER"


class SyntheticEvidenceProvider:
    def __init__(self, claims):
        self.claims = tuple(claims)

    def get_evidence(self, request):
        return self.claims


class SyntheticTrustedAdapter:
    def __init__(self, module):
        self.module = module
        self.issuer_id = f"synthetic-issuer-{module.value.lower()}"
        self.provider_id = f"synthetic-provider-{module.value.lower()}"

    def validate_evidence(self, claim):
        module_result = {
            VerificationModule.FACE_RECOGNITION: "MATCH",
            VerificationModule.FACE_LIVENESS: "LIVE",
        }[claim.module]
        return TrustedEvidence(
            evidence=claim,
            provenance=EvidenceProvenance(
                evidence_id=claim.evidence_id,
                issuer_id=claim.issuer_id,
                provider_id=self.provider_id,
                validated_at=NOW,
                validated_outcome=claim.outcome,
            ),
            module_result=module_result,
        )


class SyntheticIssuerProvider:
    def __init__(self):
        self.adapters = {
            adapter.issuer_id: adapter
            for adapter in (
                SyntheticTrustedAdapter(VerificationModule.FACE_RECOGNITION),
                SyntheticTrustedAdapter(VerificationModule.FACE_LIVENESS),
            )
        }

    def get_trusted_issuer(self, issuer_id):
        return self.adapters.get(issuer_id)


class SyntheticCampusProvider:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def get_authorization_data(self, request, evaluated_at):
        return TrustedCampusData(
            authorization_snapshot=self.snapshot,
            revocation_source_checks=(
                RevocationSourceCheck(
                    source_id="synthetic-revocation",
                    checked_at=evaluated_at,
                    available=True,
                ),
            ),
        )


class SyntheticPolicyProvider:
    def __init__(self):
        sources = {
            domain: (SourceAuthorityRule(source_id=source, priority=0),)
            for domain, source in (
                (RecordDomain.IDENTITY, "synthetic-sis"),
                (RecordDomain.ROLE, "synthetic-roles"),
                (RecordDomain.PERMISSION, "synthetic-access-control"),
                (RecordDomain.DISCIPLINARY, "synthetic-conduct"),
                (RecordDomain.EXAMINATION, "synthetic-exams"),
                (RecordDomain.TEMPORARY_PASS, "synthetic-lab-office"),
                (RecordDomain.SAFETY_CLEARANCE, "synthetic-safety"),
                (RecordDomain.REVOCATION, "synthetic-revocation"),
            )
        }
        self.policy = DecisionEnginePolicy(
            policy_version="synthetic-demo-policy-v1",
            resource_sensitivity=ResourceSensitivity.LOW,
            evidence_requirements=EvidenceRequirements(
                required_modules=(
                    VerificationModule.FACE_RECOGNITION,
                    VerificationModule.FACE_LIVENESS,
                )
            ),
            authorization_policy=AuthorizationPolicy(),
            conflict_resolution_policy=ConflictResolutionPolicy(
                sources_by_domain=sources,
                max_age_by_domain={domain: timedelta(days=2) for domain in RecordDomain},
            ),
            revocation_policy=RevocationPolicy(
                authoritative_sources=("synthetic-revocation",),
            ),
        )

    def get_policy(self, request):
        return self.policy


def _record_fields(record_id, source_id, *, status=RecordStatus.ACTIVE):
    return {
        "record_id": record_id,
        "subject_id": USER_ID,
        "source_id": source_id,
        "version": 1,
        "issued_at": NOW - timedelta(hours=2),
        "source_updated_at": NOW - timedelta(hours=1),
        "observed_at": NOW - timedelta(minutes=5),
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "status": status,
    }


def _snapshot(*, suspended=False):
    return AuthorizationSnapshot(
        identities=(
            IdentityStatusRecord(**_record_fields("synthetic-identity", "synthetic-sis")),
        ),
        permissions=(
            ResourcePermissionRecord(
                **_record_fields("synthetic-permission", "synthetic-access-control"),
                effect=PermissionEffect.GRANT,
                resource_ids=(RESOURCE_ID,),
                action_ids=(ACTION_ID,),
            ),
        ),
        suspensions=(
            DisciplinarySuspensionRecord(
                **_record_fields(
                    "synthetic-suspension",
                    "synthetic-conduct",
                    status=RecordStatus.SUSPENDED,
                ),
                reason_code="synthetic-disciplinary-hold",
            ),
        ) if suspended else (),
    )


def _evidence(module):
    return VerificationEvidence(
        module=module,
        user_id=USER_ID,
        authentication_attempt_id=ATTEMPT_ID,
        outcome=EvidenceOutcome.SUCCESS,
        issued_at=NOW,
        issuer_id=f"synthetic-issuer-{module.value.lower()}",
        evidence_id=f"synthetic-evidence-{module.value.lower()}",
    )


def _engine(snapshot, claims):
    return ZeroTrustDecisionEngine(
        evidence_validator=EvidenceValidator(
            SyntheticIssuerProvider(),
            EvidenceFreshnessPolicy(
                max_age_by_module={module: timedelta(hours=1) for module in VerificationModule}
            ),
        ),
        evidence_provider=SyntheticEvidenceProvider(claims),
        campus_record_provider=SyntheticCampusProvider(snapshot),
        policy_provider=SyntheticPolicyProvider(),
        authorization_evaluator=CampusAuthorizationEvaluator(),
        policy_evaluator=PolicyEvaluator(),
        conflict_resolver=CampusRecordConflictResolver(),
        revocation_checker=RevocationChecker(),
        clock=lambda: NOW,
    )


def _request(request_id):
    return AccessRequest(
        request_id=request_id,
        user_id=USER_ID,
        authentication_attempt_id=ATTEMPT_ID,
        resource={"resource_id": RESOURCE_ID},
        action={"action_id": ACTION_ID},
        requested_at=NOW,
    )


def main():
    face_and_liveness = (
        _evidence(VerificationModule.FACE_RECOGNITION),
        _evidence(VerificationModule.FACE_LIVENESS),
    )
    scenarios = (
        (
            "1. Valid identity and authorization",
            "Synthetic active identity, permission grant, face match, and live evidence.",
            _snapshot(),
            face_and_liveness,
        ),
        (
            "2. Biometric success with active disciplinary suspension",
            "Synthetic active identity and permission, successful face/liveness, and active suspension.",
            _snapshot(suspended=True),
            face_and_liveness,
        ),
        (
            "3. Missing required liveness evidence",
            "Synthetic active identity and permission, face match present, liveness evidence absent.",
            _snapshot(),
            (_evidence(VerificationModule.FACE_RECOGNITION),),
        ),
    )

    print("VERIGATE ZERO TRUST DECISION ENGINE â€” OFFLINE SYNTHETIC DEMO")
    print("All identities, campus records, evidence, and providers below are synthetic.\n")
    for title, summary, snapshot, claims in scenarios:
        result = _engine(snapshot, claims).evaluate(_request(title.split(".")[0]))
        assert result.decision in {
            AccessDecision.ALLOW,
            AccessDecision.DENY,
            AccessDecision.REQUEST_VERIFICATION,
        }
        print(f"{title} [SYNTHETIC DATA]")
        print(f"  Input summary: {summary}")
        print(f"  Final decision: {result.decision.value}")
        print("  Reason codes: " + ", ".join(code.value for code in result.reason_codes))
        print(f"  Explanation: {result.explanation}\n")


if __name__ == "__main__":
    main()

