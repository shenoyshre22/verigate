"""Validate authentication evidence against trusted adapters and explicit policy inputs."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import timedelta
from enum import StrEnum
from typing import Annotated, Protocol

from pydantic import Field, StrictBool, StrictInt, ValidationError, model_validator

from .enums import EvidenceOutcome, VerificationModule
from .schemas import (
    AccessRequest,
    DomainModel,
    EvaluationContext,
    EvidenceProvenance,
    VerificationEvidence,
)


class EvidenceValidationReasonCode(StrEnum):
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    ISSUER_PROVIDER_UNAVAILABLE = "ISSUER_PROVIDER_UNAVAILABLE"
    INVALID_ISSUER_PROVIDER_RESPONSE = "INVALID_ISSUER_PROVIDER_RESPONSE"
    EVIDENCE_NOT_VERIFIED = "EVIDENCE_NOT_VERIFIED"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    UNSUPPORTED_FIELD = "UNSUPPORTED_FIELD"
    MISSING_ISSUER = "MISSING_ISSUER"
    MISSING_USER_ID = "MISSING_USER_ID"
    MISSING_ATTEMPT_ID = "MISSING_ATTEMPT_ID"
    MISSING_EVIDENCE_ID = "MISSING_EVIDENCE_ID"
    MISSING_TIMESTAMP = "MISSING_TIMESTAMP"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    UNKNOWN_MODULE = "UNKNOWN_MODULE"
    IDENTITY_CORRELATION_FAILURE = "IDENTITY_CORRELATION_FAILURE"
    ATTEMPT_CORRELATION_FAILURE = "ATTEMPT_CORRELATION_FAILURE"
    DUPLICATE_EVIDENCE = "DUPLICATE_EVIDENCE"
    FUTURE_DATED_EVIDENCE = "FUTURE_DATED_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    EXPIRED_EVIDENCE = "EXPIRED_EVIDENCE"
    FRESHNESS_POLICY_MISSING = "FRESHNESS_POLICY_MISSING"
    MODULE_FAILURE = "MODULE_FAILURE"
    MODULE_ERROR = "MODULE_ERROR"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    EVIDENCE_INDETERMINATE = "EVIDENCE_INDETERMINATE"
    CONFIRMED_SPOOF = "CONFIRMED_SPOOF"
    MODULE_RESULT_INVALID = "MODULE_RESULT_INVALID"
    MODULE_RESULT_CONFLICT = "MODULE_RESULT_CONFLICT"
    EVIDENCE_ACCEPTED = "EVIDENCE_ACCEPTED"
    MISSING_REQUIRED_EVIDENCE = "MISSING_REQUIRED_EVIDENCE"
    FAILED_REQUIRED_EVIDENCE = "FAILED_REQUIRED_EVIDENCE"


class EvidenceRequirements(DomainModel):
    """All required modules must succeed; each `required_any_of` group needs one success."""

    required_modules: tuple[VerificationModule, ...] = ()
    required_any_of: tuple[tuple[VerificationModule, ...], ...] = ()

    @model_validator(mode="after")
    def requirements_must_be_explicit_and_unambiguous(self) -> "EvidenceRequirements":
        if not self.required_modules and not self.required_any_of:
            raise ValueError("at least one required module or required_any_of group is required")
        if len(set(self.required_modules)) != len(self.required_modules):
            raise ValueError("required_modules must not contain duplicates")
        for group in self.required_any_of:
            if not group:
                raise ValueError("required_any_of groups must not be empty")
            if len(set(group)) != len(group):
                raise ValueError("required_any_of groups must not contain duplicates")
        return self


class EvidenceFreshnessPolicy(DomainModel):
    """Explicit maximum age for each usable module and permitted clock skew."""

    max_age_by_module: dict[VerificationModule, timedelta]
    allowed_future_skew: timedelta = timedelta(0)

    @model_validator(mode="after")
    def durations_must_be_valid(self) -> "EvidenceFreshnessPolicy":
        if not self.max_age_by_module:
            raise ValueError("max_age_by_module must configure at least one module")
        if any(age <= timedelta(0) for age in self.max_age_by_module.values()):
            raise ValueError("maximum evidence ages must be positive")
        if self.allowed_future_skew < timedelta(0):
            raise ValueError("allowed_future_skew cannot be negative")
        return self


class TrustedEvidence(DomainModel):
    """Canonical evidence and provenance returned by a trusted module adapter."""

    evidence: VerificationEvidence
    provenance: EvidenceProvenance
    module_result: str

    @model_validator(mode="after")
    def provenance_must_bind_the_evidence(self) -> "TrustedEvidence":
        if self.provenance.evidence_id != self.evidence.evidence_id:
            raise ValueError("provider provenance evidence_id does not match canonical evidence")
        if self.provenance.issuer_id != self.evidence.issuer_id:
            raise ValueError("provider provenance issuer_id does not match canonical evidence")
        if self.provenance.validated_outcome is not self.evidence.outcome:
            raise ValueError("provider provenance outcome does not match canonical evidence")
        return self


class TrustedIssuerAdapter(Protocol):
    """Trusted adapter verifies the evidence claim against its originating module."""

    issuer_id: str
    module: VerificationModule
    provider_id: str

    def validate_evidence(self, claim: VerificationEvidence) -> TrustedEvidence | None:
        """Return canonical evidence only after authenticating its source and contents."""


class TrustedIssuerProvider(Protocol):
    """Server-side issuer registry; never populated from request authority fields."""

    def get_trusted_issuer(self, issuer_id: str) -> TrustedIssuerAdapter | None:
        """Resolve an issuer identifier to an adapter from trusted configuration."""


class EvidenceIssue(DomainModel):
    """Sanitized issue record; it never stores unknown raw request payloads."""

    item_index: Annotated[StrictInt, Field(ge=0)]
    evidence_id: str | None = None
    module_claim: str | None = None
    reason_codes: tuple[EvidenceValidationReasonCode, ...] = Field(min_length=1)
    evidence: VerificationEvidence | None = None


class EvidenceValidationResult(DomainModel):
    """Complete validation output, including every accepted and rejected claim."""

    accepted_evidence: tuple[TrustedEvidence, ...]
    rejected_evidence: tuple[EvidenceIssue, ...]
    missing_required_modules: tuple[VerificationModule, ...]
    failed_required_modules: tuple[VerificationModule, ...]
    pending_required_modules: tuple[VerificationModule, ...]
    conflicting_modules: tuple[VerificationModule, ...]
    stale_evidence: tuple[EvidenceIssue, ...]
    expired_evidence: tuple[EvidenceIssue, ...]
    unknown_issuers: tuple[EvidenceIssue, ...]
    identity_correlation_failures: tuple[EvidenceIssue, ...]
    attempt_correlation_failures: tuple[EvidenceIssue, ...]
    confirmed_spoof_indicators: tuple[EvidenceIssue, ...]
    reason_codes: tuple[EvidenceValidationReasonCode, ...]
    evidence_sufficient: StrictBool
    additional_verification_can_resolve: StrictBool


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_MODULE_CLAIM = re.compile(r"^[A-Za-z0-9_]{1,64}$")

_MODULE_RESULTS: dict[VerificationModule, dict[str, EvidenceOutcome]] = {
    VerificationModule.FACE_RECOGNITION: {
        "MATCH": EvidenceOutcome.SUCCESS,
        "NO_MATCH": EvidenceOutcome.FAILURE,
        "ERROR": EvidenceOutcome.ERROR,
    },
    VerificationModule.FACE_LIVENESS: {
        "LIVE": EvidenceOutcome.SUCCESS,
        "SPOOF": EvidenceOutcome.FAILURE,
        "PENDING": EvidenceOutcome.PENDING,
        "EXPIRED": EvidenceOutcome.EXPIRED,
        "INDETERMINATE": EvidenceOutcome.INDETERMINATE,
        "ERROR": EvidenceOutcome.ERROR,
    },
    VerificationModule.FINGERPRINT: {
        "MATCH": EvidenceOutcome.SUCCESS,
        "NO_MATCH": EvidenceOutcome.FAILURE,
        "ERROR": EvidenceOutcome.ERROR,
    },
    VerificationModule.RFID: {
        "VALID": EvidenceOutcome.SUCCESS,
        "INVALID": EvidenceOutcome.FAILURE,
        "ERROR": EvidenceOutcome.ERROR,
    },
}


def _raw_value(raw: object, key: str) -> object | None:
    if isinstance(raw, VerificationEvidence):
        return getattr(raw, key, None)
    if isinstance(raw, Mapping):
        return raw.get(key)
    return None


def _parse_error_reasons(error: ValidationError) -> tuple[EvidenceValidationReasonCode, ...]:
    reasons: set[EvidenceValidationReasonCode] = set()
    for item in error.errors():
        field = item["loc"][0] if item["loc"] else None
        error_type = item["type"]
        if field == "module" and error_type in {"enum", "string_type"}:
            reasons.add(EvidenceValidationReasonCode.UNKNOWN_MODULE)
        elif field == "issuer_id" and error_type in {"missing", "string_too_short", "string_type"}:
            reasons.add(EvidenceValidationReasonCode.MISSING_ISSUER)
        elif field == "user_id" and error_type in {"missing", "string_too_short", "string_type"}:
            reasons.add(EvidenceValidationReasonCode.MISSING_USER_ID)
        elif field == "authentication_attempt_id" and error_type in {
            "missing",
            "string_too_short",
            "string_type",
        }:
            reasons.add(EvidenceValidationReasonCode.MISSING_ATTEMPT_ID)
        elif field == "evidence_id" and error_type in {"missing", "string_too_short", "string_type"}:
            reasons.add(EvidenceValidationReasonCode.MISSING_EVIDENCE_ID)
        elif field in {"issued_at", "expires_at"}:
            if field == "issued_at" and (
                error_type == "missing" or item.get("input") in (None, "")
            ):
                reasons.add(EvidenceValidationReasonCode.MISSING_TIMESTAMP)
            else:
                reasons.add(EvidenceValidationReasonCode.INVALID_TIMESTAMP)
        elif error_type == "extra_forbidden":
            reasons.add(EvidenceValidationReasonCode.UNSUPPORTED_FIELD)
        else:
            reasons.add(EvidenceValidationReasonCode.INVALID_EVIDENCE)
    if not reasons:
        reasons.add(EvidenceValidationReasonCode.INVALID_EVIDENCE)
    return tuple(sorted(reasons, key=lambda reason: reason.value))


class EvidenceValidator:
    """Validates provider-backed evidence using only injected, deterministic inputs."""

    def __init__(
        self,
        issuer_provider: TrustedIssuerProvider,
        freshness_policy: EvidenceFreshnessPolicy,
    ) -> None:
        self._issuer_provider = issuer_provider
        freshness_policy = EvidenceFreshnessPolicy.model_validate(freshness_policy)
        self._max_age_by_module = dict(freshness_policy.max_age_by_module)
        self._allowed_future_skew = freshness_policy.allowed_future_skew

    def validate(
        self,
        request: AccessRequest,
        evidence_items: Sequence[VerificationEvidence | Mapping[str, object]],
        requirements: EvidenceRequirements,
        context: EvaluationContext,
    ) -> EvidenceValidationResult:
        request = AccessRequest.model_validate(request)
        requirements = EvidenceRequirements.model_validate(requirements)
        context = EvaluationContext.model_validate(context)
        if context.request_id != request.request_id:
            raise ValueError("evaluation context request_id must match access request request_id")

        parsed: list[tuple[int, VerificationEvidence]] = []
        rejected: list[EvidenceIssue] = []

        for index, raw in enumerate(evidence_items):
            try:
                claim = VerificationEvidence.model_validate(raw)
            except ValidationError as error:
                rejected.append(
                    EvidenceIssue(
                        item_index=index,
                        evidence_id=self._safe_identifier(_raw_value(raw, "evidence_id")),
                        module_claim=self._safe_module_claim(_raw_value(raw, "module")),
                        reason_codes=_parse_error_reasons(error),
                    )
                )
                continue
            parsed.append((index, claim))

        duplicate_ids = {
            evidence_id
            for evidence_id, count in Counter(claim.evidence_id for _, claim in parsed).items()
            if count > 1
        }
        accepted: list[TrustedEvidence] = []
        stale: list[EvidenceIssue] = []
        expired: list[EvidenceIssue] = []
        unknown_issuers: list[EvidenceIssue] = []
        identity_failures: list[EvidenceIssue] = []
        attempt_failures: list[EvidenceIssue] = []
        spoof_indicators: list[EvidenceIssue] = []
        validated_outcomes: dict[VerificationModule, list[EvidenceOutcome]] = {}
        fresh_results: dict[VerificationModule, list[str]] = {}
        reported_reason_codes: set[EvidenceValidationReasonCode] = {
            code for issue in rejected for code in issue.reason_codes
        }

        for index, claim in parsed:
            if claim.evidence_id in duplicate_ids:
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.DUPLICATE_EVIDENCE,
                    reason_codes_out=reported_reason_codes,
                )
                continue
            if claim.user_id != request.user_id:
                issue = self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.IDENTITY_CORRELATION_FAILURE,
                    reason_codes_out=reported_reason_codes,
                )
                identity_failures.append(issue)
                continue
            if claim.authentication_attempt_id != request.authentication_attempt_id:
                issue = self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.ATTEMPT_CORRELATION_FAILURE,
                    reason_codes_out=reported_reason_codes,
                )
                attempt_failures.append(issue)
                continue

            try:
                lookup = getattr(self._issuer_provider, "get_trusted_issuer", None)
                if not callable(lookup):
                    self._record_issue(
                        rejected,
                        index,
                        claim,
                        EvidenceValidationReasonCode.INVALID_ISSUER_PROVIDER_RESPONSE,
                        reason_codes_out=reported_reason_codes,
                    )
                    continue
                issuer = lookup(claim.issuer_id)
            except Exception:
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.ISSUER_PROVIDER_UNAVAILABLE,
                    reason_codes_out=reported_reason_codes,
                )
                continue

            if issuer is None:
                issue = self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.UNKNOWN_ISSUER,
                    reason_codes_out=reported_reason_codes,
                )
                unknown_issuers.append(issue)
                continue
            if not self._valid_issuer_adapter(issuer, claim):
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.INVALID_ISSUER_PROVIDER_RESPONSE,
                    reason_codes_out=reported_reason_codes,
                )
                continue

            try:
                trusted = issuer.validate_evidence(claim)
            except Exception:
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.ISSUER_PROVIDER_UNAVAILABLE,
                    reason_codes_out=reported_reason_codes,
                )
                continue
            if trusted is None:
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.EVIDENCE_NOT_VERIFIED,
                    reason_codes_out=reported_reason_codes,
                )
                continue
            try:
                trusted = TrustedEvidence.model_validate(trusted)
            except ValidationError:
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.INVALID_ISSUER_PROVIDER_RESPONSE,
                    reason_codes_out=reported_reason_codes,
                )
                continue
            if not self._valid_trusted_evidence(trusted, issuer, context):
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.INVALID_ISSUER_PROVIDER_RESPONSE,
                    reason_codes_out=reported_reason_codes,
                )
                continue

            canonical = trusted.evidence
            if canonical.user_id != request.user_id:
                issue = self._record_issue(
                    rejected,
                    index,
                    canonical,
                    EvidenceValidationReasonCode.IDENTITY_CORRELATION_FAILURE,
                    reason_codes_out=reported_reason_codes,
                )
                identity_failures.append(issue)
                continue
            if canonical.authentication_attempt_id != request.authentication_attempt_id:
                issue = self._record_issue(
                    rejected,
                    index,
                    canonical,
                    EvidenceValidationReasonCode.ATTEMPT_CORRELATION_FAILURE,
                    reason_codes_out=reported_reason_codes,
                )
                attempt_failures.append(issue)
                continue
            if canonical != claim:
                self._record_issue(
                    rejected,
                    index,
                    claim,
                    EvidenceValidationReasonCode.EVIDENCE_NOT_VERIFIED,
                    reason_codes_out=reported_reason_codes,
                )
                continue

            module_result_outcome = _MODULE_RESULTS[canonical.module].get(trusted.module_result)
            if module_result_outcome is None or module_result_outcome is not canonical.outcome:
                self._record_issue(
                    rejected,
                    index,
                    canonical,
                    EvidenceValidationReasonCode.MODULE_RESULT_INVALID,
                    reason_codes_out=reported_reason_codes,
                )
                continue
            validated_outcomes.setdefault(canonical.module, []).append(canonical.outcome)

            max_age = self._max_age_by_module.get(canonical.module)
            time_reasons: list[EvidenceValidationReasonCode] = []
            if max_age is None:
                time_reasons.append(EvidenceValidationReasonCode.FRESHNESS_POLICY_MISSING)
            if canonical.issued_at > context.evaluated_at + self._allowed_future_skew:
                time_reasons.append(EvidenceValidationReasonCode.FUTURE_DATED_EVIDENCE)
            elif max_age is not None and context.evaluated_at - canonical.issued_at > max_age:
                time_reasons.append(EvidenceValidationReasonCode.STALE_EVIDENCE)
            if canonical.expires_at is not None and canonical.expires_at <= context.evaluated_at:
                time_reasons.append(EvidenceValidationReasonCode.EXPIRED_EVIDENCE)

            is_spoof = (
                canonical.module is VerificationModule.FACE_LIVENESS
                and trusted.module_result == "SPOOF"
            )
            if time_reasons or is_spoof:
                if not time_reasons:
                    fresh_results.setdefault(canonical.module, []).append(trusted.module_result)
                if is_spoof:
                    time_reasons.append(EvidenceValidationReasonCode.CONFIRMED_SPOOF)
                issue = self._record_issue(
                    rejected,
                    index,
                    canonical,
                    *time_reasons,
                    reason_codes_out=reported_reason_codes,
                )
                if EvidenceValidationReasonCode.STALE_EVIDENCE in time_reasons:
                    stale.append(issue)
                if EvidenceValidationReasonCode.EXPIRED_EVIDENCE in time_reasons:
                    expired.append(issue)
                if is_spoof:
                    spoof_indicators.append(issue)
                continue

            fresh_results.setdefault(canonical.module, []).append(trusted.module_result)
            if canonical.outcome is EvidenceOutcome.SUCCESS:
                accepted.append(trusted)
                reported_reason_codes.add(EvidenceValidationReasonCode.EVIDENCE_ACCEPTED)
            else:
                reason = self._outcome_reason(canonical.outcome)
                issue = self._record_issue(
                    rejected,
                    index,
                    canonical,
                    reason,
                    reason_codes_out=reported_reason_codes,
                )
                if canonical.outcome is EvidenceOutcome.EXPIRED:
                    expired.append(issue)

        conflicting_modules = {
            module for module, results in fresh_results.items() if len(set(results)) > 1
        }
        if conflicting_modules:
            reported_reason_codes.add(EvidenceValidationReasonCode.MODULE_RESULT_CONFLICT)
            remaining_accepted: list[TrustedEvidence] = []
            for item in accepted:
                if item.evidence.module in conflicting_modules:
                    rejected.append(
                        EvidenceIssue(
                            item_index=next(
                                index
                                for index, parsed_claim in parsed
                                if parsed_claim.evidence_id == item.evidence.evidence_id
                            ),
                            evidence_id=item.evidence.evidence_id,
                            module_claim=item.evidence.module.value,
                            reason_codes=(EvidenceValidationReasonCode.MODULE_RESULT_CONFLICT,),
                            evidence=item.evidence,
                        )
                    )
                else:
                    remaining_accepted.append(item)
            accepted = remaining_accepted

        accepted_modules = {item.evidence.module for item in accepted}
        missing_modules, failed_modules, pending_modules = self._requirements_status(
            requirements,
            accepted_modules,
            validated_outcomes,
        )
        if missing_modules:
            reported_reason_codes.add(EvidenceValidationReasonCode.MISSING_REQUIRED_EVIDENCE)
        if failed_modules:
            reported_reason_codes.add(EvidenceValidationReasonCode.FAILED_REQUIRED_EVIDENCE)
        if pending_modules:
            reported_reason_codes.add(EvidenceValidationReasonCode.EVIDENCE_PENDING)

        requirements_met = not missing_modules and not failed_modules and not pending_modules
        sufficient = requirements_met and not spoof_indicators
        can_resolve = not sufficient and not spoof_indicators

        ordered_reasons = tuple(
            sorted(reported_reason_codes, key=lambda reason: reason.value)
        )
        return EvidenceValidationResult(
            accepted_evidence=tuple(accepted),
            rejected_evidence=tuple(rejected),
            missing_required_modules=missing_modules,
            failed_required_modules=failed_modules,
            pending_required_modules=pending_modules,
            conflicting_modules=tuple(
                sorted(conflicting_modules, key=lambda module: list(VerificationModule).index(module))
            ),
            stale_evidence=tuple(stale),
            expired_evidence=tuple(expired),
            unknown_issuers=tuple(unknown_issuers),
            identity_correlation_failures=tuple(identity_failures),
            attempt_correlation_failures=tuple(attempt_failures),
            confirmed_spoof_indicators=tuple(spoof_indicators),
            reason_codes=ordered_reasons,
            evidence_sufficient=sufficient,
            additional_verification_can_resolve=can_resolve,
        )

    @staticmethod
    def _safe_identifier(value: object | None) -> str | None:
        if isinstance(value, str):
            candidate = value.strip()
            if _SAFE_IDENTIFIER.fullmatch(candidate):
                return candidate
        return None

    @staticmethod
    def _safe_module_claim(value: object | None) -> str | None:
        if isinstance(value, str):
            candidate = value.strip()
            if _SAFE_MODULE_CLAIM.fullmatch(candidate):
                return candidate
        return None

    @staticmethod
    def _valid_issuer_adapter(issuer: object, claim: VerificationEvidence) -> bool:
        return (
            getattr(issuer, "issuer_id", None) == claim.issuer_id
            and getattr(issuer, "module", None) is claim.module
            and isinstance(getattr(issuer, "provider_id", None), str)
            and callable(getattr(issuer, "validate_evidence", None))
        )

    @staticmethod
    def _valid_trusted_evidence(
        trusted: object,
        issuer: TrustedIssuerAdapter,
        context: EvaluationContext,
    ) -> bool:
        if not isinstance(trusted, TrustedEvidence):
            return False
        evidence = trusted.evidence
        provenance = trusted.provenance
        return (
            evidence.module is issuer.module
            and evidence.issuer_id == issuer.issuer_id
            and provenance.provider_id == issuer.provider_id
            and provenance.validated_at <= context.evaluated_at
            and bool(trusted.module_result)
        )

    @staticmethod
    def _outcome_reason(outcome: EvidenceOutcome) -> EvidenceValidationReasonCode:
        return {
            EvidenceOutcome.FAILURE: EvidenceValidationReasonCode.MODULE_FAILURE,
            EvidenceOutcome.ERROR: EvidenceValidationReasonCode.MODULE_ERROR,
            EvidenceOutcome.PENDING: EvidenceValidationReasonCode.EVIDENCE_PENDING,
            EvidenceOutcome.EXPIRED: EvidenceValidationReasonCode.EXPIRED_EVIDENCE,
            EvidenceOutcome.INDETERMINATE: EvidenceValidationReasonCode.EVIDENCE_INDETERMINATE,
            EvidenceOutcome.SUCCESS: EvidenceValidationReasonCode.INVALID_EVIDENCE,
        }[outcome]

    @staticmethod
    def _record_issue(
        rejected: list[EvidenceIssue],
        index: int,
        evidence: VerificationEvidence,
        *reason_codes: EvidenceValidationReasonCode,
        reason_codes_out: set[EvidenceValidationReasonCode] | None = None,
    ) -> EvidenceIssue:
        # Preserve insertion order while avoiding duplicate reason values.
        unique_codes = tuple(dict.fromkeys(reason_codes))
        issue = EvidenceIssue(
            item_index=index,
            evidence_id=evidence.evidence_id,
            module_claim=evidence.module.value,
            reason_codes=unique_codes,
            evidence=evidence,
        )
        rejected.append(issue)
        if reason_codes_out is not None:
            reason_codes_out.update(unique_codes)
        return issue

    @staticmethod
    def _requirements_status(
        requirements: EvidenceRequirements,
        accepted_modules: set[VerificationModule],
        trusted_outcomes: dict[VerificationModule, list[EvidenceOutcome]],
    ) -> tuple[
        tuple[VerificationModule, ...],
        tuple[VerificationModule, ...],
        tuple[VerificationModule, ...],
    ]:
        missing: set[VerificationModule] = set()
        failed: set[VerificationModule] = set()
        pending: set[VerificationModule] = set()

        for module in requirements.required_modules:
            outcomes = trusted_outcomes.get(module, [])
            if outcomes:
                if any(outcome in {EvidenceOutcome.FAILURE, EvidenceOutcome.ERROR} for outcome in outcomes):
                    failed.add(module)
                elif module in accepted_modules:
                    continue
                elif any(outcome in {EvidenceOutcome.PENDING, EvidenceOutcome.INDETERMINATE, EvidenceOutcome.EXPIRED, EvidenceOutcome.SUCCESS} for outcome in outcomes):
                    pending.add(module)
            elif module in accepted_modules:
                continue
            else:
                missing.add(module)

        for group in requirements.required_any_of:
            if accepted_modules.intersection(group):
                continue
            group_has_terminal_failure = False
            for module in group:
                outcomes = trusted_outcomes.get(module, [])
                if not outcomes:
                    missing.add(module)
                elif any(outcome in {EvidenceOutcome.FAILURE, EvidenceOutcome.ERROR} for outcome in outcomes):
                    failed.add(module)
                    group_has_terminal_failure = True
                elif any(outcome in {EvidenceOutcome.PENDING, EvidenceOutcome.INDETERMINATE, EvidenceOutcome.EXPIRED, EvidenceOutcome.SUCCESS} for outcome in outcomes):
                    pending.add(module)
            # Pending/indeterminate evidence is neither missing nor a module failure.
            if group_has_terminal_failure:
                continue

        enum_order = {module: index for index, module in enumerate(VerificationModule)}
        return (
            tuple(sorted(missing, key=enum_order.__getitem__)),
            tuple(sorted(failed, key=enum_order.__getitem__)),
            tuple(sorted(pending, key=enum_order.__getitem__)),
        )
