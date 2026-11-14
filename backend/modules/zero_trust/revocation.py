"""Scoped revocation evaluation with explicit freshness and availability states."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from pydantic import AwareDatetime, Field, StrictBool, TypeAdapter, model_validator

from .enums import (
    AccessReasonCode,
    RecordStatus,
    ResourceSensitivity,
    RevocationFindingState,
    RevocationState,
)
from .schemas import (
    CampusRecord,
    DisciplinarySuspensionRecord,
    DomainModel,
    Identifier,
    IdentityStatusRecord,
    RecordProvenanceSummary,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
)

PositiveDuration = Annotated[timedelta, Field(gt=timedelta(0))]


class RevocationSourceCheck(DomainModel):
    """Trusted provider result proving an authoritative source was checked."""

    source_id: Identifier
    checked_at: AwareDatetime
    available: StrictBool


class RevocationPolicy(DomainModel):
    """Freshness and source requirements supplied by trusted server configuration."""

    required_for: tuple[ResourceSensitivity, ...] = (
        ResourceSensitivity.HIGH,
        ResourceSensitivity.CRITICAL,
    )
    max_age_by_sensitivity: dict[ResourceSensitivity, PositiveDuration] = Field(default_factory=dict)
    authoritative_sources: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def source_ids_must_be_unique(self) -> "RevocationPolicy":
        if len(set(self.authoritative_sources)) != len(self.authoritative_sources):
            raise ValueError("authoritative_sources must not contain duplicates")
        if len(set(self.required_for)) != len(self.required_for):
            raise ValueError("required_for must not contain duplicates")
        return self


class RevocationEvaluationResult(DomainModel):
    subject_id: Identifier
    resource_id: Identifier
    evaluated_at: AwareDatetime
    state: RevocationFindingState
    required: bool
    blocking: bool
    reason_codes: tuple[AccessReasonCode, ...]
    applicable_records: tuple[RecordProvenanceSummary, ...] = ()
    source_checks: tuple[RevocationSourceCheck, ...] = ()

    @model_validator(mode="after")
    def confirmed_revocation_must_block(self) -> "RevocationEvaluationResult":
        if self.state is RevocationFindingState.CONFIRMED_REVOCATION:
            if not self.blocking or AccessReasonCode.REVOCATION_CONFIRMED not in self.reason_codes:
                raise ValueError("confirmed revocation must block access and include its reason code")
        if self.state is RevocationFindingState.FRESH_AUTHORITATIVE_SOURCE_WITH_NO_REVOCATION:
            if self.blocking or self.reason_codes:
                raise ValueError("fresh clear revocation status cannot contain blocking findings")
        if self.required and self.state in {
            RevocationFindingState.STALE_REVOCATION_INFORMATION,
            RevocationFindingState.MISSING_REVOCATION_INFORMATION,
        }:
            expected = (
                AccessReasonCode.REVOCATION_STALE
                if self.state is RevocationFindingState.STALE_REVOCATION_INFORMATION
                else AccessReasonCode.REVOCATION_UNAVAILABLE
            )
            if not self.blocking or expected not in self.reason_codes:
                raise ValueError("required stale or missing revocation data must block access")
        return self


class RevocationChecker:
    """Check user, resource, permission, suspension and temporary-pass revocation scopes."""

    def evaluate(
        self,
        *,
        subject_id: str,
        resource_id: str,
        records: tuple[CampusRecord, ...],
        sensitivity: ResourceSensitivity,
        evaluated_at: AwareDatetime,
        policy: RevocationPolicy,
        source_checks: tuple[RevocationSourceCheck, ...] = (),
    ) -> RevocationEvaluationResult:
        policy = RevocationPolicy.model_validate(policy)
        now = TypeAdapter(AwareDatetime).validate_python(evaluated_at)
        if len({item.source_id for item in source_checks}) != len(source_checks):
            raise ValueError("only one revocation source check is allowed per source and evaluation")
        required = sensitivity in policy.required_for
        max_age = policy.max_age_by_sensitivity.get(sensitivity)
        applicable = tuple(
            record
            for record in records
            if self._applies_to(record, subject_id, resource_id)
        )
        summaries = tuple(
            sorted(
                (
                    RecordProvenanceSummary(
                        record_id=record.record_id,
                        source_id=record.source_id,
                        version=record.version,
                        observed_at=record.observed_at,
                        status=record.status,
                    )
                    for record in applicable
                ),
                key=lambda item: (item.source_id, item.record_id, item.version),
            )
        )
        checks = tuple(sorted(source_checks, key=lambda item: (item.source_id, item.checked_at)))

        confirmed = tuple(record for record in applicable if self._is_revoked(record, now))
        if confirmed:
            return RevocationEvaluationResult(
                subject_id=subject_id,
                resource_id=resource_id,
                evaluated_at=now,
                state=RevocationFindingState.CONFIRMED_REVOCATION,
                required=required,
                blocking=True,
                reason_codes=(AccessReasonCode.REVOCATION_CONFIRMED,),
                applicable_records=summaries,
                source_checks=checks,
            )

        if max_age is None:
            fresh_records = ()
            # Without a configured maximum age there is no valid freshness proof.
            # Preserve Phase 3's unavailable result rather than relabeling it stale.
            stale_information = False
        else:
            fresh_records = tuple(
                record
                for record in applicable
                if isinstance(record, RevocationStatusRecord)
                and record.revocation_state is RevocationState.CLEAR
                and record.status is RecordStatus.ACTIVE
                and record.valid_from <= now
                and (record.valid_until is None or now < record.valid_until)
                and timedelta(0) <= now - record.observed_at <= max_age
            )
            fresh_checks = tuple(
                check
                for check in checks
                if check.source_id in policy.authoritative_sources
                and check.available
                and timedelta(0) <= now - check.checked_at <= max_age
            )
            sources_checked = {check.source_id for check in fresh_checks}
            all_sources_checked = bool(policy.authoritative_sources) and set(policy.authoritative_sources) <= sources_checked
            stale_information = bool(applicable) or any(
                check.source_id in policy.authoritative_sources
                and check.available
                and (now - check.checked_at > max_age or now < check.checked_at)
                for check in checks
            )
            if fresh_records or all_sources_checked:
                return RevocationEvaluationResult(
                    subject_id=subject_id,
                    resource_id=resource_id,
                    evaluated_at=now,
                    state=RevocationFindingState.FRESH_AUTHORITATIVE_SOURCE_WITH_NO_REVOCATION,
                    required=required,
                    blocking=False,
                    reason_codes=(),
                    applicable_records=summaries,
                    source_checks=checks,
                )

        state = (
            RevocationFindingState.STALE_REVOCATION_INFORMATION
            if stale_information
            else RevocationFindingState.MISSING_REVOCATION_INFORMATION
        )
        reason = (
            AccessReasonCode.REVOCATION_STALE
            if stale_information
            else AccessReasonCode.REVOCATION_UNAVAILABLE
        )
        return RevocationEvaluationResult(
            subject_id=subject_id,
            resource_id=resource_id,
            evaluated_at=now,
            state=state,
            required=required,
            blocking=required,
            reason_codes=(reason,) if required else (),
            applicable_records=summaries,
            source_checks=checks,
        )

    @staticmethod
    def _applies_to(record: CampusRecord, subject_id: str, resource_id: str) -> bool:
        if record.subject_id != subject_id:
            return False
        if isinstance(record, RevocationStatusRecord):
            return record.resource_id is None or record.resource_id == resource_id
        if isinstance(record, ResourcePermissionRecord):
            return resource_id in record.resource_ids and record.status is RecordStatus.REVOKED
        if isinstance(record, DisciplinarySuspensionRecord):
            return (
                record.status in {RecordStatus.ACTIVE, RecordStatus.SUSPENDED}
                and (not record.resource_ids or resource_id in record.resource_ids)
            )
        if isinstance(record, TemporaryLabPassRecord):
            return record.resource_id == resource_id and record.status is RecordStatus.REVOKED
        if isinstance(record, IdentityStatusRecord):
            return record.status is RecordStatus.REVOKED
        return False

    @staticmethod
    def _is_revoked(record: CampusRecord, now: AwareDatetime) -> bool:
        if isinstance(record, RevocationStatusRecord):
            return record.revocation_state is RevocationState.REVOKED or record.status is RecordStatus.REVOKED
        if isinstance(record, DisciplinarySuspensionRecord):
            if record.valid_from > now or (record.valid_until is not None and now >= record.valid_until):
                return False
            return record.status in {RecordStatus.ACTIVE, RecordStatus.SUSPENDED}
        return record.status is RecordStatus.REVOKED
