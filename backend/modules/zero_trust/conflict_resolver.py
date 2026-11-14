"""Deterministic resolution of trusted campus records using server-side authority rules.

Configure ``sources_by_domain`` in server-owned code or an injected trusted
configuration provider. For example, an IDENTITY domain may rank ``registrar``
at priority 0 and an import feed at priority 5, while DISCIPLINARY separately
ranks ``conduct-office`` at priority 0. Lower numeric priority is stronger;
rankings never cross domains. Configure ``max_age_by_domain`` for each sensitive
record domain. Resolution filters unauthorized, invalid, future, expired and
stale candidates, then compares authority, version, source update time, and
issuance time in that order. Equal-ranked contradictory candidates remain
unresolved and are denied or sent for verification according to policy.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Annotated, TypeAlias

from pydantic import AwareDatetime, Field, StrictInt, StrictStr, StringConstraints, TypeAdapter, model_validator

from .enums import (
    AccessDecision,
    AccessReasonCode,
    RecordDomain,
    RecordFreshness,
    RecordStatus,
    ResourceSensitivity,
)
from .schemas import (
    CampusRecord,
    CampusRoleRecord,
    DisciplinarySuspensionRecord,
    DomainModel,
    ExaminationEligibilityRecord,
    IdentityStatusRecord,
    Identifier,
    LabSafetyClearanceRecord,
    PermissionEffect,
    RecordProvenanceSummary,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
)

CampusRecordValue: TypeAlias = (
    IdentityStatusRecord
    | CampusRoleRecord
    | DisciplinarySuspensionRecord
    | ExaminationEligibilityRecord
    | LabSafetyClearanceRecord
    | ResourcePermissionRecord
    | RevocationStatusRecord
    | TemporaryLabPassRecord
)
PositiveDuration = Annotated[timedelta, Field(gt=timedelta(0))]
ScopePart = Annotated[StrictStr, StringConstraints(min_length=1)]


class SourceAuthorityRule(DomainModel):
    """Trusted configuration for one source within one record domain.

    A lower numeric priority is more authoritative. Priorities are only compared
    within the configured domain; they are never accepted from campus records.
    Equal priorities intentionally represent equal authority and can conflict.
    """

    source_id: Identifier
    priority: Annotated[StrictInt, Field(ge=0)]


class ConflictResolutionPolicy(DomainModel):
    """Injected server-side authority, freshness, and unresolved-conflict policy."""

    sources_by_domain: dict[RecordDomain, tuple[SourceAuthorityRule, ...]] = Field(default_factory=dict)
    max_age_by_domain: dict[RecordDomain, PositiveDuration] = Field(default_factory=dict)
    conflict_decision_by_sensitivity: dict[ResourceSensitivity, AccessDecision] = Field(default_factory=dict)
    maximum_future_skew: timedelta = Field(default=timedelta(0), ge=timedelta(0))

    @model_validator(mode="after")
    def configuration_must_be_unambiguous(self) -> "ConflictResolutionPolicy":
        for domain, rules in self.sources_by_domain.items():
            ids = [rule.source_id for rule in rules]
            if len(ids) != len(set(ids)):
                raise ValueError(f"source IDs must be unique within {domain.value}")
        if any(decision is AccessDecision.ALLOW for decision in self.conflict_decision_by_sensitivity.values()):
            raise ValueError("unresolved conflicts must never be configured to ALLOW")
        return self


class RecordTraceEntry(DomainModel):
    """Sanitized, stable trace of one considered record."""

    provenance: RecordProvenanceSummary
    domain: RecordDomain
    authority_priority: Annotated[StrictInt, Field(ge=0)] | None = None
    freshness: RecordFreshness
    freshness_age_seconds: Annotated[float, Field(ge=0)] | None = None
    considered: bool
    reason_codes: tuple[AccessReasonCode, ...] = ()


class RecordResolution(DomainModel):
    """Resolution for one subject and scope key."""

    domain: RecordDomain
    scope_key: tuple[ScopePart, ...] = Field(min_length=1)
    decision: AccessDecision
    winning_record: CampusRecordValue | None = None
    conflict: bool = False
    reason_codes: tuple[AccessReasonCode, ...] = Field(min_length=1)
    trace: tuple[RecordTraceEntry, ...] = ()

    @model_validator(mode="after")
    def decision_must_be_safe(self) -> "RecordResolution":
        if self.conflict and self.winning_record is not None:
            raise ValueError("an unresolved conflict cannot have a winning record")
        if self.decision is AccessDecision.ALLOW and self.winning_record is None:
            raise ValueError("ALLOW requires a winning record")
        return self


class RecordResolutionBatch(DomainModel):
    """Deterministically ordered resolutions for a single domain evaluation."""

    domain: RecordDomain
    evaluated_at: AwareDatetime
    resolutions: tuple[RecordResolution, ...]

    @property
    def winning_records(self) -> tuple[CampusRecordValue, ...]:
        return tuple(item.winning_record for item in self.resolutions if item.winning_record is not None)

    @property
    def has_unresolved_conflict(self) -> bool:
        return any(item.conflict for item in self.resolutions)


class CampusRecordConflictResolver:
    """Resolve records without relying on input order or caller-supplied authority."""

    def resolve(
        self,
        records: tuple[CampusRecordValue, ...],
        *,
        domain: RecordDomain,
        sensitivity: ResourceSensitivity,
        policy: ConflictResolutionPolicy,
        evaluated_at: datetime,
        expected_scope: tuple[str, ...] | None = None,
    ) -> RecordResolutionBatch:
        policy = ConflictResolutionPolicy.model_validate(policy)
        evaluated_at = TypeAdapter(AwareDatetime).validate_python(evaluated_at)
        groups: dict[tuple[str, ...], list[CampusRecordValue]] = {}
        for raw_record in records:
            record = type(raw_record).model_validate(raw_record)
            if self._domain_of(record) is not domain:
                raise ValueError("record type does not match requested record domain")
            groups.setdefault(self._scope_key(record), []).append(record)

        if not groups:
            if not expected_scope:
                raise ValueError("expected_scope is required when resolving an empty record set")
            return RecordResolutionBatch(
                domain=domain,
                evaluated_at=evaluated_at,
                resolutions=(
                    RecordResolution(
                        domain=domain,
                        scope_key=expected_scope,
                        decision=AccessDecision.DENY,
                        reason_codes=(AccessReasonCode.AUTHORITATIVE_SOURCE_MISSING,),
                    ),
                ),
            )

        resolutions = [
            self._resolve_group(
                group,
                domain=domain,
                sensitivity=sensitivity,
                policy=policy,
                evaluated_at=evaluated_at,
            )
            for _, group in sorted(groups.items())
        ]
        return RecordResolutionBatch(
            domain=domain,
            evaluated_at=evaluated_at,
            resolutions=tuple(resolutions),
        )

    @staticmethod
    def _domain_of(record: CampusRecord) -> RecordDomain:
        mapping = {
            IdentityStatusRecord: RecordDomain.IDENTITY,
            CampusRoleRecord: RecordDomain.ROLE,
            ResourcePermissionRecord: RecordDomain.PERMISSION,
            DisciplinarySuspensionRecord: RecordDomain.DISCIPLINARY,
            ExaminationEligibilityRecord: RecordDomain.EXAMINATION,
            TemporaryLabPassRecord: RecordDomain.TEMPORARY_PASS,
            LabSafetyClearanceRecord: RecordDomain.SAFETY_CLEARANCE,
            RevocationStatusRecord: RecordDomain.REVOCATION,
        }
        for record_type, record_domain in mapping.items():
            if isinstance(record, record_type):
                return record_domain
        raise TypeError(f"unsupported campus record type: {type(record).__name__}")

    @staticmethod
    def _scope_key(record: CampusRecord) -> tuple[str, ...]:
        values: list[str] = [record.subject_id]
        if isinstance(record, ResourcePermissionRecord):
            values.extend(("resources", *sorted(record.resource_ids), "actions", *sorted(record.action_ids)))
        elif isinstance(record, DisciplinarySuspensionRecord):
            values.extend(("resources", *(sorted(record.resource_ids) or ("*",))))
        elif isinstance(record, ExaminationEligibilityRecord):
            values.append(record.exam_id)
        elif isinstance(record, TemporaryLabPassRecord):
            values.extend((record.resource_id, "actions", *sorted(record.action_ids), record.purpose_id or "<NO_PURPOSE>"))
        elif isinstance(record, LabSafetyClearanceRecord):
            values.extend((record.resource_id, "requirements", *sorted(record.requirement_ids)))
        elif isinstance(record, RevocationStatusRecord):
            values.append(record.resource_id or "*")
        elif isinstance(record, CampusRoleRecord):
            values.extend(sorted(role.value for role in record.roles))
        return tuple(values)

    @staticmethod
    def _semantic_value(record: CampusRecord) -> str:
        # Provenance identifiers do not change the claim represented by a record.
        return json.dumps(
            record.model_dump(mode="json", exclude={"record_id", "source_id"}),
            sort_keys=True,
            separators=(",", ":"),
        )

    def _resolve_group(self, records, *, domain, sensitivity, policy, evaluated_at) -> RecordResolution:
        source_rules = {rule.source_id: rule.priority for rule in policy.sources_by_domain.get(domain, ())}
        all_known_sources = {
            rule.source_id
            for rules in policy.sources_by_domain.values()
            for rule in rules
        }
        max_age = policy.max_age_by_domain.get(domain)
        trace: list[RecordTraceEntry] = []
        eligible: list[tuple[int, CampusRecordValue]] = []
        rejected: list[tuple[int | None, set[AccessReasonCode]]] = []
        for record in records:
            priority = source_rules.get(record.source_id)
            item_reasons: set[AccessReasonCode] = set()
            age = (evaluated_at - record.observed_at).total_seconds()
            if record.issued_at > evaluated_at + policy.maximum_future_skew or record.source_updated_at > evaluated_at + policy.maximum_future_skew or record.observed_at > evaluated_at + policy.maximum_future_skew:
                freshness = RecordFreshness.FUTURE_DATED
                item_reasons.add(AccessReasonCode.RECORD_FUTURE_DATED)
            elif record.source_updated_at < record.issued_at:
                freshness = RecordFreshness.INVALID
                item_reasons.add(AccessReasonCode.RECORD_INVALID)
            elif max_age is None:
                freshness = RecordFreshness.NOT_CONFIGURED
                if sensitivity in {ResourceSensitivity.HIGH, ResourceSensitivity.CRITICAL}:
                    item_reasons.add(AccessReasonCode.RECORD_FRESHNESS_UNCONFIGURED)
            elif evaluated_at - record.source_updated_at > max_age:
                freshness = RecordFreshness.STALE
                item_reasons.add(AccessReasonCode.RECORD_STALE)
            else:
                freshness = RecordFreshness.FRESH

            if priority is None:
                item_reasons.add(
                    AccessReasonCode.RECORD_SOURCE_UNAUTHORIZED
                    if record.source_id in all_known_sources
                    else AccessReasonCode.RECORD_SOURCE_UNKNOWN
                )
            if record.valid_until is not None and evaluated_at >= record.valid_until:
                item_reasons.add(AccessReasonCode.RECORD_EXPIRED)
            elif evaluated_at < record.valid_from:
                item_reasons.add(AccessReasonCode.RECORD_NOT_YET_VALID)

            considered = priority is not None and not item_reasons
            trace.append(
                RecordTraceEntry(
                    provenance=RecordProvenanceSummary(
                        record_id=record.record_id,
                        source_id=record.source_id,
                        version=record.version,
                        observed_at=record.observed_at,
                        status=record.status,
                    ),
                    domain=domain,
                    authority_priority=priority,
                    freshness=freshness,
                    freshness_age_seconds=max(age, 0.0) if age >= 0 else None,
                    considered=considered,
                    reason_codes=tuple(sorted(item_reasons, key=lambda code: code.value)),
                )
            )
            if considered:
                eligible.append((priority, record))
            else:
                rejected.append((priority, item_reasons))

        scope_key = self._scope_key(records[0])
        if not eligible:
            reasons = {code for _, rejected_reasons in rejected for code in rejected_reasons}
            if not any(code in reasons for code in (AccessReasonCode.RECORD_SOURCE_UNKNOWN, AccessReasonCode.RECORD_SOURCE_UNAUTHORIZED)):
                reasons.add(AccessReasonCode.AUTHORITATIVE_SOURCE_MISSING)
            return RecordResolution(
                domain=domain,
                scope_key=scope_key,
                decision=AccessDecision.DENY,
                conflict=False,
                reason_codes=tuple(sorted(reasons, key=lambda code: code.value)),
                trace=tuple(sorted(trace, key=self._trace_key)),
            )

        best_priority = min(priority for priority, _ in eligible)
        blocking_data_reasons = {
            AccessReasonCode.RECORD_STALE,
            AccessReasonCode.RECORD_FUTURE_DATED,
            AccessReasonCode.RECORD_INVALID,
            AccessReasonCode.RECORD_FRESHNESS_UNCONFIGURED,
        }
        authoritative_data_issues = {
            code
            for priority, rejected_reasons in rejected
            if priority is not None and priority <= best_priority
            for code in rejected_reasons
            if code in blocking_data_reasons
        }
        if authoritative_data_issues:
            return RecordResolution(
                domain=domain,
                scope_key=scope_key,
                decision=AccessDecision.DENY,
                conflict=False,
                reason_codes=tuple(sorted(authoritative_data_issues, key=lambda code: code.value)),
                trace=tuple(sorted(trace, key=self._trace_key)),
            )

        best_records = [record for priority, record in eligible if priority == best_priority]
        max_version = max(record.version for record in best_records)
        best_records = [record for record in best_records if record.version == max_version]
        newest_update = max(record.source_updated_at for record in best_records)
        best_records = [record for record in best_records if record.source_updated_at == newest_update]
        newest_issue = max(record.issued_at for record in best_records)
        best_records = [record for record in best_records if record.issued_at == newest_issue]
        semantic_values = {self._semantic_value(record) for record in best_records}
        if len(semantic_values) > 1:
            configured = policy.conflict_decision_by_sensitivity.get(sensitivity, AccessDecision.DENY)
            reasons = {AccessReasonCode.RECORD_CONFLICT}
            return RecordResolution(
                domain=domain,
                scope_key=scope_key,
                decision=configured,
                conflict=True,
                reason_codes=tuple(sorted(reasons, key=lambda code: code.value)),
                trace=tuple(sorted(trace, key=self._trace_key)),
            )

        winner = min(best_records, key=lambda record: record.record_id)
        reasons: set[AccessReasonCode] = set()
        if (
            winner.status is RecordStatus.REVOKED
            or isinstance(winner, RevocationStatusRecord) and winner.revocation_state.value == "REVOKED"
        ):
            decision = AccessDecision.DENY
            reasons.add(AccessReasonCode.RECORD_REVOKED)
        elif (
            winner.status in {RecordStatus.EXPIRED, RecordStatus.INACTIVE, RecordStatus.BLOCKED, RecordStatus.SUSPENDED}
            or isinstance(winner, DisciplinarySuspensionRecord) and winner.status is RecordStatus.ACTIVE
            or isinstance(winner, ResourcePermissionRecord) and winner.effect is PermissionEffect.DENY
            or isinstance(winner, ExaminationEligibilityRecord) and not winner.eligible
            or isinstance(winner, LabSafetyClearanceRecord) and not winner.cleared
        ):
            decision = AccessDecision.DENY
            reasons.add(AccessReasonCode.RECORD_STATUS_DENIED)
        else:
            decision = AccessDecision.ALLOW
            reasons.add(AccessReasonCode.ACCESS_POLICY_SATISFIED)
        return RecordResolution(
            domain=domain,
            scope_key=scope_key,
            decision=decision,
            winning_record=winner,
            conflict=False,
            reason_codes=tuple(sorted(reasons, key=lambda code: code.value)),
            trace=tuple(sorted(trace, key=self._trace_key)),
        )

    @staticmethod
    def _trace_key(entry: RecordTraceEntry) -> tuple:
        return (entry.authority_priority is None, entry.authority_priority or 0, entry.provenance.source_id, entry.provenance.version, entry.provenance.record_id)
