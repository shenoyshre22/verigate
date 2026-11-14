"""Deterministic campus-record authorization independent of HTTP and persistence."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated

from pydantic import Field, StrictBool, StringConstraints, model_validator

from .enums import (
    AccessReasonCode,
    CampusRole,
    PermissionEffect,
    RecordStatus,
    ResourceSensitivity,
    RevocationState,
)
from .schemas import (
    AccessRequest,
    CampusRecord,
    CampusRoleRecord,
    DisciplinarySuspensionRecord,
    DomainModel,
    EvaluationContext,
    ExaminationEligibilityRecord,
    Identifier,
    IdentityStatusRecord,
    LabSafetyClearanceRecord,
    RecordProvenanceSummary,
    ResourcePermissionRecord,
    RevocationStatusRecord,
    TemporaryLabPassRecord,
)


PositiveDuration = Annotated[timedelta, Field(gt=timedelta(0))]
_NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class RoleRequirement(DomainModel):
    """Server-side role rule for one exact resource/action pair."""

    resource_id: Identifier
    action_id: Identifier
    allowed_roles: tuple[CampusRole, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def roles_must_be_unique(self) -> "RoleRequirement":
        if len(set(self.allowed_roles)) != len(self.allowed_roles):
            raise ValueError("allowed_roles must not contain duplicates")
        return self


class AuthorizationPolicy(DomainModel):
    """Explicit resource policy configuration; it contains no campus-specific defaults."""

    role_requirements: tuple[RoleRequirement, ...] = ()
    required_safety_by_resource: dict[Identifier, tuple[Identifier, ...]] = {}
    trusted_temporary_pass_sources: tuple[Identifier, ...] = ()
    temporary_pass_required_resources: tuple[Identifier, ...] = ()
    require_fresh_revocation_for: tuple[ResourceSensitivity, ...] = (
        ResourceSensitivity.HIGH,
        ResourceSensitivity.CRITICAL,
    )
    revocation_max_age_by_sensitivity: dict[ResourceSensitivity, PositiveDuration] = {}
    exam_action_id: Identifier = "TAKE_EXAM"

    @model_validator(mode="after")
    def configured_scopes_must_be_unambiguous(self) -> "AuthorizationPolicy":
        role_scopes = [(rule.resource_id, rule.action_id) for rule in self.role_requirements]
        if len(set(role_scopes)) != len(role_scopes):
            raise ValueError("role_requirements must have one rule per resource/action pair")
        for resource_id, requirement_ids in self.required_safety_by_resource.items():
            if not resource_id.strip() or not requirement_ids:
                raise ValueError("safety policy scopes and requirement lists must be non-empty")
            if len(set(requirement_ids)) != len(requirement_ids):
                raise ValueError("safety requirement IDs must not contain duplicates")
        if len(set(self.trusted_temporary_pass_sources)) != len(self.trusted_temporary_pass_sources):
            raise ValueError("trusted_temporary_pass_sources must not contain duplicates")
        if len(set(self.temporary_pass_required_resources)) != len(self.temporary_pass_required_resources):
            raise ValueError("temporary_pass_required_resources must not contain duplicates")
        if len(set(self.require_fresh_revocation_for)) != len(self.require_fresh_revocation_for):
            raise ValueError("require_fresh_revocation_for must not contain duplicates")
        return self


class AuthorizationSnapshot(DomainModel):
    """Trusted, provider-resolved records for one evaluation; never accept this from an API caller."""

    identities: tuple[IdentityStatusRecord, ...] = ()
    role_assignments: tuple[CampusRoleRecord, ...] = ()
    permissions: tuple[ResourcePermissionRecord, ...] = ()
    suspensions: tuple[DisciplinarySuspensionRecord, ...] = ()
    examinations: tuple[ExaminationEligibilityRecord, ...] = ()
    temporary_lab_passes: tuple[TemporaryLabPassRecord, ...] = ()
    safety_clearances: tuple[LabSafetyClearanceRecord, ...] = ()
    revocations: tuple[RevocationStatusRecord, ...] = ()


class AuthorizationEvaluationResult(DomainModel):
    request_id: str
    user_id: Identifier
    resource_id: Identifier
    permitted: StrictBool
    reason_codes: tuple[AccessReasonCode, ...] = Field(min_length=1)
    explanation: _NonEmptyText
    record_provenance: tuple[RecordProvenanceSummary, ...] = ()

    @model_validator(mode="after")
    def permitted_must_match_reason_codes(self) -> "AuthorizationEvaluationResult":
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("reason_codes must not contain duplicates")
        policy_passed = self.reason_codes == (AccessReasonCode.ACCESS_POLICY_SATISFIED,)
        if self.permitted != policy_passed:
            raise ValueError("permitted must be true only when all authorization checks passed")
        return self


class CampusAuthorizationEvaluator:
    """Evaluate trusted campus records against one request and server policy snapshot."""

    def evaluate(
        self,
        request: AccessRequest,
        snapshot: AuthorizationSnapshot,
        policy: AuthorizationPolicy,
        context: EvaluationContext,
    ) -> AuthorizationEvaluationResult:
        request = AccessRequest.model_validate(request)
        snapshot = AuthorizationSnapshot.model_validate(snapshot)
        policy = AuthorizationPolicy.model_validate(policy)
        context = EvaluationContext.model_validate(context)
        if request.request_id != context.request_id:
            raise ValueError("evaluation context request_id must match access request request_id")

        now = context.evaluated_at
        user_id = request.user_id
        resource_id = request.resource.resource_id
        action_id = request.action.action_id
        reason_codes: set[AccessReasonCode] = set()
        provenance: dict[tuple[str, str, int], RecordProvenanceSummary] = {}

        self._check_identity(snapshot, user_id, now, reason_codes, provenance)
        self._check_suspensions(snapshot, user_id, resource_id, now, reason_codes, provenance)
        self._check_revocation(
            snapshot,
            user_id,
            resource_id,
            context.resource_sensitivity,
            policy,
            now,
            reason_codes,
            provenance,
        )

        active_roles = self._active_roles(snapshot, user_id, now, provenance)
        self._check_role_requirements(
            policy,
            resource_id,
            action_id,
            active_roles,
            reason_codes,
        )

        active_permission, permission_reasons = self._check_permissions(
            snapshot,
            user_id,
            resource_id,
            action_id,
            now,
            provenance,
        )
        reason_codes.update(permission_reasons)

        exam_grant, exam_required, exam_reasons = self._check_examination(
            snapshot,
            request,
            policy,
            now,
            provenance,
        )
        reason_codes.update(exam_reasons)

        pass_grant, pass_reasons = self._check_temporary_passes(
            snapshot,
            request,
            policy,
            now,
            provenance,
        )
        pass_required = resource_id in policy.temporary_pass_required_resources
        if pass_required and not pass_grant and not pass_reasons:
            pass_reasons.add(AccessReasonCode.TEMPORARY_PASS_INVALID)
        if pass_required:
            reason_codes.update(pass_reasons)
        elif not active_permission and not exam_grant and not pass_grant:
            reason_codes.update(pass_reasons)

        safety_reasons = self._check_safety_clearances(
            snapshot,
            user_id,
            resource_id,
            policy,
            now,
            provenance,
        )
        reason_codes.update(safety_reasons)

        has_explicit_grant = active_permission or exam_grant or pass_grant
        if not has_explicit_grant and not reason_codes.intersection(permission_reasons):
            reason_codes.add(AccessReasonCode.PERMISSION_NOT_FOUND)
        if not reason_codes:
            reason_codes.add(AccessReasonCode.ACCESS_POLICY_SATISFIED)

        ordered_reasons = tuple(sorted(reason_codes, key=lambda reason: reason.value))
        permitted = ordered_reasons == (AccessReasonCode.ACCESS_POLICY_SATISFIED,)
        ordered_provenance = tuple(
            provenance[key]
            for key in sorted(provenance)
        )
        explanation = (
            "All configured campus authorization checks passed."
            if permitted
            else "Campus authorization denied: " + ", ".join(reason.value for reason in ordered_reasons)
        )
        return AuthorizationEvaluationResult(
            request_id=request.request_id,
            user_id=request.user_id,
            resource_id=request.resource.resource_id,
            permitted=permitted,
            reason_codes=ordered_reasons,
            explanation=explanation,
            record_provenance=ordered_provenance,
        )

    @staticmethod
    def _record_provenance(
        record: CampusRecord,
        provenance: dict[tuple[str, str, int], RecordProvenanceSummary],
    ) -> None:
        summary = RecordProvenanceSummary(
            record_id=record.record_id,
            source_id=record.source_id,
            version=record.version,
            observed_at=record.observed_at,
            status=record.status,
        )
        provenance[(record.record_id, record.source_id, record.version)] = summary

    @staticmethod
    def _date_state(record: CampusRecord, now: datetime) -> str:
        if record.valid_until is not None and now >= record.valid_until:
            return "EXPIRED"
        if now < record.valid_from:
            return "NOT_YET_VALID"
        return "IN_WINDOW"

    def _check_identity(self, snapshot, user_id, now, reasons, provenance) -> None:
        records = [record for record in snapshot.identities if record.subject_id == user_id]
        if not records:
            reasons.add(AccessReasonCode.IDENTITY_INVALID)
            return
        if len(records) != 1:
            reasons.add(AccessReasonCode.RECORD_CONFLICT)
            for record in records:
                self._record_provenance(record, provenance)
            return

        record = records[0]
        self._record_provenance(record, provenance)
        date_state = self._date_state(record, now)
        if date_state == "EXPIRED" or record.status is RecordStatus.EXPIRED:
            reasons.add(AccessReasonCode.IDENTITY_EXPIRED)
        elif date_state == "NOT_YET_VALID":
            reasons.add(AccessReasonCode.IDENTITY_NOT_YET_VALID)
        elif record.status is RecordStatus.ACTIVE:
            return
        elif record.status is RecordStatus.INACTIVE:
            reasons.add(AccessReasonCode.IDENTITY_INACTIVE)
        elif record.status is RecordStatus.BLOCKED:
            reasons.add(AccessReasonCode.IDENTITY_BLOCKED)
        elif record.status is RecordStatus.SUSPENDED:
            reasons.add(AccessReasonCode.IDENTITY_SUSPENDED)
        elif record.status is RecordStatus.REVOKED:
            reasons.add(AccessReasonCode.IDENTITY_REVOKED)
        else:
            reasons.add(AccessReasonCode.IDENTITY_INVALID)

    def _check_suspensions(self, snapshot, user_id, resource_id, now, reasons, provenance) -> None:
        for record in snapshot.suspensions:
            if record.subject_id != user_id:
                continue
            if record.resource_ids and resource_id not in record.resource_ids:
                continue
            if record.status not in {RecordStatus.ACTIVE, RecordStatus.SUSPENDED}:
                continue
            if self._date_state(record, now) != "IN_WINDOW":
                continue
            self._record_provenance(record, provenance)
            reasons.add(AccessReasonCode.IDENTITY_SUSPENDED)

    def _check_revocation(
        self,
        snapshot,
        user_id,
        resource_id,
        sensitivity,
        policy,
        now,
        reasons,
        provenance,
    ) -> None:
        records = [
            record
            for record in snapshot.revocations
            if record.subject_id == user_id
            and (record.resource_id is None or record.resource_id == resource_id)
        ]
        for record in records:
            self._record_provenance(record, provenance)
            if record.revocation_state is RevocationState.REVOKED:
                reasons.add(AccessReasonCode.IDENTITY_REVOKED)

        if any(record.revocation_state is RevocationState.REVOKED for record in records):
            return

        must_check = sensitivity in policy.require_fresh_revocation_for
        max_age = policy.revocation_max_age_by_sensitivity.get(sensitivity)
        if not must_check and max_age is None:
            return
        if max_age is None:
            reasons.add(AccessReasonCode.REVOCATION_UNAVAILABLE)
            return

        fresh_clear = [
            record
            for record in records
            if record.revocation_state is RevocationState.CLEAR
            and record.status is RecordStatus.ACTIVE
            and self._date_state(record, now) == "IN_WINDOW"
            and timedelta(0) <= now - record.observed_at <= max_age
        ]
        if fresh_clear:
            return
        if records:
            reasons.add(AccessReasonCode.REVOCATION_STALE)
        else:
            reasons.add(AccessReasonCode.REVOCATION_UNAVAILABLE)

    def _active_roles(self, snapshot, user_id, now, provenance) -> set[CampusRole]:
        roles: set[CampusRole] = set()
        for record in snapshot.role_assignments:
            if record.subject_id != user_id:
                continue
            self._record_provenance(record, provenance)
            if record.status is RecordStatus.ACTIVE and self._date_state(record, now) == "IN_WINDOW":
                roles.update(record.roles)
        return roles

    @staticmethod
    def _check_role_requirements(policy, resource_id, action_id, active_roles, reasons) -> None:
        requirement = next(
            (
                item
                for item in policy.role_requirements
                if item.resource_id == resource_id and item.action_id == action_id
            ),
            None,
        )
        if requirement is not None and not set(requirement.allowed_roles).intersection(active_roles):
            reasons.add(AccessReasonCode.ROLE_NOT_AUTHORIZED)

    def _check_permissions(self, snapshot, user_id, resource_id, action_id, now, provenance):
        matching = [
            record
            for record in snapshot.permissions
            if record.subject_id == user_id
            and resource_id in record.resource_ids
            and action_id in record.action_ids
        ]
        grants = False
        reasons: set[AccessReasonCode] = set()
        for record in matching:
            self._record_provenance(record, provenance)
            if record.status is RecordStatus.REVOKED:
                reasons.add(AccessReasonCode.PERMISSION_REVOKED)
                continue
            date_state = self._date_state(record, now)
            if date_state == "EXPIRED" or record.status is RecordStatus.EXPIRED:
                reasons.add(AccessReasonCode.PERMISSION_EXPIRED)
                continue
            if date_state == "NOT_YET_VALID":
                reasons.add(AccessReasonCode.PERMISSION_NOT_YET_VALID)
                continue
            if record.status is not RecordStatus.ACTIVE:
                continue
            if record.effect is PermissionEffect.DENY:
                reasons.add(AccessReasonCode.PERMISSION_DENIED)
            else:
                grants = True
        return grants, reasons

    def _check_examination(self, snapshot, request, policy, now, provenance):
        exam_id = request.action.exam_id
        is_exam = exam_id is not None or request.action.action_id == policy.exam_action_id
        if not is_exam:
            return False, False, set()
        if exam_id is None:
            return False, True, {AccessReasonCode.EXAMINATION_NOT_FOUND}

        records = [
            record
            for record in snapshot.examinations
            if record.subject_id == request.user_id and record.exam_id == exam_id
        ]
        if not records:
            return False, True, {AccessReasonCode.EXAMINATION_NOT_FOUND}
        if len(records) != 1:
            for record in records:
                self._record_provenance(record, provenance)
            return False, True, {AccessReasonCode.RECORD_CONFLICT}

        record = records[0]
        self._record_provenance(record, provenance)
        reasons: set[AccessReasonCode] = set()
        date_state = self._date_state(record, now)
        if record.status is not RecordStatus.ACTIVE or date_state != "IN_WINDOW":
            if date_state == "NOT_YET_VALID":
                reasons.add(AccessReasonCode.EXAM_NOT_ELIGIBLE)
            else:
                reasons.add(AccessReasonCode.EXAM_NOT_ELIGIBLE)
            return False, True, reasons
        if not record.eligible:
            reasons.add(AccessReasonCode.EXAM_NOT_ELIGIBLE)
        if request.resource.resource_id not in record.resource_ids:
            reasons.add(AccessReasonCode.EXAMINATION_LOCATION_MISMATCH)
        if not any(window.starts_at <= now < window.ends_at for window in record.schedule):
            reasons.add(AccessReasonCode.OUTSIDE_EXAM_SCHEDULE)
        return not reasons, True, reasons

    def _check_temporary_passes(self, snapshot, request, policy, now, provenance):
        records = [
            record for record in snapshot.temporary_lab_passes if record.subject_id == request.user_id
        ]
        matching_resource_action = [
            record
            for record in records
            if record.resource_id == request.resource.resource_id
            and request.action.action_id in record.action_ids
        ]
        reasons: set[AccessReasonCode] = set()
        for record in matching_resource_action:
            self._record_provenance(record, provenance)
            if record.status is RecordStatus.REVOKED:
                reasons.add(AccessReasonCode.TEMPORARY_PASS_REVOKED)
                continue
            date_state = self._date_state(record, now)
            if date_state == "EXPIRED" or record.status is RecordStatus.EXPIRED:
                reasons.add(AccessReasonCode.TEMPORARY_PASS_EXPIRED)
                continue
            if date_state == "NOT_YET_VALID":
                reasons.add(AccessReasonCode.TEMPORARY_PASS_NOT_YET_VALID)
                continue
            if record.status is not RecordStatus.ACTIVE:
                continue
            if record.source_id not in policy.trusted_temporary_pass_sources:
                reasons.add(AccessReasonCode.TEMPORARY_PASS_ISSUER_UNTRUSTED)
                continue
            if request.action.purpose_id is None or record.purpose_id != request.action.purpose_id:
                reasons.add(AccessReasonCode.TEMPORARY_PASS_INVALID)
                continue
            return True, set()

        # A pass for another lab/action is never treated as a general permission.
        if not matching_resource_action and records:
            reasons.add(AccessReasonCode.TEMPORARY_PASS_INVALID)
        return False, reasons

    def _check_safety_clearances(self, snapshot, user_id, resource_id, policy, now, provenance):
        required = policy.required_safety_by_resource.get(resource_id, ())
        if not required:
            return set()

        applicable = [
            record
            for record in snapshot.safety_clearances
            if record.subject_id == user_id and record.resource_id == resource_id
        ]
        completed: set[str] = set()
        expired_requirements: set[str] = set()
        future_requirements: set[str] = set()
        incomplete_requirements: set[str] = set()
        for record in applicable:
            self._record_provenance(record, provenance)
            date_state = self._date_state(record, now)
            if date_state == "EXPIRED" or record.status is RecordStatus.EXPIRED:
                expired_requirements.update(record.requirement_ids)
                continue
            if date_state == "NOT_YET_VALID":
                future_requirements.update(record.requirement_ids)
                continue
            if record.status is not RecordStatus.ACTIVE:
                continue
            if not record.cleared:
                incomplete_requirements.update(record.requirement_ids)
                continue
            completed.update(record.requirement_ids)

        missing = set(required) - completed
        reasons: set[AccessReasonCode] = set()
        if missing & expired_requirements:
            reasons.add(AccessReasonCode.SAFETY_CLEARANCE_EXPIRED)
        if missing & future_requirements:
            reasons.add(AccessReasonCode.SAFETY_CLEARANCE_NOT_YET_VALID)
        if missing & incomplete_requirements:
            reasons.add(AccessReasonCode.SAFETY_TRAINING_INCOMPLETE)
        if missing and not reasons:
            reasons.add(AccessReasonCode.LAB_SAFETY_CLEARANCE_REQUIRED)
        return reasons
