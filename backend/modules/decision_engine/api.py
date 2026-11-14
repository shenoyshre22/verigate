"""HTTP routes for the zero-trust decision engine.

POST /decision/evaluate      context-aware access: campus records + evidence -> ALLOW / REQUEST_VERIFICATION / DENY
POST /decision/offline-sync  kiosk uploads decisions it made offline; each is audited as mode="offline-synced"

Fail-closed everywhere: if campus records cannot be read the answer is DENY, and an ALLOW is never
returned without an audit record. Requests carrying image or template fields are rejected outright.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .audit_store import AuditLog
from .context_loader import ContextLoader, normalize_room, parse_ts
from .engine import ALLOW, DENY, Decision, Evidence, decide
from .liveness import SESSION_ID_PATTERN, LivenessVerifier, client_evidence_allowed

SERVER, CLIENT, ABSENT = "server-verified", "client-reported", "absent"

log = logging.getLogger(__name__)
router = APIRouter(prefix="/decision", tags=["decision-engine"])

FORBIDDEN_KEY_PARTS = ("image", "template", "embedding", "photo", "selfie", "vector", "biometric")
MAX_FUTURE_SKEW = timedelta(minutes=5)
def _id() -> Any:
    return Field(default=None, min_length=1, max_length=64)


def _find_forbidden(data: Any, path: str = "") -> Optional[str]:
    if isinstance(data, dict):
        for k, v in data.items():
            key = str(k).lower()
            if any(part in key for part in FORBIDDEN_KEY_PARTS):
                return f"{path}{k}"
            hit = _find_forbidden(v, f"{path}{k}.")
            if hit:
                return hit
    elif isinstance(data, list):
        for i, v in enumerate(data):
            hit = _find_forbidden(v, f"{path}{i}.")
            if hit:
                return hit
    return None


class _NoBiometrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _reject_biometric_fields(cls, data: Any) -> Any:
        hit = _find_forbidden(data)
        if hit:
            raise ValueError(f"biometric data is not accepted by this API (field '{hit}')")
        return data


# --- request / response models ------------------------------------------------
class EvidenceIn(_NoBiometrics):
    liveness_session_id: Optional[str] = Field(default=None, pattern=SESSION_ID_PATTERN)
    liveness: Optional[float] = Field(default=None, ge=0, le=100)  # only with ALLOW_CLIENT_EVIDENCE=true
    liveness_status: Optional[Literal["LIVE", "SPOOF", "UNCERTAIN"]] = None  # same rule as liveness
    face_person_id: Optional[str] = _id()
    face_similarity: Optional[float] = Field(default=None, ge=0, le=100)
    fingerprint_match: Optional[bool] = None
    challenge_passed: Optional[bool] = None


class EvaluateRequest(_NoBiometrics):
    person_id: Optional[str] = _id()
    rfid_card_id: Optional[str] = _id()
    room_id: str = Field(min_length=1, max_length=64)
    online: bool = True
    evidence: EvidenceIn = Field(default_factory=EvidenceIn)

    @model_validator(mode="after")
    def _needs_identity(self) -> "EvaluateRequest":
        if not (self.person_id or self.rfid_card_id):
            raise ValueError("person_id or rfid_card_id is required")
        return self


class EvaluateResponse(BaseModel):
    attempt_id: str
    decision: str
    reasons: list[str]
    mode: str
    decision_ms: float
    audited: bool


class OfflineDecisionIn(_NoBiometrics):
    attempt_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    room_id: str = Field(min_length=1, max_length=64)
    person_id: Optional[str] = _id()
    rfid_card_id: Optional[str] = _id()
    decision: Literal["ALLOW", "REQUEST_VERIFICATION", "DENY"]
    decided_at: datetime
    reasons: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("decided_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("decided_at must include a timezone")
        return v.astimezone(timezone.utc)

    @field_validator("reasons")
    @classmethod
    def _short_reasons(cls, v: list[str]) -> list[str]:
        return [r[:200] for r in v]


class OfflineSyncRequest(_NoBiometrics):
    kiosk_id: str = Field(min_length=1, max_length=64)
    cache_version: Optional[int] = None
    decisions: list[OfflineDecisionIn] = Field(min_length=1, max_length=100)


class OfflineSyncResponse(BaseModel):
    synced: list[str]
    duplicates: list[str]
    rejected: list[dict]
    flagged: list[dict]
    failed: list[str]


# --- dependencies (overridden in tests) --------------------------------------
_loader: Optional[ContextLoader] = None
_audit: Optional[AuditLog] = None


def get_loader() -> ContextLoader:
    global _loader
    if _loader is None:
        _loader = ContextLoader()
    return _loader


def get_audit_log() -> AuditLog:
    global _audit
    if _audit is None:
        _audit = AuditLog()
    return _audit


_liveness: Optional[LivenessVerifier] = None


def get_liveness_verifier() -> LivenessVerifier:
    global _liveness
    if _liveness is None:
        _liveness = LivenessVerifier()
    return _liveness


def get_clock() -> Callable[[], datetime]:
    return lambda: datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- routes ---------------------------------------------------------------------
@router.post("/evaluate", response_model=EvaluateResponse)
def evaluate(
    req: EvaluateRequest,
    loader: ContextLoader = Depends(get_loader),
    audit: AuditLog = Depends(get_audit_log),
    verifier: LivenessVerifier = Depends(get_liveness_verifier),
    clock: Callable[[], datetime] = Depends(get_clock),
) -> EvaluateResponse:
    ein = req.evidence
    client_liveness = ein.liveness is not None or ein.liveness_status is not None
    if client_liveness and not ein.liveness_session_id and not client_evidence_allowed():
        raise HTTPException(status_code=422, detail="client-reported liveness is not accepted; "
                                                    "send evidence.liveness_session_id instead")
    started = time.perf_counter()
    now = clock()
    attempt_id = uuid.uuid4().hex
    room = normalize_room(req.room_id)
    mode_if_error = "online" if req.online else "offline"
    person_id = req.person_id
    notes: list[str] = []

    # Liveness: the server's own Rekognition lookup wins; client numbers only when explicitly allowed.
    liveness, liveness_src, liveness_status, reused = None, ABSENT, None, False
    if ein.liveness_session_id:
        try:
            first_use = audit.claim_liveness_session(ein.liveness_session_id, now)
        except Exception:  # noqa: BLE001 - cannot rule out replay, so the session is not trusted
            log.exception("liveness replay check failed for attempt %s", attempt_id)
            first_use, liveness_status = None, "REPLAY_CHECK_UNAVAILABLE"
            notes.append("liveness replay check unavailable")
        if first_use is False:
            reused, liveness_status = True, "REUSED"
        elif first_use:
            res = verifier.check(ein.liveness_session_id)
            liveness_status = res.status
            if res.confidence is not None:
                liveness, liveness_src = res.confidence, SERVER
            if res.note:
                notes.append(res.note)
        if client_liveness:
            notes.append("client-reported liveness ignored; server lookup used")
    elif client_liveness:
        liveness, liveness_src = ein.liveness, CLIENT
        liveness_status = ein.liveness_status

    evidence_used = {
        "liveness": liveness,
        "liveness_status": liveness_status if liveness_src == CLIENT else None,
        "face_person_id": ein.face_person_id,
        "face_similarity": ein.face_similarity,
        "fingerprint_match": ein.fingerprint_match,
        "challenge_passed": ein.challenge_passed,
    }
    sources = {k: (CLIENT if v is not None else ABSENT) for k, v in evidence_used.items()}
    sources["liveness"] = liveness_src
    sources["liveness_status"] = liveness_src if evidence_used["liveness_status"] else ABSENT
    context_summary: dict = {}

    try:
        loaded = loader.load(room_id=room, person_id=req.person_id, rfid_card_id=req.rfid_card_id,
                             online=req.online, now=now)
        person_id = loaded.person_id or req.person_id
        c, rec = loaded.context, loaded.reconciliation
        context_summary = {
            "status": c.person.get("status") if c.person else None,
            "status_sources": list(rec.sources) if rec else [],
            "records_conflict": c.records_conflict,
            "schedule_ok": c.schedule_ok, "temp_pass_valid": c.temp_pass_valid, "pass_required": c.pass_required,
            "safety_training_required": c.safety_training_required, "safety_training_valid": c.safety_training_valid,
            "revoked": c.revoked, "revocation_fresh": c.revocation_fresh, "card_issuer": loaded.card_issuer,
            "records_fresh": c.records_fresh, "room_sensitive": c.room_sensitive,
        }
        sources["rfid_person_id"] = SERVER if req.rfid_card_id else ABSENT  # resolved from campus records
        ev = Evidence(**evidence_used, rfid_person_id=loaded.card_person_id, liveness_session_reused=reused)
        result = decide(ev, loaded.context)
    except Exception:  # noqa: BLE001 - any failure to read records must fail closed
        log.exception("campus records unavailable for attempt %s", attempt_id)
        result = Decision(DENY, ["campus records unavailable; failing closed"], mode_if_error)
    if notes:
        result = Decision(result.decision, list(result.reasons) + notes, result.mode)
    decision_ms = round((time.perf_counter() - started) * 1000, 2)

    record = {
        "attempt_id": attempt_id,
        "room_id": room,
        "person_id": person_id,
        "rfid_card_id": req.rfid_card_id,
        "decision": result.decision,
        "reasons": list(result.reasons),
        "mode": result.mode,
        "decision_ms": decision_ms,
        "evidence": evidence_used,  # scores and booleans only, never biometric data
        "evidence_source": sources,  # per field: server-verified / client-reported / absent
        "liveness_session_id": ein.liveness_session_id,
        "liveness_status": liveness_status,
        "context": context_summary,  # the campus-record facts the decision rested on
        "decided_at": _iso(now),
    }
    audited = True
    try:
        audit.append(record, day=now.strftime("%Y-%m-%d"), ts_attempt=f"{_iso(now)}#{attempt_id}", now=now)
    except Exception:  # noqa: BLE001
        log.exception("audit write failed for attempt %s", attempt_id)
        audited = False
        if result.decision == ALLOW:
            result = Decision(DENY, ["audit log unavailable; access is never granted without an audit record"],
                              result.mode)

    return EvaluateResponse(attempt_id=attempt_id, decision=result.decision, reasons=list(result.reasons),
                            mode=result.mode, decision_ms=decision_ms, audited=audited)


@router.post("/offline-sync", response_model=OfflineSyncResponse)
def offline_sync(
    req: OfflineSyncRequest,
    loader: ContextLoader = Depends(get_loader),
    audit: AuditLog = Depends(get_audit_log),
    clock: Callable[[], datetime] = Depends(get_clock),
) -> OfflineSyncResponse:
    now = clock()
    out = OfflineSyncResponse(synced=[], duplicates=[], rejected=[], flagged=[], failed=[])
    seen: set[str] = set()

    for item in req.decisions:
        if item.attempt_id in seen:
            out.duplicates.append(item.attempt_id)
            continue
        seen.add(item.attempt_id)
        if item.decided_at > now + MAX_FUTURE_SKEW:
            out.rejected.append({"attempt_id": item.attempt_id, "reason": "decided_at is in the future"})
            continue

        review = _review_offline(item, loader)
        ts_attempt = f"{_iso(item.decided_at)}#{item.attempt_id}"
        try:
            if not audit.claim_offline(item.attempt_id, now):
                out.duplicates.append(item.attempt_id)
                continue
            audit.append(
                {
                    "attempt_id": item.attempt_id,
                    "room_id": normalize_room(item.room_id),
                    "person_id": item.person_id,
                    "rfid_card_id": item.rfid_card_id,
                    "decision": item.decision,
                    "reasons": item.reasons,
                    "mode": "offline-synced",
                    "kiosk_id": req.kiosk_id,
                    "cache_version": req.cache_version,
                    "decided_at": _iso(item.decided_at),
                    "synced_at": _iso(now),
                    "review_required": review is not None,
                    "review_reason": review,
                },
                day=item.decided_at.strftime("%Y-%m-%d"), ts_attempt=ts_attempt, now=now,
            )
            audit.mark_offline_synced(item.attempt_id, now, ts_attempt)
        except Exception:  # noqa: BLE001 - marker stays "pending" so a retry can succeed
            log.exception("offline sync failed for attempt %s", item.attempt_id)
            out.failed.append(item.attempt_id)
            continue
        out.synced.append(item.attempt_id)
        if review:
            out.flagged.append({"attempt_id": item.attempt_id, "reason": review})
    return out


def _review_offline(item: OfflineDecisionIn, loader: ContextLoader) -> Optional[str]:
    """Revocation propagation check: an offline ALLOW for a credential revoked before it was used is flagged."""
    if item.decision != ALLOW:
        return None
    try:
        for subject in (item.person_id, item.rfid_card_id):
            if not subject:
                continue
            rev = loader.revocation(subject)
            if rev is None:
                continue
            revoked_at = parse_ts(rev.get("revoked_at"))
            if revoked_at is None or revoked_at <= item.decided_at:
                return f"offline ALLOW used credential {subject} revoked at {rev.get('revoked_at')}"
    except Exception:  # noqa: BLE001
        log.exception("revocation re-check failed for %s", item.attempt_id)
        return "revocation re-check unavailable; review manually"
    return None


__all__ = ["router", "get_loader", "get_audit_log", "get_liveness_verifier", "get_clock"]
