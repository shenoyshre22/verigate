"""VERIGATE Zero Trust Decision Engine.

Deterministic rules only. No network calls, no AI: the same evidence and
context always give the same decision. Bedrock may explain a decision
afterwards but never makes or changes one.

Order of checks is deny-first: a security failure from one module can never
be outweighed by a success from another.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

ALLOW = "ALLOW"
REQUEST_VERIFICATION = "REQUEST_VERIFICATION"
DENY = "DENY"

# Starting thresholds (0-100). Tune from real test runs and record why.
THRESHOLDS = {
    "liveness_spoof_below": 60.0,   # below this: treated as a presentation attack
    "liveness_live_at": 90.0,       # at or above: confidently live
    "match_reject_below": 80.0,     # below this: not the same person
    "match_accept_at": 95.0,        # at or above: confident identity match
}

# Liveness verdicts (from a Rekognition Face Liveness confidence).
SPOOF = "SPOOF"
LIVE = "LIVE"
UNCERTAIN = "UNCERTAIN"


def liveness_verdict(confidence: Optional[float], t: dict = THRESHOLDS) -> Optional[str]:
    """SPOOF below the spoof threshold, LIVE at/above the live threshold, UNCERTAIN in between, None if not run."""
    if confidence is None:
        return None
    if confidence < t["liveness_spoof_below"]:
        return SPOOF
    if confidence >= t["liveness_live_at"]:
        return LIVE
    return UNCERTAIN


def combined_verdict(confidence: Optional[float], status: Optional[str], t: dict = THRESHOLDS) -> Optional[str]:
    """Worst of the numeric verdict and a reported status (e.g. a PAD sensor): SPOOF > UNCERTAIN > LIVE."""
    verdicts = {v for v in (liveness_verdict(confidence, t), status) if v}
    for v in (SPOOF, UNCERTAIN, LIVE):
        if v in verdicts:
            return v
    return None


@dataclass
class Evidence:
    """What the verification modules observed for one access attempt."""
    liveness: Optional[float] = None          # Rekognition Face Liveness confidence, None if not run
    face_person_id: Optional[str] = None      # who the face matched, None if no match
    face_similarity: Optional[float] = None   # similarity of that match
    rfid_person_id: Optional[str] = None      # who the presented card belongs to, None if no card
    fingerprint_match: Optional[bool] = None  # result of a 1:1 fingerprint step-up, None if not done
    challenge_passed: Optional[bool] = None   # result of a randomized face challenge, None if not done
    liveness_session_reused: bool = False     # the liveness session id was already used (replay)
    liveness_status: Optional[str] = None     # SPOOF / LIVE / UNCERTAIN reported by a liveness/PAD check
    liveness_session_rejected: Optional[str] = None  # why a presented session id was refused (not issued, expired ...)
    face_reference_missing: bool = False      # server face check impossible: no enrolled reference photo


@dataclass
class Context:
    """Campus records and conditions the decision depends on."""
    person: Optional[dict] = None       # identity record from the authoritative source, None if unknown
    revoked: bool = False               # card/person revoked
    schedule_ok: bool = False           # an official schedule entry allows this room now
    temp_pass_valid: bool = False       # a valid, unexpired lab-specific pass exists
    room_sensitive: bool = False        # exam hall / hazardous lab
    records_fresh: bool = True          # identity/authorization data is within its freshness window
    online: bool = True                 # kiosk can reach the backend
    revocation_fresh: bool = True       # the revocation feed for this credential refreshed recently
    pass_required: bool = False         # the active schedule entry (e.g. an exam in a lab) also needs a lab pass
    safety_training_required: bool = False  # hazardous lab: valid lab safety training required
    safety_training_valid: bool = False
    records_conflict: bool = False      # equally authoritative sources disagree on the person's status
    conflict_detail: str = ""


@dataclass
class Decision:
    decision: str
    reasons: list = field(default_factory=list)
    mode: str = "online"

    def as_dict(self) -> dict:
        return {"decision": self.decision, "reasons": list(self.reasons), "mode": self.mode}


def _offline(ev: Evidence, ctx: Context) -> Decision:
    """Offline fail-safe: never fail open."""
    if ctx.room_sensitive:
        return Decision(DENY, ["offline: sensitive rooms are never opened without the backend"], "offline")
    if not ctx.records_fresh:
        return Decision(DENY, ["offline: cached revocation data is stale"], "offline")
    if ctx.revoked:
        return Decision(DENY, ["offline: card is on the cached revocation list"], "offline")
    if ev.rfid_person_id and ev.fingerprint_match is True:
        return Decision(ALLOW, ["offline: card and on-device fingerprint verified; decision queued for sync"], "offline")
    return Decision(DENY, ["offline: card and fingerprint are both required"], "offline")


def decide(ev: Evidence, ctx: Context, t: dict = THRESHOLDS) -> Decision:
    if not ctx.online:
        return _offline(ev, ctx)

    # 1. Liveness failure or a replayed liveness session cannot be overridden by any other module.
    if ev.liveness_session_reused:
        return Decision(DENY, ["liveness session was already used (replay suspected)"])
    if ev.liveness_session_rejected:
        return Decision(DENY, [f"liveness session rejected: {ev.liveness_session_rejected}"])
    verdict = combined_verdict(ev.liveness, ev.liveness_status, t)
    if verdict == SPOOF:
        detail = f"liveness {ev.liveness:.0f}%" if liveness_verdict(ev.liveness, t) == SPOOF else "liveness status SPOOF"
        return Decision(DENY, [f"spoof suspected ({detail})"])

    # 2. Identity must exist in the authoritative record and be in good standing.
    if ctx.person is None:
        return Decision(DENY, ["identity not found in campus records"])
    if ctx.revoked:
        return Decision(DENY, ["credential revoked"])
    if not ctx.records_conflict:  # an unresolved status is handled in step 5, never guessed
        status = ctx.person.get("status")
        if status == "suspended":
            return Decision(DENY, ["person is suspended (disciplinary record)"])
        if status != "active":
            return Decision(DENY, [f"person is not active (status {status})"])

    # 3. Evidence from different modules must agree on who this is.
    if ev.rfid_person_id and ev.face_person_id and ev.rfid_person_id != ev.face_person_id:
        return Decision(DENY, ["card and face belong to different people"])
    claimed = ctx.person.get("person_id")
    if claimed and ev.rfid_person_id and ev.rfid_person_id != claimed:
        return Decision(DENY, ["card belongs to a different person than the identity record"])
    if claimed and ev.face_person_id and ev.face_person_id != claimed:
        return Decision(DENY, ["face matched a different person than the identity record"])

    # 4. Authorization: schedule or a valid temporary pass; both when the schedule entry requires a pass.
    if ctx.pass_required:
        if not ctx.schedule_ok:
            return Decision(DENY, ["no scheduled access to this room now"])
        if not ctx.temp_pass_valid:
            return Decision(DENY, ["exam in this room requires a valid temporary lab pass; none is valid now"])
    elif not (ctx.schedule_ok or ctx.temp_pass_valid):
        return Decision(DENY, ["no scheduled access to this room now"])
    if ctx.safety_training_required and not ctx.safety_training_valid:
        return Decision(DENY, ["lab safety training missing or expired"])

    # 5. Uncertain records: sensitive rooms deny, others ask for more proof.
    if not ctx.revocation_fresh:
        if ctx.room_sensitive:
            return Decision(DENY, ["revocation list could not be refreshed; sensitive room stays closed"])
        return Decision(REQUEST_VERIFICATION, ["revocation list could not be refreshed; extra check needed"])
    if ctx.records_conflict:
        if ctx.room_sensitive:
            return Decision(DENY, ["conflicting authoritative records for a sensitive room", ctx.conflict_detail])
        return Decision(REQUEST_VERIFICATION, ["conflicting records from equally authoritative sources; "
                                               "manual verification required", ctx.conflict_detail])
    if not ctx.records_fresh:
        if ctx.room_sensitive:
            return Decision(DENY, ["authorization records are stale for a sensitive room"])
        return Decision(REQUEST_VERIFICATION, ["authorization records are stale; extra check needed"])

    # 6. A failed extra check is final.
    if ev.fingerprint_match is False:
        return Decision(DENY, ["fingerprint did not match"])
    if ev.challenge_passed is False:
        return Decision(DENY, ["randomized face challenge failed"])

    # 7. Face identity.
    if ev.face_person_id is None or ev.face_similarity is None:
        if ev.face_reference_missing:
            return Decision(REQUEST_VERIFICATION, ["no enrolled reference photo; manual identity check required"])
        return Decision(REQUEST_VERIFICATION, ["no confident face match; please recapture"])
    if ev.face_similarity < t["match_reject_below"]:
        return Decision(DENY, [f"face does not match ({ev.face_similarity:.0f}%)"])

    uncertain = []
    if verdict != LIVE:
        uncertain.append("liveness uncertain" if verdict == UNCERTAIN else "liveness not checked")
    if ev.face_similarity < t["match_accept_at"]:
        uncertain.append(f"face match {ev.face_similarity:.0f}% below {t['match_accept_at']:.0f}%")

    extra_passed = ev.fingerprint_match is True or ev.challenge_passed is True
    if uncertain and not extra_passed:
        return Decision(REQUEST_VERIFICATION, uncertain + ["additional verification required"])

    reasons = ["live person and identity verified", "authorized for this room now"]
    if extra_passed:
        reasons.append("additional verification passed")
    return Decision(ALLOW, reasons)
