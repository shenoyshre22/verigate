from backend.modules.decision_engine import ALLOW, DENY, REQUEST_VERIFICATION, Context, Evidence, decide
from backend.modules.decision_engine.audit import chain, verify

PERSON = {"person_id": "P001", "name": "Test Student A", "status": "active"}


def ctx(**kw):
    base = dict(person=PERSON, schedule_ok=True)
    base.update(kw)
    return Context(**base)


def good(**kw):
    base = dict(liveness=97.0, face_person_id="P001", face_similarity=99.0)
    base.update(kw)
    return Evidence(**base)


def test_allow_live_matched_scheduled():
    assert decide(good(), ctx()).decision == ALLOW


def test_spoof_denied_even_with_card_and_finger():
    d = decide(good(liveness=20.0, rfid_person_id="P001", fingerprint_match=True), ctx())
    assert d.decision == DENY and "spoof" in d.reasons[0]


def test_unknown_identity_denied():
    assert decide(good(), ctx(person=None)).decision == DENY


def test_revoked_denied():
    assert decide(good(), ctx(revoked=True)).decision == DENY


def test_suspended_denied():
    assert decide(good(), ctx(person={**PERSON, "status": "suspended"})).decision == DENY


def test_card_face_mismatch_denied():
    assert decide(good(rfid_person_id="P002"), ctx()).decision == DENY


def test_face_of_other_person_than_identity_denied():
    d = decide(good(face_person_id="P003"), ctx())
    assert d.decision == DENY and "different person" in d.reasons[0]


def test_card_of_other_person_than_identity_denied():
    assert decide(good(face_person_id=None, face_similarity=None, rfid_person_id="P003"), ctx()).decision == DENY


def test_not_scheduled_denied():
    d = decide(good(), ctx(schedule_ok=False))
    assert d.decision == DENY and "schedule" in d.reasons[0]


def test_temp_pass_allows_without_schedule():
    assert decide(good(), ctx(schedule_ok=False, temp_pass_valid=True)).decision == ALLOW


def test_stale_records_sensitive_room_denied():
    assert decide(good(), ctx(records_fresh=False, room_sensitive=True)).decision == DENY


def test_stale_records_normal_room_needs_verification():
    assert decide(good(), ctx(records_fresh=False)).decision == REQUEST_VERIFICATION


def test_uncertain_liveness_requests_verification():
    assert decide(good(liveness=75.0), ctx()).decision == REQUEST_VERIFICATION


def test_borderline_match_requests_verification():
    assert decide(good(face_similarity=88.0), ctx()).decision == REQUEST_VERIFICATION


def test_borderline_then_fingerprint_allows():
    assert decide(good(face_similarity=88.0, fingerprint_match=True), ctx()).decision == ALLOW


def test_borderline_then_fingerprint_fails_denied():
    assert decide(good(face_similarity=88.0, fingerprint_match=False), ctx()).decision == DENY


def test_low_match_denied():
    assert decide(good(face_similarity=40.0), ctx()).decision == DENY


def test_no_face_match_requests_recapture():
    assert decide(good(face_person_id=None, face_similarity=None), ctx()).decision == REQUEST_VERIFICATION


def test_offline_sensitive_room_never_opens():
    d = decide(good(rfid_person_id="P001", fingerprint_match=True), ctx(online=False, room_sensitive=True))
    assert d.decision == DENY and d.mode == "offline"


def test_offline_stale_cache_denied():
    d = decide(good(rfid_person_id="P001", fingerprint_match=True), ctx(online=False, records_fresh=False))
    assert d.decision == DENY


def test_offline_card_and_finger_allows_normal_room():
    d = decide(good(rfid_person_id="P001", fingerprint_match=True), ctx(online=False))
    assert d.decision == ALLOW and d.mode == "offline"


def test_offline_without_fingerprint_denied():
    assert decide(good(rfid_person_id="P001"), ctx(online=False)).decision == DENY


def test_audit_chain_detects_tampering():
    recs = chain([{"attempt_id": "A1", "decision": "ALLOW"}, {"attempt_id": "A2", "decision": "DENY"}])
    assert verify(recs)
    recs[0]["decision"] = "DENY"
    assert not verify(recs)
