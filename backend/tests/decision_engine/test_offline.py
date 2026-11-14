from datetime import timedelta

import pytest

from backend.modules.decision_engine import ALLOW, DENY, Evidence, decide
from backend.modules.decision_engine.audit_store import verify_items
from backend.modules.decision_engine.offline_cache import OfflineCache

from .conftest import NOW, audit_records, iso


def queued(attempt_id="OFF-1", **kw):
    base = {"attempt_id": attempt_id, "room_id": "LAB3", "rfid_card_id": "CARD-A1", "person_id": "P001",
            "decision": "ALLOW", "decided_at": iso(NOW - timedelta(minutes=30)),
            "reasons": ["offline: card and on-device fingerprint verified; decision queued for sync"]}
    base.update(kw)
    return base


def sync(client, *decisions, **extra):
    return client.post("/decision/offline-sync",
                       json={"kiosk_id": "KIOSK-01", "cache_version": 7, "decisions": list(decisions), **extra})


# --- offline-sync route -----------------------------------------------------
def test_sync_audits_as_offline_synced(client, tables):
    r = sync(client, queued("OFF-1"), queued("OFF-2", decision="DENY"))
    assert r.status_code == 200 and r.json()["synced"] == ["OFF-1", "OFF-2"]
    recs = audit_records(tables)
    assert {x["mode"] for x in recs} == {"offline-synced"}
    assert all(x["kiosk_id"] == "KIOSK-01" and int(x["cache_version"]) == 7 for x in recs)
    assert {x["day"] for x in recs} == {"2026-11-14"} and verify_items(recs)


def test_resync_skips_duplicates(client, tables):
    sync(client, queued("OFF-1"))
    r = sync(client, queued("OFF-1"), queued("OFF-3"))
    assert r.json()["duplicates"] == ["OFF-1"] and r.json()["synced"] == ["OFF-3"]
    assert len(audit_records(tables)) == 2


def test_duplicate_within_one_batch(client):
    r = sync(client, queued("OFF-1"), queued("OFF-1"))
    assert r.json()["synced"] == ["OFF-1"] and r.json()["duplicates"] == ["OFF-1"]


@pytest.mark.parametrize("field", ["face_image", "fingerprint_template", "faceEmbedding", "photo"])
def test_biometric_fields_rejected(client, tables, field):
    r = sync(client, queued(**{field: "AAAA"}))
    assert r.status_code == 422 and audit_records(tables) == []


def test_biometric_field_at_top_level_rejected(client):
    assert sync(client, queued(), image="AAAA").status_code == 422


def test_unknown_field_rejected(client):
    assert sync(client, queued(door_override=True)).status_code == 422


def test_future_decision_rejected(client, tables):
    r = sync(client, queued(decided_at=iso(NOW + timedelta(hours=1))))
    assert r.json()["rejected"][0]["attempt_id"] == "OFF-1" and audit_records(tables) == []


def test_naive_timestamp_rejected(client):
    assert sync(client, queued(decided_at="2026-11-14T09:00:00")).status_code == 422


def test_allow_with_revoked_card_flagged_for_review(client, tables):
    r = sync(client, queued("OFF-9", rfid_card_id="CARD-X9", person_id=None))
    assert r.json()["synced"] == ["OFF-9"] and "CARD-X9" in r.json()["flagged"][0]["reason"]
    [rec] = audit_records(tables)
    assert rec["review_required"] is True


def test_deny_with_revoked_card_not_flagged(client):
    assert sync(client, queued("OFF-8", rfid_card_id="CARD-X9", decision="DENY")).json()["flagged"] == []


def test_offline_and_online_records_share_one_chain(client, tables):
    client.post("/decision/evaluate", json={"person_id": "P001", "room_id": "LAB3",
                                            "evidence": {"liveness": 97, "face_person_id": "P001", "face_similarity": 99}})
    sync(client, queued("OFF-1"))
    recs = audit_records(tables)
    assert len(recs) == 2 and verify_items(recs)


# --- kiosk cache --------------------------------------------------------------
def cache(age_minutes=5, revoked=("CARD-X9",)):
    return OfflineCache.build(revoked, list_version=7, now=NOW - timedelta(minutes=age_minutes))


def test_cache_round_trip_holds_no_biometrics():
    data = cache().to_dict()
    assert set(data) == {"revoked_ids", "list_version", "fetched_at"}
    assert OfflineCache.from_dict(data) == cache()


def test_cache_rejects_biometric_or_extra_fields():
    with pytest.raises(ValueError, match="face_vectors"):
        OfflineCache.from_dict({**cache().to_dict(), "face_vectors": []})


def test_cache_staleness(monkeypatch):
    assert not cache(age_minutes=5).is_stale(NOW)
    assert cache(age_minutes=16).is_stale(NOW)
    assert cache(age_minutes=-60).is_stale(NOW)  # fetched "in the future": clock tampering
    monkeypatch.setenv("OFFLINE_CACHE_MAX_AGE_MINUTES", "60")
    assert not cache(age_minutes=16).is_stale(NOW)


def test_offline_decision_from_fresh_cache_allows_card_and_finger():
    ctx = cache().offline_context(room_id="LAB3", rfid_card_id="CARD-A1", now=NOW)
    assert decide(Evidence(rfid_person_id="P001", fingerprint_match=True), ctx).decision == ALLOW


def test_offline_decision_from_stale_cache_denies():
    ctx = cache(age_minutes=60).offline_context(room_id="LAB3", rfid_card_id="CARD-A1", now=NOW)
    assert decide(Evidence(rfid_person_id="P001", fingerprint_match=True), ctx).decision == DENY


def test_offline_revoked_card_denied():
    ctx = cache().offline_context(room_id="LAB3", rfid_card_id="CARD-X9", now=NOW)
    assert decide(Evidence(rfid_person_id="P010", fingerprint_match=True), ctx).decision == DENY


def test_offline_sensitive_room_denied_even_with_fresh_cache():
    ctx = cache().offline_context(room_id="chemlab", rfid_card_id="CARD-A1", now=NOW)
    assert decide(Evidence(rfid_person_id="P001", fingerprint_match=True), ctx).decision == DENY
