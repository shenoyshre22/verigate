from botocore.exceptions import ClientError

from backend.modules.decision_engine.audit_store import AuditLog, verify_items
from backend.modules.decision_engine.context_loader import ContextLoader

from .conftest import NOW, audit_records
from .conftest import make_client as _client
from .fakes import BrokenTable

GOOD = {"liveness": 97.0, "face_person_id": "P001", "face_similarity": 99.0}


def post(client, **body):
    body.setdefault("room_id", "LAB3")
    body.setdefault("evidence", GOOD)
    return client.post("/decision/evaluate", json=body)


def test_allow_end_to_end_and_audited(client, tables):
    r = post(client, person_id="P001")
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "ALLOW" and body["mode"] == "online" and body["audited"]
    assert body["decision_ms"] >= 0
    [rec] = audit_records(tables)
    assert rec["day"] == "2026-11-14" and rec["ts_attempt"].endswith("#" + body["attempt_id"])
    assert rec["decision"] == "ALLOW" and len(rec["hash"]) == 64
    assert int(rec["expires_at"]) == int(NOW.timestamp()) + 30 * 86400


def test_card_only_resolves_identity(client):
    assert post(client, rfid_card_id="CARD-A1").json()["decision"] == "ALLOW"


def test_face_of_another_person_denied(client):
    r = post(client, person_id="P001", evidence={**GOOD, "face_person_id": "P003"})
    assert r.json()["decision"] == "DENY" and "different person" in r.json()["reasons"][0]


def test_card_of_another_person_denied(client):
    assert post(client, person_id="P001", rfid_card_id="CARD-C3").json()["decision"] == "DENY"


def test_not_scheduled_denied(client):
    assert post(client, person_id="P001", room_id="LAB9").json()["decision"] == "DENY"


def test_suspended_denied(client):
    r = post(client, person_id="P002", evidence={**GOOD, "face_person_id": "P002"})
    assert r.json()["decision"] == "DENY"


def test_borderline_match_requests_verification(client):
    r = post(client, person_id="P001", evidence={**GOOD, "face_similarity": 88.0})
    assert r.json()["decision"] == "REQUEST_VERIFICATION"


def test_offline_simulation_never_opens_sensitive_room(client):
    r = post(client, rfid_card_id="CARD-A1", room_id="EXAMHALL", online=False,
             evidence={})
    assert r.json()["decision"] == "DENY" and r.json()["mode"] == "offline"


def test_client_cannot_assert_fingerprint_result(client):
    for result in (True, False):
        r = post(client, person_id="P001", evidence={**GOOD, "fingerprint_match": result})
        assert r.status_code == 422
        assert "trusted fingerprint evidence adapter" in r.text


def test_raw_image_field_rejected(client, tables):
    r = post(client, person_id="P001", evidence={**GOOD, "face_image": "base64..."})
    assert r.status_code == 422 and "biometric" in r.text
    assert audit_records(tables) == []


def test_identity_required(client):
    assert post(client).status_code == 422


def test_out_of_range_score_rejected(client):
    assert post(client, person_id="P001", evidence={**GOOD, "face_similarity": 150}).status_code == 422


def test_records_unavailable_fails_closed(audit_log, tables):
    c = _client(ContextLoader(BrokenTable(), BrokenTable(), BrokenTable()), audit_log)
    body = post(c, person_id="P001").json()
    assert body["decision"] == "DENY" and "failing closed" in body["reasons"][0] and body["audited"]


def test_allow_downgraded_when_audit_unavailable(loader):
    body = post(_client(loader, AuditLog(BrokenTable())), person_id="P001").json()
    assert body["decision"] == "DENY" and not body["audited"] and "audit" in body["reasons"][0]


def test_audit_chain_verifies_and_detects_tampering(client, tables):
    for _ in range(3):
        post(client, person_id="P001")
    post(client, person_id="P001", room_id="LAB9")
    recs = audit_records(tables)
    assert len(recs) == 4 and verify_items(recs)
    recs[1]["decision"] = "ALLOW" if recs[1]["decision"] == "DENY" else "DENY"
    assert not verify_items(recs)


def test_deleted_record_breaks_chain(client, tables):
    for _ in range(3):
        post(client, person_id="P001")
    recs = sorted(audit_records(tables), key=lambda i: int(i["seq"]))
    assert not verify_items([recs[0], recs[2]])


def test_concurrent_head_update_retries(client, tables):
    post(client, person_id="P001")
    audit = tables["audit"]
    real_put = audit.put_item
    state = {"raced": False}

    def racing_put(Item, ConditionExpression=None):  # noqa: N803
        if Item.get("ts_attempt") == "HEAD" and not state["raced"]:
            state["raced"] = True
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "race"}}, "PutItem")
        return real_put(Item=Item, ConditionExpression=ConditionExpression)

    audit.put_item = racing_put
    assert post(client, person_id="P001").json()["audited"]
    assert state["raced"] and verify_items(audit_records(tables))


def test_numbers_hash_in_the_form_dynamodb_returns():
    from decimal import Decimal

    from backend.modules.decision_engine.audit_store import canonical_number

    assert canonical_number(97.0) == Decimal("97") and str(canonical_number(97.0)) == "97"
    assert str(canonical_number(Decimal("1.50"))) == "1.5"
    assert str(canonical_number(100)) == "100" and str(canonical_number(430.66)) == "430.66"
    assert str(canonical_number(Decimal("1E+2"))) == "100"


def test_seq_gap_fails_verification(client, tables):
    for _ in range(3):
        post(client, person_id="P001")
    recs = sorted(audit_records(tables), key=lambda i: int(i["seq"]))
    assert verify_items(recs) and verify_items(recs, from_seq=2)
    assert not verify_items([recs[0], recs[2]])
