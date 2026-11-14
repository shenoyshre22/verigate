"""Kiosk liveness sessions + server-side face verification. Rekognition and S3 are faked, no AWS calls."""
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from backend.modules.decision_engine import LIVE, SPOOF, UNCERTAIN, liveness_verdict
from backend.modules.decision_engine.audit_store import AuditLog

from .conftest import FACE_BUCKET, NOW, audit_records, make_client
from .fakes import BrokenTable

UNKNOWN = "22222222-3333-4444-8555-666666666666"
LIVE_P001, REF_P001, REF_P003 = b"\xff\xd8LIVE-P001", b"\xff\xd8REF-P001", b"\xff\xd8REF-P003"


@pytest.fixture(autouse=True)
def _server_evidence_only(monkeypatch):
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "false")  # production default


@pytest.fixture
def enrolled(s3, rekognition):
    """P001 has an enrolled photo that matches their live capture; P003's photo does not match it."""
    s3.objects[(FACE_BUCKET, "P001.jpg")] = REF_P001
    s3.objects[(FACE_BUCKET, "P003.jpg")] = REF_P003
    rekognition.similarities[(LIVE_P001, REF_P001)] = 99.2
    rekognition.similarities[(LIVE_P001, REF_P003)] = 31.0


def new_session(client, **bind):
    r = client.post("/decision/liveness-session", json=bind)
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


def completed(rekognition, sid, confidence, image=LIVE_P001):
    rekognition.sessions[sid] = {"SessionId": sid, "Status": "SUCCEEDED", "Confidence": confidence,
                                 "ReferenceImage": {"Bytes": image}, "AuditImages": [{"Bytes": b"\xff\xd8AUDIT"}]}


def evaluate(client, sid, person_id="P001", **evidence):
    body = {"person_id": person_id, "room_id": "LAB3", "evidence": {"liveness_session_id": sid, **evidence}}
    return client.post("/decision/evaluate", json=body)


# --- engine mapping -------------------------------------------------------------
@pytest.mark.parametrize("conf,verdict", [(None, None), (0, SPOOF), (59.9, SPOOF), (60, UNCERTAIN),
                                          (89.9, UNCERTAIN), (90, LIVE), (100, LIVE)])
def test_liveness_verdict_mapping(conf, verdict):
    assert liveness_verdict(conf) == verdict


# --- POST /decision/liveness-session --------------------------------------------
def test_session_is_issued_single_use_with_ttl(client, tables, rekognition):
    r = client.post("/decision/liveness-session", json={"person_id": "P001"})
    body = r.json()
    assert r.status_code == 201 and body["ttl_seconds"] == 600 and body["bound_to"] == "P001"
    assert body["session_id"] == rekognition.created[0]
    marker = tables["audit"].items[("LIVENESS-SESSION", body["session_id"])]
    assert marker["status"] == "issued" and marker["valid_until"] == "2026-11-14T10:10:00.000000Z"
    assert int(marker["expires_at"]) == int((NOW + timedelta(minutes=10)).timestamp())


def test_provider_failure_returns_no_session(client, rekognition, tables):
    rekognition.create_error = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                                           "CreateFaceLivenessSession")
    assert client.post("/decision/liveness-session", json={}).status_code == 502
    assert not any(k[0] == "LIVENESS-SESSION" for k in tables["audit"].items)


def test_unrecordable_session_is_not_handed_out(loader, rekognition):
    c = make_client(loader, AuditLog(BrokenTable()), rekognition)
    assert c.post("/decision/liveness-session", json={}).status_code == 503


def test_biometric_field_rejected_on_session_route(client):
    assert client.post("/decision/liveness-session", json={"face_image": "AAAA"}).status_code == 422


# --- server-side face verification ---------------------------------------------------
def test_match_allows_with_server_verified_evidence(client, tables, rekognition, s3, enrolled):
    sid = new_session(client, person_id="P001")
    completed(rekognition, sid, 98.5)
    body = evaluate(client, sid).json()
    assert body["decision"] == "ALLOW", body["reasons"]
    [rec] = audit_records(tables)
    assert rec["evidence_source"]["liveness"] == "server-verified"
    assert rec["evidence_source"]["face_similarity"] == "server-verified"
    assert rec["evidence_source"]["face_person_id"] == "server-verified"
    assert rec["face_check"] == {"status": "MATCH", "similarity": rec["face_check"]["similarity"]}
    assert float(rec["evidence"]["face_similarity"]) == 99.2 and rec["evidence"]["face_person_id"] == "P001"
    assert s3.calls == [(FACE_BUCKET, "P001.jpg")] and rekognition.compare_calls == [(LIVE_P001, REF_P001)]
    assert tables["audit"].items[("LIVENESS-SESSION", sid)]["status"] == "consumed"


def test_image_bytes_are_never_stored(client, tables, rekognition, enrolled):
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    evaluate(client, sid)
    dump = repr(list(tables["audit"].items.values()))
    assert "LIVE-P001" not in dump and "REF-P001" not in dump and "AUDIT" not in dump and "\\xff\\xd8" not in dump


def test_mismatch_denied(client, rekognition, s3, enrolled):
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    s3.objects[(FACE_BUCKET, "P001.jpg")] = REF_P003  # enrolled photo is someone else
    body = evaluate(client, sid).json()
    assert body["decision"] == "DENY" and "face does not match (31%)" in body["reasons"][0]


def test_no_faces_matched_at_all_denied(client, rekognition, s3):
    s3.objects[(FACE_BUCKET, "P001.jpg")] = b"\xff\xd8OTHER"
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    assert evaluate(client, sid).json()["decision"] == "DENY"


def test_no_reference_photo_requests_verification(client, rekognition):
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    body = evaluate(client, sid).json()
    assert body["decision"] == "REQUEST_VERIFICATION"
    assert body["reasons"][0] == "no enrolled reference photo; manual identity check required"
    assert "no enrolled reference photo for P001" in body["reasons"]


def test_reference_bucket_error_never_allows(client, rekognition, s3):
    s3.objects[(FACE_BUCKET, "P001.jpg")] = ClientError({"Error": {"Code": "SlowDown", "Message": "x"}}, "GetObject")
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    body = evaluate(client, sid).json()
    assert body["decision"] != "ALLOW" and any("reference photo unavailable (SlowDown)" in r for r in body["reasons"])


def test_no_face_in_image_never_allows(client, rekognition, enrolled):
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    rekognition.similarities[(LIVE_P001, REF_P001)] = ClientError(
        {"Error": {"Code": "InvalidParameterException", "Message": "no face"}}, "CompareFaces")
    assert evaluate(client, sid).json()["decision"] != "ALLOW"


def test_client_face_scores_ignored_with_session(client, rekognition, enrolled, s3):
    s3.objects[(FACE_BUCKET, "P001.jpg")] = REF_P003  # server says: not the same person
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    body = evaluate(client, sid, face_person_id="P001", face_similarity=99.9).json()
    assert body["decision"] == "DENY"
    assert "client-reported face match ignored; server comparison used" in body["reasons"]


def test_person_resolved_from_card(client, rekognition, enrolled):
    sid = new_session(client, rfid_card_id="CARD-A1")
    completed(rekognition, sid, 98.5)
    body = client.post("/decision/evaluate", json={"rfid_card_id": "CARD-A1", "room_id": "LAB3",
                                                   "evidence": {"liveness_session_id": sid}}).json()
    assert body["decision"] == "ALLOW", body["reasons"]


# --- spoof / unfinished / provider errors -----------------------------------------
def test_spoof_denied_and_never_compared(client, rekognition, enrolled):
    sid = new_session(client)
    completed(rekognition, sid, 30.0)
    body = evaluate(client, sid).json()
    assert body["decision"] == "DENY" and "spoof" in body["reasons"][0]
    assert rekognition.compare_calls == []


def test_uncertain_liveness_requests_verification(client, rekognition, enrolled):
    sid = new_session(client)
    completed(rekognition, sid, 75.0)
    assert evaluate(client, sid).json()["decision"] == "REQUEST_VERIFICATION"


@pytest.mark.parametrize("status", ["CREATED", "IN_PROGRESS", "FAILED", "EXPIRED"])
def test_unfinished_session_never_allows(client, rekognition, enrolled, status):
    sid = new_session(client)
    rekognition.sessions[sid] = {"SessionId": sid, "Status": status}
    body = evaluate(client, sid).json()
    assert body["decision"] != "ALLOW" and f"liveness session {status}" in body["reasons"]
    assert rekognition.compare_calls == []


@pytest.mark.parametrize("error", [
    ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "GetFaceLivenessSessionResults"),
    ReadTimeoutError(endpoint_url="https://rekognition"),
])
def test_rekognition_failure_never_allows(client, rekognition, tables, enrolled, error):
    sid = new_session(client)
    rekognition.sessions[sid] = error
    body = evaluate(client, sid).json()
    assert body["decision"] != "ALLOW" and any("liveness lookup failed" in r for r in body["reasons"])
    assert audit_records(tables)[0]["liveness_status"] == "ERROR"


# --- issuance / single use ----------------------------------------------------------
def test_reused_session_denied(client, rekognition, tables, enrolled):
    sid = new_session(client)
    completed(rekognition, sid, 98.5)
    assert evaluate(client, sid).json()["decision"] == "ALLOW"
    body = evaluate(client, sid).json()
    assert body["decision"] == "DENY" and body["reasons"][0] == "liveness session was already used (replay suspected)"
    assert rekognition.calls == [sid]  # the replay never reaches Rekognition
    assert [r["liveness_status"] for r in sorted(audit_records(tables), key=lambda r: int(r["seq"]))] == ["SUCCEEDED", "REUSED"]


def test_unknown_session_denied(client, rekognition):
    rekognition.sessions[UNKNOWN] = {"SessionId": UNKNOWN, "Status": "SUCCEEDED", "Confidence": 99.0,
                                     "ReferenceImage": {"Bytes": LIVE_P001}}  # real, but not issued by us
    body = evaluate(client, UNKNOWN).json()
    assert body["decision"] == "DENY" and body["reasons"][0] == "liveness session rejected: not issued by this backend"
    assert rekognition.calls == []


def test_expired_session_denied(loader, audit_log, rekognition, s3, enrolled):
    c = make_client(loader, audit_log, rekognition, s3)
    sid = new_session(c)
    completed(rekognition, sid, 98.5)
    late = make_client(loader, audit_log, rekognition, s3)
    from backend.modules.decision_engine import api
    late.app.dependency_overrides[api.get_clock] = lambda: (lambda: NOW + timedelta(minutes=11))
    body = evaluate(late, sid).json()
    assert body["decision"] == "DENY" and body["reasons"][0] == "liveness session rejected: expired"


def test_session_bound_to_other_person_denied(client, rekognition, enrolled):
    sid = new_session(client, person_id="P003")
    completed(rekognition, sid, 98.5)
    body = evaluate(client, sid, person_id="P001").json()
    assert body["decision"] == "DENY" and "issued for a different person" in body["reasons"][0]


def test_issuance_check_unavailable_never_allows(loader, rekognition, s3, enrolled):
    c = make_client(loader, AuditLog(BrokenTable()), rekognition, s3)
    body = evaluate(c, UNKNOWN).json()
    assert body["decision"] == "DENY" and "issuance check unavailable" in body["reasons"][0]


def test_malformed_session_id_rejected(client):
    assert evaluate(client, "../../etc").status_code == 422


# --- client evidence gate (unchanged behaviour) ----------------------------------------
def test_client_liveness_rejected_by_default(client, tables):
    r = client.post("/decision/evaluate", json={"person_id": "P001", "room_id": "LAB3",
                                                "evidence": {"liveness": 99.0, "face_person_id": "P001",
                                                             "face_similarity": 99.0}})
    assert r.status_code == 422 and "liveness_session_id" in r.text and audit_records(tables) == []


def test_client_evidence_only_with_flag(client, tables, monkeypatch):
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "true")
    r = client.post("/decision/evaluate", json={"person_id": "P001", "room_id": "LAB3",
                                                "evidence": {"liveness": 99.0, "face_person_id": "P001",
                                                             "face_similarity": 99.0}})
    assert r.json()["decision"] == "ALLOW"
    assert audit_records(tables)[0]["evidence_source"]["liveness"] == "client-reported"
    assert audit_records(tables)[0]["evidence_source"]["face_similarity"] == "client-reported"
