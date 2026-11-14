"""Server-side liveness evidence: Rekognition is faked, no AWS calls."""
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from backend.modules.decision_engine import LIVE, SPOOF, UNCERTAIN, liveness_verdict

from .conftest import audit_records

S1 = "11111111-2222-4333-8444-555555555555"
S2 = "22222222-3333-4444-8555-666666666666"
FACE = {"face_person_id": "P001", "face_similarity": 99.0}


def ok(confidence):
    # Real responses also carry images; they must never reach the audit log.
    return {"SessionId": S1, "Status": "SUCCEEDED", "Confidence": confidence,
            "ReferenceImage": {"Bytes": b"\xff\xd8RAWJPEG"}, "AuditImages": [{"Bytes": b"\xff\xd8RAW2"}]}


@pytest.fixture(autouse=True)
def _server_evidence_only(monkeypatch):
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "false")  # production default


def post(client, evidence, **body):
    return client.post("/decision/evaluate", json={"person_id": "P001", "room_id": "LAB3", **body, "evidence": evidence})


# --- engine mapping -------------------------------------------------------------
@pytest.mark.parametrize("conf,verdict", [(None, None), (0, SPOOF), (59.9, SPOOF), (60, UNCERTAIN),
                                          (89.9, UNCERTAIN), (90, LIVE), (100, LIVE)])
def test_liveness_verdict_mapping(conf, verdict):
    assert liveness_verdict(conf) == verdict


# --- client evidence gate -------------------------------------------------------
def test_client_liveness_rejected_by_default(client, tables):
    r = post(client, {"liveness": 99.0, **FACE})
    assert r.status_code == 422 and "liveness_session_id" in r.text
    assert audit_records(tables) == []


def test_client_liveness_accepted_only_with_flag(client, tables, monkeypatch):
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "true")
    assert post(client, {"liveness": 99.0, **FACE}).json()["decision"] == "ALLOW"
    [rec] = audit_records(tables)
    assert rec["evidence_source"]["liveness"] == "client-reported"


def test_no_liveness_at_all_needs_more_verification(client, tables):
    body = post(client, FACE).json()
    assert body["decision"] == "REQUEST_VERIFICATION" and "liveness not checked" in body["reasons"]
    assert audit_records(tables)[0]["evidence_source"]["liveness"] == "absent"


# --- server-verified liveness ---------------------------------------------------
def test_server_live_allows_and_records_provenance(client, tables, rekognition):
    rekognition.sessions[S1] = ok(98.5)
    body = post(client, {"liveness_session_id": S1, **FACE}, rfid_card_id="CARD-A1").json()
    assert body["decision"] == "ALLOW"
    [rec] = audit_records(tables)
    assert rec["evidence_source"] == {
        "liveness": "server-verified", "liveness_status": "absent",
        "face_person_id": "client-reported", "face_similarity": "client-reported",
        "fingerprint_match": "absent", "challenge_passed": "absent", "rfid_person_id": "server-verified",
    }
    assert rec["liveness_status"] == "SUCCEEDED" and float(rec["evidence"]["liveness"]) == 98.5
    assert "RAW" not in repr(rec) and "ReferenceImage" not in repr(rec)
    assert rekognition.calls == [S1]


def test_server_spoof_denied(client, rekognition):
    rekognition.sessions[S1] = ok(30.0)
    body = post(client, {"liveness_session_id": S1, **FACE}).json()
    assert body["decision"] == "DENY" and "spoof" in body["reasons"][0]


def test_server_uncertain_requests_verification(client, rekognition):
    rekognition.sessions[S1] = ok(75.0)
    assert post(client, {"liveness_session_id": S1, **FACE}).json()["decision"] == "REQUEST_VERIFICATION"


def test_server_value_wins_over_client_value(client, rekognition):
    rekognition.sessions[S1] = ok(30.0)
    body = post(client, {"liveness_session_id": S1, "liveness": 99.0, **FACE}).json()
    assert body["decision"] == "DENY"
    assert "client-reported liveness ignored; server lookup used" in body["reasons"]


@pytest.mark.parametrize("status", ["EXPIRED", "FAILED", "IN_PROGRESS", "CREATED"])
def test_unfinished_session_never_allows(client, rekognition, status):
    rekognition.sessions[S1] = {"SessionId": S1, "Status": status}
    body = post(client, {"liveness_session_id": S1, **FACE}).json()
    assert body["decision"] != "ALLOW" and f"liveness session {status}" in body["reasons"]


@pytest.mark.parametrize("error", [
    ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "GetFaceLivenessSessionResults"),
    ReadTimeoutError(endpoint_url="https://rekognition"),
])
def test_rekognition_failure_never_allows(client, rekognition, tables, error):
    rekognition.sessions[S1] = error
    body = post(client, {"liveness_session_id": S1, **FACE}).json()
    assert body["decision"] != "ALLOW" and any("liveness lookup failed" in r for r in body["reasons"])
    assert audit_records(tables)[0]["liveness_status"] == "ERROR"


def test_unknown_session_never_allows(client):
    assert post(client, {"liveness_session_id": S2, **FACE}).json()["decision"] != "ALLOW"


def test_replayed_session_denied(client, rekognition, tables):
    rekognition.sessions[S1] = ok(98.5)
    assert post(client, {"liveness_session_id": S1, **FACE}).json()["decision"] == "ALLOW"
    body = post(client, {"liveness_session_id": S1, **FACE}).json()
    assert body["decision"] == "DENY" and "replay" in body["reasons"][0]
    assert rekognition.calls == [S1]  # replay is caught before Rekognition is asked again
    assert [r["liveness_status"] for r in sorted(audit_records(tables), key=lambda r: int(r["seq"]))] == ["SUCCEEDED", "REUSED"]


def test_malformed_session_id_rejected(client):
    assert post(client, {"liveness_session_id": "../../etc", **FACE}).status_code == 422
