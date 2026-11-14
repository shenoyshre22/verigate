"""Judge scenarios J1..J5 against exactly the records aws/dynamodb/seed.py writes (no AWS calls)."""
import importlib.util
from datetime import timedelta
from pathlib import Path

import pytest

from backend.modules.decision_engine import (
    ALLOW, DENY, LIVE, REQUEST_VERIFICATION, SPOOF, UNCERTAIN, Context, Evidence, combined_verdict, decide,
)
from backend.modules.decision_engine.audit_store import AuditLog
from backend.modules.decision_engine.context_loader import ContextLoader
from backend.modules.decision_engine.reconcile import reconcile_status

from .conftest import NOW, audit_records, iso, make_client
from .fakes import campus_tables
from .judge_cases import JUDGE_CASES

SEED = Path(__file__).resolve().parents[3] / "aws" / "dynamodb" / "seed.py"


def load_seed():
    spec = importlib.util.spec_from_file_location("verigate_seed", SEED)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def seeded():
    t = campus_tables()
    for table, items in load_seed().build(NOW).items():
        for item in items:
            t[table].put_item(Item=item)
    return t


@pytest.fixture
def judge_client(seeded):
    return make_client(ContextLoader(seeded["identities"], seeded["authorization"], seeded["revocations"]),
                       AuditLog(seeded["audit"]))


@pytest.mark.parametrize("case_id,title,body,expected,fragment", JUDGE_CASES, ids=[c[0] for c in JUDGE_CASES])
def test_judge_scenario(judge_client, case_id, title, body, expected, fragment):
    r = judge_client.post("/decision/evaluate", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["decision"] == expected, (case_id, out["reasons"])
    assert any(fragment in reason for reason in out["reasons"]), (case_id, out["reasons"])
    assert out["audited"] and out["mode"] == "online"


def test_judge_audit_records_explain_context(judge_client, seeded):
    by_id = {c[0]: c[2] for c in JUDGE_CASES}
    judge_client.post("/decision/evaluate", json=by_id["J2"])
    judge_client.post("/decision/evaluate", json=by_id["J5"])
    j2, j5 = sorted(audit_records(seeded), key=lambda r: int(r["seq"]))
    assert j2["context"]["status"] == "suspended" and j2["context"]["status_sources"] == ["disciplinary_office"]
    assert j5["context"]["records_conflict"] is True and j5["context"]["status_sources"] == ["hr", "registrar"]


def test_seeded_s_scenarios_still_hold(judge_client):
    expected = {"S1": ALLOW, "S3": DENY, "S5": DENY}
    rooms = {"S5": "EXAMHALL"}
    for pid, decision in expected.items():
        body = {"person_id": pid, "room_id": rooms.get(pid, "LAB3"),
                "evidence": {"liveness": 97.0, "face_person_id": pid, "face_similarity": 99.0}}
        assert judge_client.post("/decision/evaluate", json=body).json()["decision"] == decision, pid


# --- liveness status (J1) --------------------------------------------------------
@pytest.mark.parametrize("score,status,verdict", [
    (None, "SPOOF", SPOOF), (99.0, "SPOOF", SPOOF), (20.0, "LIVE", SPOOF), (99.0, "UNCERTAIN", UNCERTAIN),
    (None, "LIVE", LIVE), (75.0, None, UNCERTAIN), (None, None, None),
])
def test_combined_verdict_takes_the_worst(score, status, verdict):
    assert combined_verdict(score, status) == verdict


def test_spoof_status_beats_card_fingerprint_and_face():
    ev = Evidence(liveness_status=SPOOF, face_person_id="J1", face_similarity=99.0, rfid_person_id="J1",
                  fingerprint_match=True, challenge_passed=True)
    d = decide(ev, Context(person={"person_id": "J1", "status": "active"}, schedule_ok=True))
    assert d.decision == DENY and d.reasons == ["spoof suspected (liveness status SPOOF)"]


def test_client_liveness_status_needs_flag(judge_client, monkeypatch):
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "false")
    assert judge_client.post("/decision/evaluate", json=JUDGE_CASES[0][2]).status_code == 422


# --- reconciliation (J2, J5) --------------------------------------------------------
def rec(source, status, version, updated="2026-11-14T09:00:00Z"):
    return {"source": source, "status": status, "version": version, "updated_at": updated}


def test_higher_authority_wins():
    r = reconcile_status([rec("registrar", "active", 9), rec("disciplinary_office", "suspended", 1)])
    assert r.status == "suspended" and not r.conflict and r.sources == ("disciplinary_office",)


def test_latest_version_per_source_wins():
    r = reconcile_status([rec("registrar", "suspended", 1), rec("registrar", "active", 2)])
    assert r.status == "active" and not r.conflict


def test_equal_authority_disagreement_is_a_conflict():
    r = reconcile_status([rec("registrar", "active", 3), rec("hr", "inactive", 3)])
    assert r.conflict and r.status is None and "registrar=active" in r.detail and "hr=inactive" in r.detail


def test_equal_authority_agreement_is_not_a_conflict():
    r = reconcile_status([rec("registrar", "active", 3), rec("hr", "active", 1)])
    assert r.status == "active" and not r.conflict


def test_unknown_source_cannot_override_known_office():
    r = reconcile_status([rec("registrar", "active", 1), rec("some_spreadsheet", "suspended", 99)])
    assert r.status == "active"


def test_non_active_status_denied():
    ctx = Context(person={"person_id": "X", "status": "graduated"}, schedule_ok=True)
    assert decide(Evidence(liveness=97, face_person_id="X", face_similarity=99), ctx).decision == DENY


# --- revocation feed freshness (J4) --------------------------------------------------
def test_missing_feed_status_is_stale(seeded, judge_client):
    del seeded["revocations"].items[("SYNC#campus", None)]
    body = {"person_id": "S1", "room_id": "LAB3",
            "evidence": {"liveness": 97.0, "face_person_id": "S1", "face_similarity": 99.0}}
    assert judge_client.post("/decision/evaluate", json=body).json()["decision"] == REQUEST_VERIFICATION


def test_feed_refreshed_again_allows(seeded, judge_client):
    seeded["revocations"].put_item(Item={"subject_id": "SYNC#contractor-office", "last_refreshed_at": iso(NOW)})
    body = dict(JUDGE_CASES[4][2])  # J4, EXAMHALL
    assert judge_client.post("/decision/evaluate", json=body).json()["decision"] == ALLOW


def test_revocation_freshness_independent_of_records_freshness():
    base = dict(person={"person_id": "X", "status": "active"}, schedule_ok=True)
    ev = Evidence(liveness=97, face_person_id="X", face_similarity=99)
    assert decide(ev, Context(**base, revocation_fresh=False, records_fresh=True)).decision == REQUEST_VERIFICATION
    assert decide(ev, Context(**base, revocation_fresh=True, records_fresh=False)).decision == REQUEST_VERIFICATION
    assert "revocation" in decide(ev, Context(**base, revocation_fresh=False)).reasons[0]
    assert "stale" in decide(ev, Context(**base, records_fresh=False)).reasons[0]


# --- exam + lab pass (J3) and lab safety training ------------------------------------
def test_pass_required_needs_both():
    ev = Evidence(liveness=97, face_person_id="X", face_similarity=99)
    p = {"person_id": "X", "status": "active"}
    assert decide(ev, Context(person=p, schedule_ok=True, temp_pass_valid=True, pass_required=True)).decision == ALLOW
    assert decide(ev, Context(person=p, schedule_ok=True, pass_required=True)).decision == DENY
    assert decide(ev, Context(person=p, temp_pass_valid=True, pass_required=True)).decision == DENY


def test_lab_safety_training_required_in_chemlab(seeded, judge_client):
    pid = "S1"
    seeded["authorization"].put_item(Item={"person_id": pid, "grant_key": "ROOM#CHEMLAB#x",
                                           "valid_from": iso(NOW - timedelta(hours=1)),
                                           "valid_to": iso(NOW + timedelta(hours=1))})
    body = {"person_id": pid, "room_id": "CHEMLAB",
            "evidence": {"liveness": 97.0, "face_person_id": pid, "face_similarity": 99.0}}
    d = judge_client.post("/decision/evaluate", json=body).json()
    assert d["decision"] == DENY and "lab safety training" in d["reasons"][0]
    seeded["authorization"].put_item(Item={"person_id": pid, "grant_key": "TRAINING#LAB_SAFETY#2026",
                                           "valid_from": iso(NOW - timedelta(days=30)),
                                           "valid_to": iso(NOW + timedelta(days=335))})
    assert judge_client.post("/decision/evaluate", json=body).json()["decision"] == ALLOW


def test_expired_lab_safety_training_denied(seeded, judge_client):
    pid = "S1"
    for key, frm, to in [("ROOM#CHEMLAB#x", NOW - timedelta(hours=1), NOW + timedelta(hours=1)),
                         ("TRAINING#LAB_SAFETY#2025", NOW - timedelta(days=400), NOW - timedelta(days=35))]:
        seeded["authorization"].put_item(Item={"person_id": pid, "grant_key": key,
                                               "valid_from": iso(frm), "valid_to": iso(to)})
    body = {"person_id": pid, "room_id": "CHEMLAB",
            "evidence": {"liveness": 97.0, "face_person_id": pid, "face_similarity": 99.0}}
    assert judge_client.post("/decision/evaluate", json=body).json()["decision"] == DENY
