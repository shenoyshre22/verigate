from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.modules.decision_engine import api
from backend.modules.decision_engine.audit_store import MARKER_PARTITIONS, AuditLog
from backend.modules.decision_engine.context_loader import ContextLoader
from backend.modules.decision_engine.face_match import ServerFaceMatcher
from backend.modules.decision_engine.liveness import LivenessVerifier

from .fakes import FakeRekognition, FakeS3, campus_tables

NOW = datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SENSITIVE_ROOMS", "EXAMHALL,CHEMLAB")
    # Engine tests send scores directly. Production default is false; tests in test_liveness.py switch it off.
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "true")
    monkeypatch.delenv("FRESHNESS_MINUTES", raising=False)
    monkeypatch.delenv("OFFLINE_CACHE_MAX_AGE_MINUTES", raising=False)


@pytest.fixture
def tables():
    """Synthetic campus records mirroring aws/dynamodb/seed.py (no AWS calls)."""
    t = campus_tables()
    for person in [
        {"person_id": "P001", "status": "active", "rfid_card_id": "CARD-A1", "updated_at": iso(NOW - timedelta(hours=1))},
        {"person_id": "P002", "status": "suspended", "rfid_card_id": "CARD-B2", "updated_at": iso(NOW)},
        {"person_id": "P003", "status": "active", "rfid_card_id": "CARD-C3", "updated_at": iso(NOW)},
    ]:
        t["identities"].put_item(Item=person)
    for grant in [
        {"person_id": "P001", "grant_key": "ROOM#LAB3#a", "valid_from": iso(NOW - timedelta(hours=1)),
         "valid_to": iso(NOW + timedelta(hours=3))},
        {"person_id": "P001", "grant_key": "ROOM#EXAMHALL#a", "valid_from": iso(NOW - timedelta(hours=1)),
         "valid_to": iso(NOW + timedelta(hours=2))},
        {"person_id": "P001", "grant_key": "ROOM#LAB9#old", "valid_from": iso(NOW - timedelta(days=2)),
         "valid_to": iso(NOW - timedelta(days=1))},
        {"person_id": "P003", "grant_key": "PASS#LAB1#a", "valid_from": iso(NOW - timedelta(minutes=5)),
         "valid_to": iso(NOW + timedelta(minutes=85))},
    ]:
        t["authorization"].put_item(Item=grant)
    t["revocations"].put_item(Item={"subject_id": "CARD-X9", "revoked_at": iso(NOW - timedelta(hours=2))})
    t["revocations"].put_item(Item={"subject_id": "SYNC#campus", "last_refreshed_at": iso(NOW - timedelta(minutes=5))})
    return t


@pytest.fixture
def loader(tables):
    return ContextLoader(tables["identities"], tables["authorization"], tables["revocations"])


@pytest.fixture
def audit_log(tables):
    return AuditLog(tables["audit"])


@pytest.fixture
def rekognition():
    return FakeRekognition()


FACE_BUCKET = "test-face-refs"


@pytest.fixture
def s3():
    return FakeS3()


def make_client(loader, audit_log, rekognition=None, s3=None):
    rekognition = rekognition or FakeRekognition()
    matcher = ServerFaceMatcher(rekognition=rekognition, s3=s3 or FakeS3(), bucket=FACE_BUCKET)
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_loader] = lambda: loader
    app.dependency_overrides[api.get_audit_log] = lambda: audit_log
    app.dependency_overrides[api.get_liveness_verifier] = lambda: LivenessVerifier(rekognition)
    app.dependency_overrides[api.get_face_matcher] = lambda: matcher
    app.dependency_overrides[api.get_clock] = lambda: (lambda: NOW)
    return TestClient(app)


@pytest.fixture
def client(loader, audit_log, rekognition, s3):
    return make_client(loader, audit_log, rekognition, s3)


def audit_records(tables):
    return [i for i in tables["audit"].items.values() if i["day"] not in MARKER_PARTITIONS]
