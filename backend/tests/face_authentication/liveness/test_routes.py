from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.modules.face_authentication.liveness.exceptions import LivenessAccessError
from backend.modules.face_authentication.liveness.routes import (
    get_authenticated_user_id,
    get_liveness_service,
    router,
)
from backend.modules.face_authentication.liveness.service import (
    FaceLivenessService,
    LivenessSessionOwnership,
)


class MemoryOwnershipStore:
    def __init__(self) -> None:
        self.attempts = {("user-1", "attempt-1")}
        self.sessions: dict[str, LivenessSessionOwnership] = {}

    def validate_attempt(self, *, user_id: str, authentication_attempt_id: str) -> bool:
        return (user_id, authentication_attempt_id) in self.attempts

    def save_session(self, ownership: LivenessSessionOwnership) -> None:
        self.sessions[ownership.session_id] = ownership

    def get_session(self, session_id: str) -> LivenessSessionOwnership | None:
        return self.sessions.get(session_id)


class FakeLivenessClient:
    def __init__(self) -> None:
        self.result: object = {"Status": "SUCCEEDED", "Confidence": 94.75}
        self.create_calls = 0
        self.get_calls = 0
        self.get_error: Exception | None = None

    def create_session(self, **kwargs):
        self.create_calls += 1
        return {"SessionId": "session-1"}

    def get_results(self, session_id: str):
        self.get_calls += 1
        if self.get_error:
            raise self.get_error
        return self.result


@pytest.fixture
def api():
    store = MemoryOwnershipStore()
    aws = FakeLivenessClient()
    service = FaceLivenessService(aws, store, live_confidence_threshold=50)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_authenticated_user_id] = lambda: "user-1"
    app.dependency_overrides[get_liveness_service] = lambda: service
    with TestClient(app) as test_client:
        yield test_client, store, aws


def test_create_session_route_returns_session_and_persists_owner(api):
    client, store, aws = api

    response = client.post(
        "/api/v1/face-auth/liveness/session",
        json={"authentication_attempt_id": "attempt-1"},
    )

    assert response.status_code == 201
    assert response.json() == {
        "module": "face_liveness",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "session_id": "session-1",
        "status": "PENDING",
    }
    assert store.get_session("session-1").user_id == "user-1"
    assert aws.create_calls == 1


def test_create_route_does_not_accept_caller_selected_user_id(api):
    client, _, aws = api

    response = client.post(
        "/api/v1/face-auth/liveness/session",
        json={"authentication_attempt_id": "attempt-1", "user_id": "victim"},
    )

    assert response.status_code == 422
    assert aws.create_calls == 0


def test_create_route_rejects_attempt_not_owned_by_principal(api):
    client, _, aws = api

    response = client.post(
        "/api/v1/face-auth/liveness/session",
        json={"authentication_attempt_id": "another-attempt"},
    )

    assert response.status_code == 404
    assert aws.create_calls == 0


def test_result_route_returns_actual_live_confidence(api):
    client, store, _ = api
    store.save_session(LivenessSessionOwnership(
        "session-1", "user-1", "attempt-1", datetime.now(timezone.utc),
    ))

    response = client.get("/api/v1/face-auth/liveness/session/session-1/result")

    assert response.status_code == 200
    assert response.json()["status"] == "LIVE"
    assert response.json()["confidence"] == 94.75
    assert response.json()["latency_ms"] >= 0
    assert response.json()["module"] == "face_liveness"


@pytest.mark.parametrize(
    ("aws_result", "expected_status"),
    [
        ({"Status": "IN_PROGRESS"}, "PENDING"),
        ({"Status": "SUCCEEDED", "Confidence": 10.25}, "SPOOF"),
        ({"Status": "SUCCEEDED", "Confidence": "bad"}, "INDETERMINATE"),
    ],
)
def test_result_route_normalizes_pending_spoof_and_malformed_results(api, aws_result, expected_status):
    client, store, aws = api
    aws.result = aws_result
    store.save_session(LivenessSessionOwnership(
        "session-1", "user-1", "attempt-1", datetime.now(timezone.utc),
    ))

    response = client.get("/api/v1/face-auth/liveness/session/session-1/result")

    assert response.status_code == 200
    assert response.json()["status"] == expected_status


def test_result_route_hides_session_from_other_authenticated_user(api):
    client, store, aws = api
    store.save_session(LivenessSessionOwnership(
        "session-1", "user-1", "attempt-1", datetime.now(timezone.utc),
    ))
    client.app.dependency_overrides[get_authenticated_user_id] = lambda: "user-2"

    response = client.get("/api/v1/face-auth/liveness/session/session-1/result")

    assert response.status_code == 404
    assert aws.get_calls == 0


def test_result_route_maps_provider_failure_to_safe_http_error(api):
    client, store, aws = api
    store.save_session(LivenessSessionOwnership(
        "session-1", "user-1", "attempt-1", datetime.now(timezone.utc),
    ))
    aws.get_error = LivenessAccessError("sensitive internal provider message")

    response = client.get("/api/v1/face-auth/liveness/session/session-1/result")

    assert response.status_code == 502
    assert "sensitive" not in response.text


def test_routes_fail_closed_without_host_auth_and_ownership_wiring():
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    auth_missing = client.post(
        "/api/v1/face-auth/liveness/session",
        json={"authentication_attempt_id": "attempt-1"},
    )
    assert auth_missing.status_code == 503

    app.dependency_overrides[get_authenticated_user_id] = lambda: "user-1"
    # Even with a verified identity, no store means there is no safe route to AWS.
    ownership_missing = client.post(
        "/api/v1/face-auth/liveness/session",
        json={"authentication_attempt_id": "attempt-1"},
    )
    assert ownership_missing.status_code == 503
    assert ownership_missing.json()["detail"] == "Liveness ownership storage is not configured."

