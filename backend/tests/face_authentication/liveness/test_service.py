from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from backend.modules.face_authentication.liveness.exceptions import (
    LivenessAccessError,
    LivenessOwnershipError,
    LivenessSessionExpiredError,
    LivenessThrottledError,
    LivenessTimeoutError,
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
        self.create_response: object = {"SessionId": "session-1"}
        self.result_response: object = {"Status": "SUCCEEDED", "Confidence": 98.25}
        self.create_error: Exception | None = None
        self.result_error: Exception | None = None
        self.create_calls = 0
        self.result_calls = 0

    def create_session(self, **kwargs):
        self.create_calls += 1
        if self.create_error:
            raise self.create_error
        return self.create_response

    def get_results(self, session_id: str):
        self.result_calls += 1
        if self.result_error:
            raise self.result_error
        return self.result_response


@pytest.fixture
def setup_liveness():
    store = MemoryOwnershipStore()
    client = FakeLivenessClient()
    service = FaceLivenessService(client, store, live_confidence_threshold=50)
    service.create_session(user_id="user-1", authentication_attempt_id="attempt-1")
    return service, client, store


def aws_error(code: str, operation: str = "GetFaceLivenessSessionResults") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "mocked"}}, operation)


def test_creates_session_and_persists_owner():
    store = MemoryOwnershipStore()
    client = FakeLivenessClient()
    service = FaceLivenessService(client, store, live_confidence_threshold=50)

    response = service.create_session(user_id="user-1", authentication_attempt_id="attempt-1")

    assert response == {
        "module": "face_liveness",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "session_id": "session-1",
        "status": "PENDING",
    }
    assert store.get_session("session-1").user_id == "user-1"


def test_rejects_unowned_attempt_without_creating_session():
    store = MemoryOwnershipStore()
    client = FakeLivenessClient()
    service = FaceLivenessService(client, store, live_confidence_threshold=50)

    with pytest.raises(LivenessOwnershipError):
        service.create_session(user_id="user-2", authentication_attempt_id="attempt-1")

    assert client.create_calls == 0


def test_successful_live_result_uses_actual_confidence(setup_liveness):
    service, client, _ = setup_liveness
    client.result_response = {"Status": "SUCCEEDED", "Confidence": 98.25}

    result = service.get_result(user_id="user-1", session_id="session-1")

    assert result.status == "LIVE"
    assert result.confidence == 98.25
    assert result.latency_ms is not None and result.latency_ms >= 0


def test_spoof_result_uses_actual_confidence(setup_liveness):
    service, client, _ = setup_liveness
    client.result_response = {"Status": "SUCCEEDED", "Confidence": 12.5}

    result = service.get_result(user_id="user-1", session_id="session-1")

    assert result.status == "SPOOF"
    assert result.confidence == 12.5


def test_pending_result_has_no_confidence(setup_liveness):
    service, client, _ = setup_liveness
    client.result_response = {"Status": "IN_PROGRESS"}

    result = service.get_result(user_id="user-1", session_id="session-1")

    assert result.status == "PENDING"
    assert result.confidence is None


def test_expired_result_and_local_session_expiry(setup_liveness):
    service, client, store = setup_liveness
    client.result_response = {"Status": "EXPIRED"}
    assert service.get_result(user_id="user-1", session_id="session-1").status == "EXPIRED"

    store.save_session(
        LivenessSessionOwnership(
            "old-session", "user-1", "attempt-1",
            datetime.now(timezone.utc) - timedelta(seconds=301),
        )
    )
    calls_before = client.result_calls
    assert service.get_result(user_id="user-1", session_id="old-session").status == "EXPIRED"
    assert client.result_calls == calls_before


@pytest.mark.parametrize("user_id,session_id", [("user-2", "session-1"), ("user-1", "unknown")])
def test_rejects_unauthorized_or_invalid_session_without_aws_call(setup_liveness, user_id, session_id):
    service, client, _ = setup_liveness

    with pytest.raises(LivenessOwnershipError):
        service.get_result(user_id=user_id, session_id=session_id)

    assert client.result_calls == 0


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (aws_error("AccessDeniedException"), LivenessAccessError),
        (aws_error("ThrottlingException"), LivenessThrottledError),
        (ReadTimeoutError(endpoint_url="https://rekognition.invalid"), LivenessTimeoutError),
        (aws_error("SessionExpiredException"), LivenessSessionExpiredError),
        (aws_error("SessionNotFoundException"), LivenessOwnershipError),
    ],
)
def test_maps_aws_errors_safely(setup_liveness, error, expected):
    service, client, _ = setup_liveness
    client.result_error = error

    with pytest.raises(expected):
        service.get_result(user_id="user-1", session_id="session-1")


@pytest.mark.parametrize(
    "response",
    [
        None,
        {"Unexpected": "shape"},
        {"Status": "SUCCEEDED"},
        {"Status": "SUCCEEDED", "Confidence": "high"},
        {"Status": "SUCCEEDED", "Confidence": 101},
        {"Status": "UNKNOWN", "Confidence": 100},
        {"Status": "FAILED"},
    ],
)
def test_malformed_or_unrecognized_provider_response_is_not_live(setup_liveness, response):
    service, client, _ = setup_liveness
    client.result_response = response

    result = service.get_result(user_id="user-1", session_id="session-1")

    assert result.status == "INDETERMINATE"
    assert result.confidence is None


def test_malformed_create_response_fails_closed():
    store = MemoryOwnershipStore()
    client = FakeLivenessClient()
    client.create_response = {"Unexpected": "shape"}
    service = FaceLivenessService(client, store, live_confidence_threshold=50)

    from backend.modules.face_authentication.liveness.exceptions import LivenessProviderError

    with pytest.raises(LivenessProviderError):
        service.create_session(user_id="user-1", authentication_attempt_id="attempt-1")
