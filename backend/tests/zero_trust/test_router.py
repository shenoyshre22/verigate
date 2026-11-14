from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.modules.zero_trust.engine import ZeroTrustDecisionEngine
from backend.modules.zero_trust.router import get_zero_trust_engine, router
from backend.tests.zero_trust.test_engine import NOW, build_engine


def request_body(**overrides):
    body = {
        "request_id": "request-1",
        "user_id": "user-1",
        "authentication_attempt_id": "attempt-1",
        "resource": {"resource_id": "LAB_101"},
        "action": {"action_id": "ENTER"},
        "requested_at": NOW.isoformat(),
    }
    body.update(overrides)
    return body


def make_app(engine=None):
    app = FastAPI()
    app.include_router(router)
    if engine is not None:
        app.state.zero_trust_decision_engine = engine
    return app


def test_decide_endpoint_serializes_structured_decision_and_summaries():
    client = TestClient(make_app(build_engine()))

    response = client.post("/api/v1/access/decide", json=request_body())

    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "ALLOW"
    assert result["access_granted"] is True
    assert result["evidence_summary"]["evidence_count"] == 2
    assert result["authorization_summary"]["permitted"] is True
    assert result["conflict_resolution_summary"]["resolution_count"] == 2
    assert "revocation_summary" in result
    assert "face_image" not in result


def test_client_cannot_submit_evidence_or_campus_authority_claims():
    client = TestClient(make_app(build_engine()))

    response = client.post(
        "/api/v1/access/decide",
        json=request_body(
            evidence=[{"module": "FACE_RECOGNITION", "outcome": "SUCCESS"}],
            source_authority=100,
            authorization_records=[{"status": "ACTIVE"}],
        ),
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "INVALID_ACCESS_REQUEST",
            "message": "Request does not match the access contract.",
        }
    }


def test_invalid_request_fields_return_consistent_422_error():
    client = TestClient(make_app(build_engine()))

    response = client.post("/api/v1/access/decide", json={"request_id": ""})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_ACCESS_REQUEST"


def test_malformed_json_returns_consistent_400_error():
    client = TestClient(make_app(build_engine()))

    response = client.post(
        "/api/v1/access/decide",
        content="{not valid json",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_JSON"


def test_unconfigured_engine_returns_safe_503_error():
    client = TestClient(make_app())

    response = client.post("/api/v1/access/decide", json=request_body())

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DECISION_ENGINE_UNAVAILABLE"


def test_dependency_override_injects_mock_engine_instance():
    engine = build_engine()
    app = make_app()
    app.dependency_overrides[get_zero_trust_engine] = lambda: engine

    response = TestClient(app).post("/api/v1/access/decide", json=request_body())

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_raised_engine_exception_returns_sanitized_503():
    class FailingEngine:
        def evaluate(self, request):
            raise RuntimeError("secret stack/provider details")

    response = TestClient(make_app(FailingEngine())).post(
        "/api/v1/access/decide", json=request_body()
    )

    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "DECISION_UNAVAILABLE",
            "message": "A safe access decision could not be completed.",
        }
    }

