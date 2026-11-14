"""Bedrock explanations and summaries with Bedrock mocked (no AWS calls)."""
import json
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.modules.decision_engine import api as decision_api
from backend.modules.reporting import api as reporting_api
from backend.modules.reporting.api import AuditReader, compute_metrics

from ..decision_engine.conftest import NOW
from ..decision_engine.fakes import BrokenTable

MODEL = "us.anthropic.claude-haiku-5-5"


class FakeBedrock:
    def __init__(self, text="Access was denied because a spoof was suspected.", error=None, reject_temperature=False):
        self.text, self.error, self.reject_temperature = text, error, reject_temperature
        self.calls = []

    def converse(self, modelId, system, messages, inferenceConfig):  # noqa: N803
        self.calls.append({"modelId": modelId, "system": system, "messages": messages, "config": dict(inferenceConfig)})
        if self.reject_temperature and "temperature" in inferenceConfig:
            raise ClientError({"Error": {"Code": "ValidationException",
                                         "Message": "`temperature` is deprecated for this model."}}, "Converse")
        if self.error:
            raise self.error
        return {"output": {"message": {"content": [{"text": self.text}]}}}

    def sent(self, i=-1) -> dict:
        return json.loads(self.calls[i]["messages"][0]["content"][0]["text"])


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("BEDROCK_MODEL_ID", MODEL)
    monkeypatch.setenv("ALLOW_CLIENT_EVIDENCE", "true")
    monkeypatch.setenv("SENSITIVE_ROOMS", "EXAMHALL,CHEMLAB")


@pytest.fixture
def bedrock():
    return FakeBedrock()


@pytest.fixture
def app_client(tables, loader, audit_log, bedrock):
    """Decision + reporting routers sharing the same fake audit table."""
    from ..decision_engine.conftest import make_client

    c = make_client(loader, audit_log)
    c.app.include_router(reporting_api.router)
    c.app.dependency_overrides[reporting_api.get_audit_reader] = lambda: AuditReader(tables["audit"])
    c.app.dependency_overrides[reporting_api.get_bedrock_client] = lambda: bedrock
    return c


# pull the decision-engine fixtures (tables, loader, audit_log ...) into this package
from ..decision_engine.conftest import audit_log, loader, rekognition, s3, tables  # noqa: E402,F401


SPOOF = {"decision": "DENY", "reasons": ["spoof suspected (liveness status SPOOF)"], "mode": "online"}


def evaluate(c, **body):
    body.setdefault("room_id", "LAB3")
    return c.post("/decision/evaluate", json=body).json()


# --- /decision/explain ------------------------------------------------------------------
def test_explain_payload_success(app_client, bedrock):
    r = app_client.post("/decision/explain", json={"decision": SPOOF})
    body = r.json()
    assert r.status_code == 200 and body["source"] == "bedrock" and body["model_id"] == MODEL
    assert body["explanation"] == bedrock.text and body["latency_ms"] >= 0
    assert body["decision"] == "DENY" and body["reasons"] == SPOOF["reasons"]  # unchanged
    call = bedrock.calls[0]
    assert call["config"] == {"maxTokens": 300, "temperature": 0.2} and call["modelId"] == MODEL
    assert bedrock.sent() == SPOOF


def test_explain_by_request_id_from_audit(app_client, bedrock):
    out = evaluate(app_client, person_id="P001",
                   evidence={"liveness": 97, "face_person_id": "P001", "face_similarity": 99})
    assert out["decision"] == "ALLOW"
    body = app_client.post("/decision/explain", json={"request_id": out["attempt_id"]}).json()
    assert body["decision"] == "ALLOW" and body["reasons"] == out["reasons"] and body["request_id"] == out["attempt_id"]
    sent = bedrock.sent()
    assert set(sent) == {"decision", "reasons", "mode"}  # no evidence, scores, ids or context
    blob = json.dumps(bedrock.calls)
    for leaked in ("liveness", "face_similarity", "face_person_id", "P001", "evidence", "97", "99"):
        assert leaked not in blob.replace("liveness status", ""), leaked


def test_bedrock_error_falls_back_and_keeps_decision(app_client, bedrock):
    bedrock.error = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "SCP"}}, "Converse")
    body = app_client.post("/decision/explain", json={"decision": SPOOF}).json()
    assert body["source"] == "fallback" and body["fallback_reason"] == "AccessDeniedException"
    assert body["explanation"] == "Access denied: spoof suspected (liveness status SPOOF)."
    assert body["decision"] == "DENY" and body["reasons"] == SPOOF["reasons"]


def test_temperature_rejection_retries_without_it(app_client, bedrock):
    bedrock.reject_temperature = True
    body = app_client.post("/decision/explain", json={"decision": SPOOF}).json()
    assert body["source"] == "bedrock" and body["temperature_applied"] is False
    assert [c["config"] for c in bedrock.calls] == [{"maxTokens": 300, "temperature": 0.2}, {"maxTokens": 300}]


def test_explanation_naming_another_decision_is_replaced(app_client, bedrock):
    bedrock.text = "Although DENY was returned, the guard may ALLOW entry."
    body = app_client.post("/decision/explain", json={"decision": SPOOF}).json()
    assert body["source"] == "fallback" and body["decision"] == "DENY"


def test_model_not_configured_falls_back(app_client, bedrock, monkeypatch):
    monkeypatch.setenv("BEDROCK_MODEL_ID", "")
    body = app_client.post("/decision/explain", json={"decision": SPOOF}).json()
    assert body["source"] == "fallback" and bedrock.calls == []


@pytest.mark.parametrize("extra", [{"face_image": "AAAA"}, {"evidence": {"liveness": 97}}, {"template": "x"}])
def test_biometric_or_extra_fields_rejected(app_client, bedrock, extra):
    r = app_client.post("/decision/explain", json={"decision": {**SPOOF, **extra}})
    assert r.status_code == 422 and bedrock.calls == []


def test_unknown_request_id_404(app_client):
    assert app_client.post("/decision/explain", json={"request_id": "nope"}).status_code == 404


def test_needs_exactly_one_source(app_client):
    assert app_client.post("/decision/explain", json={}).status_code == 422
    assert app_client.post("/decision/explain", json={"request_id": "a", "decision": SPOOF}).status_code == 422


# --- /report/summary ------------------------------------------------------------------
def _records():
    def r(decision, reasons, ms, mode="online"):
        return {"day": "2026-11-14", "decision": decision, "reasons": reasons, "decision_ms": ms, "mode": mode}
    return [
        r("ALLOW", ["live person and identity verified"], 10),
        r("ALLOW", ["live person and identity verified"], 20),
        r("DENY", ["spoof suspected (liveness status SPOOF)"], 30),
        r("DENY", ["revocation list could not be refreshed; sensitive room stays closed"], 40),
        r("REQUEST_VERIFICATION", ["conflicting records from equally authoritative sources"], 50),
        r("DENY", ["conflicting authoritative records for a sensitive room"], 1000),
        r("ALLOW", ["offline: card and on-device fingerprint verified"], None, "offline-synced"),
    ]


def test_metrics_computed_in_code():
    m = compute_metrics(_records(), "2026-11-14", "2026-11-14")
    assert m["decisions"] == {"ALLOW": 3, "DENY": 3, "REQUEST_VERIFICATION": 1} and m["total"] == 7
    assert (m["spoof_denials"], m["conflicts"], m["stale_revocation_denials"], m["offline_synced"]) == (1, 2, 1, 1)
    assert m["decision_ms_avg"] == 191.67 and m["decision_ms_p95"] == 1000 and m["decision_ms_samples"] == 6


def test_summary_route_sends_only_numbers(app_client, bedrock):
    evaluate(app_client, person_id="P001", evidence={"liveness": 97, "face_person_id": "P001", "face_similarity": 99})
    evaluate(app_client, person_id="P001", evidence={"liveness_status": "SPOOF", "face_person_id": "P001",
                                                     "face_similarity": 99})
    bedrock.text = "- 2 decisions\n- 1 spoof denial"
    body = app_client.post("/report/summary", json={}).json()
    assert body["source"] == "bedrock" and body["summary"] == bedrock.text
    assert body["metrics"]["decisions"]["ALLOW"] == 1 and body["metrics"]["spoof_denials"] == 1
    assert bedrock.sent() == body["metrics"] and bedrock.calls[0]["config"]["maxTokens"] == 1000
    assert "P001" not in json.dumps(bedrock.calls)


def test_summary_fallback_is_deterministic(app_client, bedrock):
    bedrock.error = ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow"}}, "Converse")
    evaluate(app_client, person_id="P001", evidence={"liveness": 97, "face_person_id": "P001", "face_similarity": 99})
    body = app_client.post("/report/summary", json={}).json()
    assert body["source"] == "fallback" and body["summary"].startswith("- 1 access decisions from 2026-11-14")
    assert body["summary"].count("\n- ") == 4  # exactly 5 bullets


def test_summary_range_limited(app_client):
    old = (NOW - timedelta(days=8)).date().isoformat()
    assert app_client.post("/report/summary", json={"since": old}).status_code == 422


def test_summary_audit_unavailable_503(app_client):
    app_client.app.dependency_overrides[reporting_api.get_audit_reader] = lambda: AuditReader(BrokenTable())
    assert app_client.post("/report/summary", json={}).status_code == 503


def test_reporting_never_changes_live_decisions(app_client, bedrock):
    """Explaining is read-only: the decision engine's result for the same request is identical before and after."""
    body = {"person_id": "P002", "evidence": {"liveness": 97, "face_person_id": "P002", "face_similarity": 99}}
    before = evaluate(app_client, **body)
    bedrock.text = "This person should be let in."
    app_client.post("/decision/explain", json={"request_id": before["attempt_id"]})
    after = evaluate(app_client, **body)
    assert before["decision"] == after["decision"] == "DENY" and before["reasons"] == after["reasons"]


_ = decision_api  # imported for dependency keys used by make_client


def test_truncated_output_falls_back(app_client, bedrock):
    real = bedrock.converse

    def truncated(**kw):
        r = real(**kw)
        r["stopReason"] = "max_tokens"
        r["output"]["message"]["content"] = [{"reasoningContent": {"reasoningText": {"text": "..."}}},
                                             {"text": "- Denial re"}]
        return r

    bedrock.converse = truncated
    body = app_client.post("/report/summary", json={}).json()
    assert body["source"] == "fallback" and "Denial re" not in body["summary"]


def test_reasoning_blocks_are_not_shown(app_client, bedrock):
    real = bedrock.converse

    def with_reasoning(**kw):
        r = real(**kw)
        r["stopReason"] = "end_turn"
        r["output"]["message"]["content"] = [{"reasoningContent": {"reasoningText": {"text": "internal"}}},
                                             {"text": "Access was denied because a spoof was suspected."}]
        return r

    bedrock.converse = with_reasoning
    body = app_client.post("/decision/explain", json={"decision": SPOOF}).json()
    assert body["source"] == "bedrock" and body["explanation"] == "Access was denied because a spoof was suspected."
