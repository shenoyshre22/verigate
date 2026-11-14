"""Optional Bedrock reporting. Explains decisions that were ALREADY made.

Bedrock never decides access, never overrides a failed biometric check, revocation or suspension.
Only decision, reasons, mode and computed numbers are sent: never images, templates, scores of
biometric matches, person names or evidence. On any Bedrock error a deterministic fallback is returned
and the access decision is unaffected.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

DEFAULT_TEMPERATURE = 0.2
# Token budgets include the model's reasoning tokens (Claude Haiku 5.5 returns reasoningContent),
# so they are larger than the visible output; the prompts cap length (1 sentence / 5 bullets).
EXPLAIN_MAX_TOKENS = 300
REPORT_MAX_TOKENS = 1000
ALLOWED_EXPLAIN_FIELDS = ("decision", "reasons", "mode")
DECISION_WORDS = ("ALLOW", "DENY", "REQUEST_VERIFICATION")

_SYSTEM_EXPLAIN = (
    "You explain a campus door access decision to a security guard in ONE short, plain-English sentence. "
    "Use only the facts in the JSON. State the decision exactly as given. Do not change, question, soften "
    "or second-guess it, and do not suggest overriding it."
)
_SYSTEM_REPORT = (
    "You write a short audit summary for a campus security administrator: at most 5 bullet points, each "
    "starting with '- '. Use only the numbers in the JSON. Do not invent, estimate or extrapolate figures. "
    "Say 'not available' for anything that is null."
)


@dataclass
class Generated:
    text: str
    source: str                      # "bedrock" or "fallback"
    model_id: Optional[str]
    latency_ms: Optional[float]
    temperature_applied: Optional[bool] = None
    error: Optional[str] = None
    sent: dict = field(default_factory=dict)  # exactly what was sent (for tests and audit)

    def as_dict(self) -> dict:
        out = {"source": self.source, "model_id": self.model_id, "latency_ms": self.latency_ms,
               "temperature_applied": self.temperature_applied}
        if self.error:
            out["fallback_reason"] = self.error
        return out


def model_id() -> str:
    return os.environ.get("BEDROCK_MODEL_ID", "").strip()


def _client():
    import boto3
    from botocore.config import Config

    return boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION", "us-east-1"),
                        config=Config(connect_timeout=3, read_timeout=15, retries={"max_attempts": 2, "mode": "standard"}))


def _is_temperature_rejection(e: Exception) -> bool:
    resp = getattr(e, "response", {}) or {}
    msg = str(resp.get("Error", {}).get("Message", "")) or str(e)
    return resp.get("Error", {}).get("Code") == "ValidationException" and "temperature" in msg.lower()


def generate(system: str, data: dict, max_tokens: int, fallback: Callable[[], str], client=None,
             validate: Optional[Callable[[str], bool]] = None) -> Generated:
    """Ask Bedrock; on any failure (or a validator rejecting the text) return the deterministic fallback."""
    model = model_id()
    started = time.perf_counter()
    if not model:
        return Generated(fallback(), "fallback", None, None, error="BEDROCK_MODEL_ID not set", sent=data)
    messages = [{"role": "user", "content": [{"text": json.dumps(data, default=str, sort_keys=True)}]}]
    config: dict[str, Any] = {"maxTokens": max_tokens, "temperature": DEFAULT_TEMPERATURE}
    temperature_applied = True
    try:
        c = client or _client()
        try:
            r = c.converse(modelId=model, system=[{"text": system}], messages=messages, inferenceConfig=config)
        except Exception as e:  # noqa: BLE001
            if not _is_temperature_rejection(e):
                raise
            # Some newer models reject temperature; retry once without it and say so.
            config.pop("temperature")
            temperature_applied = False
            r = c.converse(modelId=model, system=[{"text": system}], messages=messages, inferenceConfig=config)
        if r.get("stopReason") == "max_tokens":
            raise ValueError("truncated (max_tokens)")  # never show a cut-off explanation or summary
        text = "".join(b.get("text", "") for b in r["output"]["message"]["content"]).strip()  # skips reasoning blocks
        if not text:
            raise ValueError("empty response")
        if validate and not validate(text):
            raise ValueError("response failed validation")
    except Exception as e:  # noqa: BLE001 - reporting must never break or change access decisions
        code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
        return Generated(fallback(), "fallback", model, round((time.perf_counter() - started) * 1000, 1),
                         temperature_applied, error=code or type(e).__name__, sent=data)
    return Generated(text, "bedrock", model, round((time.perf_counter() - started) * 1000, 1),
                     temperature_applied, sent=data)


# --- explanations -------------------------------------------------------------------
def explain_facts(decision: dict) -> dict:
    """The only fields Bedrock sees: decision, reasons, mode."""
    return {"decision": str(decision.get("decision")),
            "reasons": [str(r)[:200] for r in (decision.get("reasons") or [])][:10],
            "mode": str(decision.get("mode") or "online")}


def explain_fallback(facts: dict) -> str:
    reasons = "; ".join(facts["reasons"]) or "no reason recorded"
    verb = {"ALLOW": "Access granted", "DENY": "Access denied",
            "REQUEST_VERIFICATION": "Extra verification required"}.get(facts["decision"], facts["decision"])
    return f"{verb}: {reasons}."


def _consistent_with(decision: str) -> Callable[[str], bool]:
    """Reject text that names a different decision keyword than the one actually made."""
    others = [w for w in DECISION_WORDS if w != decision]

    def ok(text: str) -> bool:
        return not any(re.search(rf"\b{w}\b", text) for w in others)
    return ok


def explain(decision: dict, client=None) -> Generated:
    facts = explain_facts(decision)
    return generate(_SYSTEM_EXPLAIN, facts, EXPLAIN_MAX_TOKENS, lambda: explain_fallback(facts), client,
                    validate=_consistent_with(facts["decision"]))


# --- audit summary -------------------------------------------------------------------
def report_fallback(m: dict) -> str:
    d = m.get("decisions", {})
    lines = [
        f"- {m.get('total', 0)} access decisions from {m.get('from')} to {m.get('to')}: "
        f"{d.get('ALLOW', 0)} ALLOW, {d.get('DENY', 0)} DENY, {d.get('REQUEST_VERIFICATION', 0)} REQUEST_VERIFICATION.",
        f"- Spoof denials: {m.get('spoof_denials', 0)}.",
        f"- Conflicting-record decisions: {m.get('conflicts', 0)}.",
        f"- Stale-revocation denials: {m.get('stale_revocation_denials', 0)}.",
        f"- Decision time: avg {m.get('decision_ms_avg')} ms, p95 {m.get('decision_ms_p95')} ms.",
    ]
    return "\n".join(lines)


def report(metrics: dict, client=None) -> Generated:
    return generate(_SYSTEM_REPORT, metrics, REPORT_MAX_TOKENS, lambda: report_fallback(metrics), client)
