"""Optional Bedrock reporting. Explains decisions that were ALREADY made.

Bedrock never decides access, never overrides a failed biometric check,
revocation or suspension. If Bedrock fails, a plain-text fallback is returned
and the access decision is unaffected.
"""
from __future__ import annotations

import json
import os

_SYSTEM_EXPLAIN = (
    "You explain a campus door access decision to a security guard in ONE short, plain sentence. "
    "Use only the facts in the JSON. Do not change, question or soften the decision."
)
_SYSTEM_REPORT = (
    "You write a short audit summary (max 6 bullet points) for a campus security manager from the JSON "
    "metrics given. Use only these numbers. Say 'not tested' for anything missing. Do not invent figures."
)


def _client():
    import boto3
    return boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION", "us-east-1"))


def _ask(system: str, data: dict, max_tokens: int) -> str:
    model = os.environ.get("BEDROCK_MODEL_ID", "")
    if not model:
        raise RuntimeError("BEDROCK_MODEL_ID not set")
    r = _client().converse(
        modelId=model,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": json.dumps(data, default=str)}]}],
        inferenceConfig={"maxTokens": max_tokens, "temperature": 0.2},
    )
    return r["output"]["message"]["content"][0]["text"]


def explain(decision: dict) -> str:
    """decision = {"decision": ..., "reasons": [...], ...} from the decision engine."""
    facts = {k: decision.get(k) for k in ("decision", "reasons", "mode", "liveness", "face_similarity")}
    try:
        return _ask(_SYSTEM_EXPLAIN, facts, 120)
    except Exception:
        return f"{decision.get('decision')}: " + "; ".join(decision.get("reasons", []))


def report(metrics: dict) -> str:
    try:
        return _ask(_SYSTEM_REPORT, metrics, 400)
    except Exception as e:
        return f"Report unavailable ({type(e).__name__}). Raw metrics: {json.dumps(metrics, default=str)}"
