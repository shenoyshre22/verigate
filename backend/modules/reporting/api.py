"""Bedrock-backed explanations and audit summaries. Read-only over the audit log; never decides access.

POST /decision/explain  {"request_id": "<attempt_id>", "day"?: "YYYY-MM-DD"}  or  {"decision": {...}}
POST /report/summary    {"since"?: "YYYY-MM-DD"}   (max 7 days back)

The original decision and reasons are returned unchanged next to the explanation.
"""
from __future__ import annotations

import math
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Literal, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from backend.modules.decision_engine.api import _NoBiometrics, get_clock
from backend.modules.decision_engine.audit_store import MARKER_PARTITIONS

from . import bedrock_report

router = APIRouter(tags=["reporting"])
MAX_SUMMARY_DAYS = 7


class DecisionPayload(_NoBiometrics):
    decision: Literal["ALLOW", "REQUEST_VERIFICATION", "DENY"]
    reasons: list[str] = Field(default_factory=list, max_length=10)
    mode: Optional[str] = Field(default="online", max_length=32)


class ExplainRequest(_NoBiometrics):
    request_id: Optional[str] = Field(default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    day: Optional[date] = None
    decision: Optional[DecisionPayload] = None

    @model_validator(mode="after")
    def _one_source(self) -> "ExplainRequest":
        if bool(self.request_id) == bool(self.decision):
            raise ValueError("send exactly one of request_id or decision")
        return self


class SummaryRequest(_NoBiometrics):
    since: Optional[date] = None


class AuditReader:
    """Reads audit records by day partition (dynamodb:Query on the audit table)."""

    def __init__(self, table=None):
        self._table = table

    @property
    def table(self):
        if self._table is None:
            import boto3

            self._table = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1")
                                         ).Table(os.environ["AUDIT_TABLE"])
        return self._table

    def day(self, day: str) -> list[dict]:
        items, kw = [], {"KeyConditionExpression": Key("day").eq(day)}
        while True:
            page = self.table.query(**kw)
            items += page.get("Items", [])
            if "LastEvaluatedKey" not in page:
                return items
            kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def find(self, attempt_id: str, days: list[str]) -> Optional[dict]:
        for d in days:
            for item in self.day(d):
                if item.get("attempt_id") == attempt_id:
                    return item
        return None


_reader: Optional[AuditReader] = None


def get_audit_reader() -> AuditReader:
    global _reader
    if _reader is None:
        _reader = AuditReader()
    return _reader


def get_bedrock_client():
    return None  # None -> bedrock_report creates the real bedrock-runtime client; tests override


# --- metrics computed in code (Bedrock only words them) ------------------------------
def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def compute_metrics(records: list[dict], start: str, end: str) -> dict:
    decisions = {"ALLOW": 0, "DENY": 0, "REQUEST_VERIFICATION": 0}
    spoof = conflicts = stale_rev = 0
    times = []
    for r in records:
        d = r.get("decision")
        if d in decisions:
            decisions[d] += 1
        reasons = " ".join(str(x) for x in r.get("reasons") or [])
        if d == "DENY" and "spoof suspected" in reasons:
            spoof += 1
        if "conflicting" in reasons:
            conflicts += 1
        if d == "DENY" and "revocation list could not be refreshed" in reasons:
            stale_rev += 1
        ms = _num(r.get("decision_ms"))
        if ms is not None:
            times.append(ms)
    times.sort()
    p95 = times[max(math.ceil(0.95 * len(times)) - 1, 0)] if times else None  # nearest-rank
    return {
        "from": start, "to": end, "total": len(records), "decisions": decisions,
        "spoof_denials": spoof, "conflicts": conflicts, "stale_revocation_denials": stale_rev,
        "offline_synced": sum(1 for r in records if r.get("mode") == "offline-synced"),
        "decision_ms_avg": round(sum(times) / len(times), 2) if times else None,
        "decision_ms_p95": round(p95, 2) if p95 is not None else None,
        "decision_ms_samples": len(times),
    }


# --- routes -------------------------------------------------------------------------
@router.post("/decision/explain")
def explain_decision(
    req: ExplainRequest,
    reader: AuditReader = Depends(get_audit_reader),
    bedrock=Depends(get_bedrock_client),
    clock: Callable[[], datetime] = Depends(get_clock),
) -> dict:
    if req.decision:
        original = req.decision.model_dump()
    else:
        today = clock().date()
        days = [req.day.isoformat()] if req.day else [today.isoformat(), (today - timedelta(days=1)).isoformat()]
        try:
            record = reader.find(req.request_id, days)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=503, detail="audit log unavailable") from e
        if record is None:
            raise HTTPException(status_code=404, detail="no audit record for this request_id")
        original = {"decision": record["decision"], "reasons": list(record.get("reasons") or []),
                    "mode": record.get("mode")}
    gen = bedrock_report.explain(original, client=bedrock)
    return {"request_id": req.request_id, "decision": original["decision"], "reasons": original["reasons"],
            "mode": original.get("mode"), "explanation": gen.text, **gen.as_dict()}


@router.post("/report/summary")
def report_summary(
    req: SummaryRequest = SummaryRequest(),
    reader: AuditReader = Depends(get_audit_reader),
    bedrock=Depends(get_bedrock_client),
    clock: Callable[[], datetime] = Depends(get_clock),
) -> dict:
    today = clock().astimezone(timezone.utc).date()
    since = req.since or today
    if since > today or (today - since).days >= MAX_SUMMARY_DAYS:
        raise HTTPException(status_code=422, detail=f"since must be within the last {MAX_SUMMARY_DAYS} days")
    days = [(since + timedelta(days=i)).isoformat() for i in range((today - since).days + 1)]
    try:
        records = [i for d in days for i in reader.day(d) if i.get("day") not in MARKER_PARTITIONS]
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="audit log unavailable") from e
    metrics = compute_metrics(records, days[0], days[-1])
    gen = bedrock_report.report(metrics, client=bedrock)
    return {"metrics": metrics, "summary": gen.text, **gen.as_dict()}
