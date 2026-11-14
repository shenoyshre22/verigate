"""Server-side liveness evidence: the Lambda asks Rekognition Face Liveness for the result itself.

Only Status and Confidence are read. The ReferenceImage / AuditImages in the response are never
stored, logged or returned. Any lookup failure yields "no liveness evidence", which the engine
can never turn into an ALLOW on liveness alone.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from botocore.exceptions import BotoCoreError, ClientError

from .engine import liveness_verdict

SESSION_ID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


def client_evidence_allowed() -> bool:
    """ALLOW_CLIENT_EVIDENCE=true lets callers send liveness numbers directly (local tests / engine demo only)."""
    return os.environ.get("ALLOW_CLIENT_EVIDENCE", "false").strip().lower() in ("1", "true", "yes")


@dataclass(frozen=True)
class LivenessResult:
    status: str                         # SUCCEEDED / FAILED / EXPIRED / IN_PROGRESS / CREATED / ERROR
    confidence: Optional[float] = None  # only set when Status == SUCCEEDED
    verdict: Optional[str] = None       # SPOOF / LIVE / UNCERTAIN from the engine thresholds
    note: Optional[str] = None


class LivenessVerifier:
    def __init__(self, client=None):
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config

            self._client = boto3.client(
                "rekognition",
                region_name=os.environ.get("AWS_REGION", "us-east-1"),
                config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 2, "mode": "standard"}),
            )
        return self._client

    def check(self, session_id: str) -> LivenessResult:
        try:
            r = self.client.get_face_liveness_session_results(SessionId=session_id)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            return LivenessResult("ERROR", note=f"liveness lookup failed ({code})")
        except BotoCoreError as e:
            return LivenessResult("ERROR", note=f"liveness lookup failed ({type(e).__name__})")

        status = str(r.get("Status", "UNKNOWN"))
        confidence = r.get("Confidence")
        del r  # drop reference/audit images immediately
        if status != "SUCCEEDED":
            return LivenessResult(status, note=f"liveness session {status}")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            return LivenessResult(status, note="liveness result has no confidence")
        confidence = float(confidence)
        return LivenessResult(status, confidence, liveness_verdict(confidence))
