"""Server-side liveness evidence: the Lambda asks Rekognition Face Liveness for the result itself.

Only Status and Confidence are read. The ReferenceImage / AuditImages in the response are never
stored, logged or returned. Any lookup failure yields "no liveness evidence", which the engine
can never turn into an ALLOW on liveness alone.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from botocore.exceptions import BotoCoreError, ClientError

from .engine import liveness_verdict

SESSION_ID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


DEFAULT_SESSION_TTL_SECONDS = 600


class LivenessUnavailable(RuntimeError):
    """A liveness session could not be created."""


def session_ttl_seconds() -> int:
    try:
        return max(int(os.environ.get("LIVENESS_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS)), 1)
    except ValueError:
        return DEFAULT_SESSION_TTL_SECONDS


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

    def create_session(self) -> str:
        """Start a Face Liveness session for a kiosk. AuditImagesLimit=0: Rekognition keeps no audit images.
        Raises LivenessUnavailable on any provider failure (the caller must not hand out a session)."""
        try:
            r = self.client.create_face_liveness_session(Settings={"AuditImagesLimit": 0})
        except (ClientError, BotoCoreError) as e:
            code = e.response.get("Error", {}).get("Code") if isinstance(e, ClientError) else type(e).__name__
            raise LivenessUnavailable(f"could not create liveness session ({code})") from e
        session_id = r.get("SessionId")
        if not isinstance(session_id, str) or not re.match(SESSION_ID_PATTERN, session_id):
            raise LivenessUnavailable("Rekognition returned an invalid session id")
        return session_id

    def check(self, session_id: str) -> LivenessResult:
        return self.check_with_reference(session_id)[0]

    def check_with_reference(self, session_id: str) -> tuple[LivenessResult, Optional[bytes]]:
        """Liveness result plus the session's reference image bytes (only when SUCCEEDED).
        The bytes are for an immediate in-memory face comparison; callers must never store or log them."""
        try:
            r = self.client.get_face_liveness_session_results(SessionId=session_id)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            return LivenessResult("ERROR", note=f"liveness lookup failed ({code})"), None
        except BotoCoreError as e:
            return LivenessResult("ERROR", note=f"liveness lookup failed ({type(e).__name__})"), None

        status = str(r.get("Status", "UNKNOWN"))
        confidence = r.get("Confidence")
        reference = (r.get("ReferenceImage") or {}).get("Bytes")
        del r  # drop the audit images and everything else immediately
        if status != "SUCCEEDED":
            return LivenessResult(status, note=f"liveness session {status}"), None
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            return LivenessResult(status, note="liveness result has no confidence"), None
        confidence = float(confidence)
        reference = reference if isinstance(reference, (bytes, bytearray)) and reference else None
        return LivenessResult(status, confidence, liveness_verdict(confidence)), reference
