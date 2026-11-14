"""Face liveness workflow with mandatory attempt/session ownership storage."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError, ConnectTimeoutError, ReadTimeoutError

from .exceptions import (
    LivenessAccessError,
    LivenessConfigurationError,
    LivenessOwnershipError,
    LivenessPendingError,
    LivenessProviderError,
    LivenessSessionExpiredError,
    LivenessThrottledError,
    LivenessTimeoutError,
)
from .rekognition_liveness_client import RekognitionLivenessClient


@dataclass(frozen=True)
class LivenessSessionOwnership:
    session_id: str
    user_id: str
    authentication_attempt_id: str
    created_at: datetime


class LivenessOwnershipStore(Protocol):
    """Durable store that validates active attempts and binds AWS sessions to owners."""

    def validate_attempt(self, *, user_id: str, authentication_attempt_id: str) -> bool: ...

    def save_session(self, ownership: LivenessSessionOwnership) -> None: ...

    def get_session(self, session_id: str) -> LivenessSessionOwnership | None: ...


@dataclass(frozen=True)
class LivenessResult:
    module: str
    user_id: str
    session_id: str
    status: str
    confidence: float | None
    latency_ms: float | None
    error: str | None = None


class FaceLivenessService:
    def __init__(
        self,
        client: RekognitionLivenessClient,
        ownership_store: LivenessOwnershipStore,
        *,
        live_confidence_threshold: float,
        session_ttl_seconds: int = 300,
        output_config: dict[str, Any] | None = None,
    ) -> None:
        if ownership_store is None:
            raise LivenessConfigurationError("Liveness ownership store is required.")
        if not 0 <= live_confidence_threshold <= 100:
            raise LivenessConfigurationError("Liveness confidence threshold must be between 0 and 100.")
        if session_ttl_seconds <= 0:
            raise LivenessConfigurationError("Session TTL must be positive.")
        self._client = client
        self._store = ownership_store
        self._threshold = live_confidence_threshold
        self._ttl_seconds = session_ttl_seconds
        self._output_config = output_config

    def create_session(self, *, user_id: str, authentication_attempt_id: str) -> dict[str, str]:
        if not self._store.validate_attempt(user_id=user_id, authentication_attempt_id=authentication_attempt_id):
            raise LivenessOwnershipError("Authentication attempt is not owned by the requesting user.")
        try:
            response = self._client.create_session(output_config=self._output_config)
        except Exception as error:
            self._raise_provider_error(error)
        session_id = response.get("SessionId") if isinstance(response, dict) else None
        if not isinstance(session_id, str) or not session_id:
            raise LivenessProviderError("Amazon Rekognition returned an invalid session response.")
        # Bind before returning the ID, so clients cannot race an unowned session.
        self._store.save_session(LivenessSessionOwnership(
            session_id=session_id,
            user_id=user_id,
            authentication_attempt_id=authentication_attempt_id,
            created_at=datetime.now(timezone.utc),
        ))
        return {
            "module": "face_liveness",
            "user_id": user_id,
            "authentication_attempt_id": authentication_attempt_id,
            "session_id": session_id,
            "status": "PENDING",
        }

    def get_result(self, *, user_id: str, session_id: str) -> LivenessResult:
        ownership = self._store.get_session(session_id)
        if ownership is None or ownership.user_id != user_id:
            raise LivenessOwnershipError("Liveness session is not available to this user.")
        age = (datetime.now(timezone.utc) - ownership.created_at).total_seconds()
        if age >= self._ttl_seconds:
            return LivenessResult("face_liveness", user_id, session_id, "EXPIRED", None, None)
        started = time.perf_counter()
        try:
            response = self._client.get_results(session_id)
        except Exception as error:
            self._raise_provider_error(error)
        latency_ms = (time.perf_counter() - started) * 1000
        if not isinstance(response, dict) or not isinstance(response.get("Status"), str):
            return LivenessResult("face_liveness", user_id, session_id, "INDETERMINATE", None, latency_ms, "Malformed provider response.")
        aws_status = response["Status"].upper()
        if aws_status in {"IN_PROGRESS", "INPROGRESS", "PENDING"}:
            return LivenessResult("face_liveness", user_id, session_id, "PENDING", None, latency_ms)
        if aws_status == "EXPIRED":
            return LivenessResult("face_liveness", user_id, session_id, "EXPIRED", None, latency_ms)
        if aws_status == "FAILED":
            return LivenessResult("face_liveness", user_id, session_id, "INDETERMINATE", None, latency_ms, "Liveness analysis could not be completed.")
        if aws_status != "SUCCEEDED":
            return LivenessResult("face_liveness", user_id, session_id, "INDETERMINATE", None, latency_ms, "Unrecognized provider result status.")
        confidence = response.get("Confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 100:
            return LivenessResult("face_liveness", user_id, session_id, "INDETERMINATE", None, latency_ms, "Malformed provider confidence value.")
        return LivenessResult(
            "face_liveness", user_id, session_id,
            "LIVE" if confidence >= self._threshold else "SPOOF",
            float(confidence), latency_ms,
        )

    @staticmethod
    def _raise_provider_error(error: Exception) -> None:
        if isinstance(error, (ConnectTimeoutError, ReadTimeoutError, TimeoutError)):
            raise LivenessTimeoutError("Amazon Rekognition request timed out.") from error
        if isinstance(error, ClientError):
            code = error.response.get("Error", {}).get("Code", "")
            if code in {"AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException"}:
                raise LivenessAccessError("Amazon Rekognition access was denied.") from error
            if code in {"ThrottlingException", "ProvisionedThroughputExceededException"}:
                raise LivenessThrottledError("Amazon Rekognition is throttling requests.") from error
            if code in {"SessionNotFoundException", "ResourceNotFoundException"}:
                raise LivenessOwnershipError("Liveness session is not available.") from error
            if code in {"SessionExpiredException"}:
                raise LivenessSessionExpiredError("Liveness session has expired.") from error
            raise LivenessProviderError("Amazon Rekognition could not process the liveness request.") from error
        if isinstance(error, BotoCoreError):
            raise LivenessProviderError("Amazon Rekognition request failed.") from error
        if isinstance(error, (LivenessAccessError, LivenessThrottledError, LivenessTimeoutError,
                              LivenessOwnershipError, LivenessProviderError, LivenessSessionExpiredError)):
            raise error
        raise LivenessProviderError("Amazon Rekognition request failed.") from error
