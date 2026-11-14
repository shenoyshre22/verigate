"""Standalone HTTP router for face liveness; mount only after wiring auth and ownership."""

import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from .exceptions import (
    LivenessAccessError,
    LivenessConfigurationError,
    LivenessOwnershipError,
    LivenessProviderError,
    LivenessSessionExpiredError,
    LivenessThrottledError,
    LivenessTimeoutError,
)
from .rekognition_liveness_client import RekognitionLivenessClient
from .schemas import CreateLivenessSessionRequest, LivenessResultResponse, LivenessSessionResponse
from .service import FaceLivenessService, LivenessOwnershipStore

router = APIRouter(prefix="/api/v1/face-auth/liveness", tags=["face-liveness"])


def get_ownership_store() -> LivenessOwnershipStore:
    """Integration must override this with a durable, access-controlled store."""
    raise HTTPException(status_code=503, detail="Liveness ownership storage is not configured.")


def get_authenticated_user_id() -> str:
    """Integration must override with the host application's verified principal."""
    raise HTTPException(status_code=503, detail="Authentication principal is not configured.")


def get_liveness_service(
    store: Annotated[LivenessOwnershipStore, Depends(get_ownership_store)],
) -> FaceLivenessService:
    try:
        threshold = float(os.getenv("FACE_LIVENESS_CONFIDENCE_THRESHOLD", "50"))
        # Rekognition Face Liveness SessionIds expire three minutes after creation.
        # A slightly shorter local TTL avoids querying AWS at its expiry boundary.
        ttl = int(os.getenv("FACE_LIVENESS_SESSION_TTL_SECONDS", "170"))
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        if not region:
            raise ValueError("region missing")
        return FaceLivenessService(
            RekognitionLivenessClient(region_name=region),
            store,
            live_confidence_threshold=threshold,
            session_ttl_seconds=ttl,
        )
    except (ValueError, LivenessConfigurationError) as error:
        raise HTTPException(status_code=500, detail="Liveness service configuration is invalid.") from error


def _handle_error(error: Exception) -> HTTPException:
    if isinstance(error, LivenessOwnershipError):
        return HTTPException(status_code=404, detail="Liveness session or authentication attempt was not found.")
    if isinstance(error, LivenessSessionExpiredError):
        return HTTPException(status_code=410, detail="Liveness session has expired.")
    if isinstance(error, LivenessTimeoutError):
        return HTTPException(status_code=504, detail="Liveness provider timed out.")
    if isinstance(error, LivenessThrottledError):
        return HTTPException(status_code=503, detail="Liveness provider is temporarily throttling requests.")
    if isinstance(error, LivenessAccessError):
        return HTTPException(status_code=502, detail="Liveness provider access failed.")
    if isinstance(error, LivenessProviderError):
        return HTTPException(status_code=502, detail="Liveness provider failed.")
    return HTTPException(status_code=500, detail="Liveness request failed.")


@router.post("/session", response_model=LivenessSessionResponse, status_code=status.HTTP_201_CREATED)
def create_liveness_session(
    request: CreateLivenessSessionRequest,
    user_id: Annotated[str, Depends(get_authenticated_user_id)],
    service: Annotated[FaceLivenessService, Depends(get_liveness_service)],
) -> LivenessSessionResponse:
    try:
        return LivenessSessionResponse(**service.create_session(
            user_id=user_id,
            authentication_attempt_id=request.authentication_attempt_id,
        ))
    except (LivenessOwnershipError, LivenessAccessError, LivenessThrottledError,
            LivenessTimeoutError, LivenessProviderError, LivenessSessionExpiredError) as error:
        raise _handle_error(error) from error


@router.get("/session/{session_id}/result", response_model=LivenessResultResponse)
def get_liveness_result(
    session_id: str,
    user_id: Annotated[str, Depends(get_authenticated_user_id)],
    service: Annotated[FaceLivenessService, Depends(get_liveness_service)],
) -> LivenessResultResponse:
    try:
        result = service.get_result(user_id=user_id, session_id=session_id)
        return LivenessResultResponse(**result.__dict__)
    except (LivenessOwnershipError, LivenessAccessError, LivenessThrottledError,
            LivenessTimeoutError, LivenessProviderError, LivenessSessionExpiredError) as error:
        raise _handle_error(error) from error
