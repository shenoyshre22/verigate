"""Typed request and response schemas for face liveness."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


LivenessStatus = Literal["PENDING", "LIVE", "SPOOF", "EXPIRED", "INDETERMINATE", "ERROR"]


class CreateLivenessSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authentication_attempt_id: str = Field(min_length=1, max_length=128)


class LivenessSessionResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    module: Literal["face_liveness"] = "face_liveness"
    user_id: str
    authentication_attempt_id: str
    session_id: str
    status: Literal["PENDING"] = "PENDING"


class LivenessResultResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    module: Literal["face_liveness"] = "face_liveness"
    user_id: str
    session_id: str
    status: LivenessStatus
    confidence: float | None = None
    latency_ms: float | None = None
    error: str | None = None
