from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EnrollmentResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    enrollment_status: Literal["ACTIVE", "DELETED"]
    enrolled_at: datetime
    model_name: str
    model_version: str
    detector_backend: str
    embedding_dimension: int = Field(gt=0)


class RecognitionResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    matched: bool
    user_id: str | None
    distance: float | None
    threshold: float
    recognition_status: Literal["MATCH", "UNKNOWN", "AMBIGUOUS"]
    model_name: str
    model_version: str


class TrustedFaceEvidence(BaseModel):
    """Server-created evidence passed only through an internal evidence sink."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    issuer_id: Literal["verigate.face_recognition"] = "verigate.face_recognition"
    module: Literal["FACE_RECOGNITION"] = "FACE_RECOGNITION"
    user_id: str
    authentication_attempt_id: str = Field(min_length=1, max_length=128)
    outcome: Literal["SUCCESS"] = "SUCCESS"
    issued_at: datetime
    distance: float = Field(ge=0, le=2)
    distance_threshold: float = Field(ge=0, le=2)
    model_name: str
    model_version: str
