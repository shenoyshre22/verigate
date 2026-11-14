"""Authenticated API boundary for face enrollment and 1:N identification."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field

from backend.modules.face_authentication.image_validator import MAX_IMAGE_BYTES
from backend.modules.face_authentication.recognition_exceptions import InvalidImageError
from .embedding_provider import DeepFaceEmbeddingProvider
from .errors import (
    FaceEnrollmentExists,
    FaceEnrollmentNotFound,
    FaceIdentityConfigurationError,
    FaceIdentityMultipleFaces,
    FaceIdentityNoFace,
    FaceIdentityProviderError,
    FaceIdentityStorageError,
)
from .schemas import EnrollmentResponse, RecognitionResponse, TrustedFaceEvidence
from .service import FaceIdentityService
from .storage import default_local_store

router = APIRouter(prefix="/api/v1/face", tags=["face-recognition"])
MAX_UPLOAD_BYTES = MAX_IMAGE_BYTES


class AuthenticatedPrincipal(BaseModel):
    """Only a host-authentication provider may construct/return this principal."""

    model_config = ConfigDict(frozen=True)

    subject_id: str = Field(min_length=1, max_length=128)
    roles: frozenset[str] = frozenset()
    authentication_attempt_id: str | None = None


class FaceEvidenceSink(Protocol):
    def submit(self, evidence: TrustedFaceEvidence) -> None: ...


class EnrollmentTargetProvider(Protocol):
    def resolve_user_id(self, requested_user_id: str, principal: AuthenticatedPrincipal) -> str: ...


def get_authenticated_principal() -> AuthenticatedPrincipal:
    """Fail closed until the host app wires a verified token/device principal."""
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Face API authentication provider is not configured.",
    )


def require_enrollment_admin(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_authenticated_principal)],
) -> AuthenticatedPrincipal:
    if "face:enroll" not in principal.roles and "admin" not in principal.roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Face enrollment permission is required.")
    return principal


def get_evidence_sink() -> FaceEvidenceSink | None:
    """The host must provide an in-process trusted evidence consumer."""
    return None


def get_enrollment_target_provider() -> EnrollmentTargetProvider | None:
    """The host must verify that the requested ID is a canonical enrolled campus identity."""
    return None


@lru_cache(maxsize=1)
def get_face_identity_service() -> FaceIdentityService:
    try:
        threshold_value = os.getenv("FACE_COSINE_DISTANCE_THRESHOLD")
        threshold = float(threshold_value) if threshold_value else None
        provider = DeepFaceEmbeddingProvider(
            model_name=os.getenv("DEEPFACE_MODEL_NAME", "ArcFace"),
            detector_backend=os.getenv("DEEPFACE_DETECTOR_BACKEND", "opencv"),
        )
        provider.initialize()
        return FaceIdentityService(provider, default_local_store(), distance_threshold=threshold)
    except (FaceIdentityConfigurationError, ValueError, OSError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Face recognition model or protected local storage is unavailable.",
        ) from error


async def _read_image(image: UploadFile) -> bytes:
    try:
        data = await image.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await image.close()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Image must be smaller than 5 MB.")
    return data


def _map_error(error: Exception) -> HTTPException:
    if isinstance(error, InvalidImageError):
        return HTTPException(status_code=400, detail=str(error))
    if isinstance(error, FaceIdentityNoFace):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, FaceIdentityMultipleFaces):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, ValueError):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, FaceEnrollmentExists):
        return HTTPException(status_code=409, detail=str(error))
    if isinstance(error, FaceEnrollmentNotFound):
        return HTTPException(status_code=404, detail=str(error))
    if isinstance(error, (FaceIdentityStorageError, FaceIdentityConfigurationError, FaceIdentityProviderError)):
        return HTTPException(status_code=503, detail=str(error))
    return HTTPException(status_code=503, detail="Face recognition operation failed safely.")


@router.post("/enroll", response_model=EnrollmentResponse, status_code=201)
async def enroll_face(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_enrollment_admin)],
    target_provider: Annotated[EnrollmentTargetProvider | None, Depends(get_enrollment_target_provider)],
    user_id: Annotated[str, Form(min_length=1, max_length=64)],
    image: Annotated[UploadFile, File()],
    replace: Annotated[bool, Form()] = False,
) -> EnrollmentResponse:
    if target_provider is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trusted campus identity provider is not configured.",
        )
    try:
        canonical_user_id = target_provider.resolve_user_id(user_id, principal)
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enrollment target is not an authorized campus identity.",
        ) from error
    if canonical_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enrollment target must use its canonical VERIGATE identity.",
        )
    data = await _read_image(image)
    try:
        metadata = get_face_identity_service().enroll(canonical_user_id, data, replace=replace)
        return EnrollmentResponse(
            user_id=metadata.user_id,
            enrollment_status=metadata.status,
            enrolled_at=metadata.enrolled_at,
            model_name=metadata.model_name,
            model_version=metadata.model_version,
            detector_backend=metadata.detector_backend,
            embedding_dimension=metadata.embedding_dimension,
        )
    except Exception as error:
        raise _map_error(error) from error


@router.post("/recognize", response_model=RecognitionResponse)
async def recognize_face(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_authenticated_principal)],
    image: Annotated[UploadFile, File()],
) -> RecognitionResponse:
    del principal  # identification requires an authenticated terminal/user context
    data = await _read_image(image)
    try:
        result = get_face_identity_service().identify(data)
        return RecognitionResponse(**result.__dict__)
    except Exception as error:
        raise _map_error(error) from error


@router.post("/verify", response_model=RecognitionResponse)
async def verify_face(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_authenticated_principal)],
    image: Annotated[UploadFile, File()],
    evidence_sink: Annotated[FaceEvidenceSink | None, Depends(get_evidence_sink)],
) -> RecognitionResponse:
    if not principal.authentication_attempt_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trusted authentication-attempt provider is not configured.",
        )
    data = await _read_image(image)
    try:
        result = get_face_identity_service().identify(data)
    except Exception as error:
        raise _map_error(error) from error

    if result.matched:
        if result.user_id != principal.subject_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Recognized identity does not match the authenticated principal.",
            )
        if evidence_sink is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Trusted Zero Trust evidence consumer is not configured.",
            )
        evidence = TrustedFaceEvidence(
            evidence_id=uuid.uuid4().hex,
            user_id=result.user_id,
            authentication_attempt_id=principal.authentication_attempt_id,
            issued_at=datetime.now(timezone.utc),
            distance=result.distance,
            distance_threshold=result.threshold,
            model_name=result.model_name,
            model_version=result.model_version,
        )
        try:
            evidence_sink.submit(evidence)
        except Exception as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Trusted face evidence could not be delivered.",
            ) from error
    return RecognitionResponse(**result.__dict__)


@router.get("/enrollment/{user_id}", response_model=EnrollmentResponse)
def get_face_enrollment(
    user_id: str,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_enrollment_admin)],
) -> EnrollmentResponse:
    del principal
    try:
        metadata = get_face_identity_service().enrollment_status(user_id)
        return EnrollmentResponse(
            user_id=metadata.user_id,
            enrollment_status=metadata.status,
            enrolled_at=metadata.enrolled_at,
            model_name=metadata.model_name,
            model_version=metadata.model_version,
            detector_backend=metadata.detector_backend,
            embedding_dimension=metadata.embedding_dimension,
        )
    except Exception as error:
        raise _map_error(error) from error


@router.delete("/enrollment/{user_id}", response_model=EnrollmentResponse)
def delete_face_enrollment(
    user_id: str,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_enrollment_admin)],
) -> EnrollmentResponse:
    del principal
    try:
        metadata = get_face_identity_service().delete_enrollment(user_id)
        return EnrollmentResponse(
            user_id=metadata.user_id,
            enrollment_status=metadata.status,
            enrolled_at=metadata.enrolled_at,
            model_name=metadata.model_name,
            model_version=metadata.model_version,
            detector_backend=metadata.detector_backend,
            embedding_dimension=metadata.embedding_dimension,
        )
    except Exception as error:
        raise _map_error(error) from error
