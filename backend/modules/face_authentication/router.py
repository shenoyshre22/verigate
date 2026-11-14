"""HTTP endpoint for face identity recognition."""

import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict

from .recognition_exceptions import (
    FaceNotFoundError,
    InvalidImageError,
    MultipleFacesError,
    RecognitionAccessError,
    RecognitionProviderError,
    RecognitionThrottledError,
    RecognitionTimeoutError,
    ReferenceNotFoundError,
)
from .recognition_service import FaceRecognitionService
from .reference_provider import DirectoryReferenceImageProvider
from .rekognition_client import RekognitionFaceRecognitionClient

router = APIRouter(prefix="/api/v1/face-auth", tags=["face-authentication"])
MAX_UPLOAD_BYTES = 5_000_000 - 1


class RecognitionResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    status: str
    matched: bool
    similarity: float | None
    threshold: float
    preprocessing_latency_ms: float
    aws_latency_ms: float
    provider_latency_ms: float
    total_latency_ms: float


def get_recognition_service() -> FaceRecognitionService:
    """Build request-scoped adapters from environment configuration and boto3 defaults."""

    references_dir = os.getenv("FACE_REFERENCE_DIR")
    if not references_dir:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Face reference provider is not configured.",
        )
    try:
        engine = os.getenv("FACE_RECOGNITION_ENGINE", "rekognition").strip().lower()
        threshold = float(os.getenv("FACE_SIMILARITY_THRESHOLD", "80"))
    except ValueError as error:
        raise HTTPException(status_code=500, detail="Face similarity threshold configuration is invalid.") from error
    if engine == "rekognition":
        recognition_client = RekognitionFaceRecognitionClient()
    elif engine == "deepface":
        from .deepface_client import DeepFaceRecognitionClient

        recognition_client = DeepFaceRecognitionClient(
            model_name=os.getenv("DEEPFACE_MODEL_NAME", "ArcFace"),
            detector_backend=os.getenv("DEEPFACE_DETECTOR_BACKEND", "opencv"),
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Face recognition engine configuration is invalid.",
        )
    try:
        return FaceRecognitionService(
            reference_provider=DirectoryReferenceImageProvider(Path(references_dir)),
            recognition_client=recognition_client,
            similarity_threshold=threshold,
        )
    except ValueError as error:
        raise HTTPException(status_code=500, detail="Face similarity threshold configuration is invalid.") from error


@router.post("/recognize", response_model=RecognitionResponse)
async def recognize_face(
    user_id: Annotated[str, Form(min_length=1, max_length=128)],
    image: Annotated[UploadFile, File()],
) -> RecognitionResponse:
    """Compare an uploaded face against that user's enrolled reference image."""

    try:
        data = await image.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await image.close()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Image must be smaller than 5 MB.")

    try:
        service = get_recognition_service()
        result = service.recognize(user_id=user_id, submitted_image=data)
    except InvalidImageError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except FaceNotFoundError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except MultipleFacesError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except ReferenceNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except RecognitionTimeoutError as error:
        raise HTTPException(status_code=504, detail=str(error)) from error
    except RecognitionAccessError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    except RecognitionThrottledError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except RecognitionProviderError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return RecognitionResponse(**result.__dict__)
