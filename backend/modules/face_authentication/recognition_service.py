"""Orchestrates image validation, reference lookup, and face identity comparison."""

import time
from dataclasses import dataclass

from .image_validator import validate_image
from .recognition_exceptions import FaceNotFoundError, MultipleFacesError, RecognitionProviderError
from .reference_provider import ReferenceImageProvider
from .rekognition_client import FaceRecognitionClient


@dataclass(frozen=True)
class RecognitionResult:
    user_id: str
    status: str
    matched: bool
    similarity: float | None
    threshold: float
    preprocessing_latency_ms: float
    aws_latency_ms: float
    total_latency_ms: float


class FaceRecognitionService:
    def __init__(
        self,
        reference_provider: ReferenceImageProvider,
        recognition_client: FaceRecognitionClient,
        similarity_threshold: float = 80.0,
    ) -> None:
        if not 0 <= similarity_threshold <= 100:
            raise ValueError("similarity_threshold must be between 0 and 100")
        self._reference_provider = reference_provider
        self._recognition_client = recognition_client
        self._similarity_threshold = similarity_threshold

    def recognize(self, user_id: str, submitted_image: bytes) -> RecognitionResult:
        total_started = time.perf_counter()
        preprocessing_started = time.perf_counter()
        validated_submitted = validate_image(submitted_image)
        reference_bytes = self._reference_provider.get_reference_image(user_id)
        validated_reference = validate_image(reference_bytes)
        preprocessing_latency_ms = (time.perf_counter() - preprocessing_started) * 1000

        measurement = self._recognition_client.compare(
            reference_image=validated_reference.data,
            submitted_image=validated_submitted.data,
        )
        matched = measurement.similarity is not None and measurement.similarity >= self._similarity_threshold
        return RecognitionResult(
            user_id=user_id,
            status="MATCH" if matched else "NO_MATCH",
            matched=matched,
            similarity=measurement.similarity,
            threshold=self._similarity_threshold,
            preprocessing_latency_ms=preprocessing_latency_ms,
            aws_latency_ms=measurement.aws_latency_ms,
            total_latency_ms=(time.perf_counter() - total_started) * 1000,
        )
