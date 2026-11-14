"""Persistent face enrollment and thresholded 1:N identification."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal

from backend.modules.face_authentication.image_validator import validate_image
from .embedding_provider import DeepFaceEmbeddingProvider
from .errors import FaceIdentityConfigurationError
from .storage import EnrollmentMetadata, SQLiteFaceEnrollmentStore

USER_ID_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


@dataclass(frozen=True)
class FaceIdentificationResult:
    matched: bool
    user_id: str | None
    distance: float | None
    threshold: float
    recognition_status: Literal["MATCH", "UNKNOWN", "AMBIGUOUS"]
    model_name: str
    model_version: str


class FaceIdentityService:
    def __init__(
        self,
        provider: DeepFaceEmbeddingProvider,
        store: SQLiteFaceEnrollmentStore,
        *,
        distance_threshold: float | None = None,
    ) -> None:
        if provider is None or store is None:
            raise FaceIdentityConfigurationError("Face embedding provider and persistent store are required.")
        resolved_threshold = provider.default_threshold if distance_threshold is None else distance_threshold
        if (
            resolved_threshold is None
            or isinstance(resolved_threshold, bool)
            or not isinstance(resolved_threshold, (int, float))
            or not math.isfinite(resolved_threshold)
            or not 0 <= resolved_threshold <= 2
        ):
            raise FaceIdentityConfigurationError("Cosine distance threshold must be between 0 and 2.")
        self._provider = provider
        self._store = store
        self._threshold = float(resolved_threshold)

    def enroll(self, user_id: str, image_bytes: bytes, *, replace: bool = False) -> EnrollmentMetadata:
        self._validate_user_id(user_id)
        validated = validate_image(image_bytes)
        embedding = self._provider.embed(validated.data)
        return self._store.enroll(user_id, embedding, replace=replace)

    def identify(self, image_bytes: bytes) -> FaceIdentificationResult:
        validated = validate_image(image_bytes)
        query = self._provider.embed(validated.data)
        enrolled = self._store.active_embeddings(query.model_version)
        if not enrolled:
            return FaceIdentificationResult(
                False, None, None, self._threshold, "UNKNOWN", query.model_name, query.model_version
            )

        candidates: list[tuple[float, EnrollmentMetadata]] = []
        query_norm = math.sqrt(math.fsum(value * value for value in query.vector))
        if not math.isfinite(query_norm) or query_norm == 0:
            raise FaceIdentityConfigurationError("DeepFace produced a zero or invalid representation.")
        for metadata, vector in enrolled:
            if len(vector) != len(query.vector):
                # Different vector shapes are incompatible even if the version label was misconfigured.
                continue
            gallery_norm = math.sqrt(math.fsum(value * value for value in vector))
            if not math.isfinite(gallery_norm) or gallery_norm == 0:
                continue
            cosine = math.fsum(a * b for a, b in zip(query.vector, vector)) / (query_norm * gallery_norm)
            distance = min(2.0, max(0.0, 1.0 - cosine))
            if math.isfinite(distance):
                candidates.append((distance, metadata))

        candidates.sort(key=lambda item: item[0])
        qualified = [candidate for candidate in candidates if candidate[0] <= self._threshold]
        if not qualified:
            nearest_distance = candidates[0][0] if candidates else None
            return FaceIdentificationResult(
                False, None, nearest_distance, self._threshold, "UNKNOWN", query.model_name, query.model_version
            )
        if len(qualified) != 1:
            return FaceIdentificationResult(
                False, None, qualified[0][0], self._threshold, "AMBIGUOUS", query.model_name, query.model_version
            )

        distance, metadata = qualified[0]
        return FaceIdentificationResult(
            True, metadata.user_id, distance, self._threshold, "MATCH", query.model_name, query.model_version
        )

    def enrollment_status(self, user_id: str) -> EnrollmentMetadata:
        self._validate_user_id(user_id)
        return self._store.get(user_id)

    def delete_enrollment(self, user_id: str) -> EnrollmentMetadata:
        self._validate_user_id(user_id)
        return self._store.delete(user_id)

    @staticmethod
    def _validate_user_id(user_id: str) -> None:
        if not isinstance(user_id, str) or USER_ID_PATTERN.fullmatch(user_id) is None:
            raise ValueError("User ID must be 1-64 letters, digits, underscores, or hyphens.")
