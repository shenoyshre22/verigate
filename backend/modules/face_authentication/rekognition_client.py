"""Amazon Rekognition adapter. Client creation follows the standard boto3 credential chain."""

import time
from dataclasses import dataclass
from typing import Any, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ConnectTimeoutError, ReadTimeoutError

from .recognition_exceptions import (
    FaceNotFoundError,
    MultipleFacesError,
    RecognitionAccessError,
    RecognitionProviderError,
    RecognitionThrottledError,
    RecognitionTimeoutError,
)


@dataclass(frozen=True)
class RekognitionMeasurement:
    similarity: float | None
    aws_latency_ms: float
    provider_match: bool | None = None
    provider_latency_ms: float | None = None


class FaceRecognitionClient(Protocol):
    def compare(self, reference_image: bytes, submitted_image: bytes) -> RekognitionMeasurement:
        """Compare exactly one face in each image and return the top measured similarity."""


class RekognitionFaceRecognitionClient:
    """Calls DetectFaces and CompareFaces using an injected or default boto3 client."""

    def __init__(self, client: Any | None = None) -> None:
        if client is not None:
            self._client = client
            return
        try:
            self._client = boto3.client(
                "rekognition",
                config=Config(
                    retries={"total_max_attempts": 2, "mode": "standard"},
                    connect_timeout=5,
                    read_timeout=15,
                ),
            )
        except BotoCoreError as error:
            raise RecognitionProviderError("Amazon Rekognition client configuration is unavailable.") from error

    def _face_count(self, image: bytes) -> tuple[int, float]:
        started = time.perf_counter()
        response = self._client.detect_faces(Image={"Bytes": image}, Attributes=["DEFAULT"])
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not isinstance(response, dict):
            raise RecognitionProviderError("Rekognition returned a malformed face detection response.")
        details = response.get("FaceDetails")
        if not isinstance(details, list) or any(not isinstance(face, dict) for face in details):
            raise RecognitionProviderError("Rekognition returned a malformed face detection response.")
        return len(details), elapsed_ms

    def compare(self, reference_image: bytes, submitted_image: bytes) -> RekognitionMeasurement:
        total_latency_ms = 0.0
        try:
            reference_count, elapsed = self._face_count(reference_image)
            total_latency_ms += elapsed
            submitted_count, elapsed = self._face_count(submitted_image)
            total_latency_ms += elapsed

            if reference_count == 0 or submitted_count == 0:
                raise FaceNotFoundError("No face was detected in the reference or submitted image.")
            if reference_count != 1 or submitted_count != 1:
                raise MultipleFacesError("Exactly one face must be present in each image.")

            started = time.perf_counter()
            response = self._client.compare_faces(
                SourceImage={"Bytes": reference_image},
                TargetImage={"Bytes": submitted_image},
                # Ask Rekognition for the measured score; apply the configured
                # decision threshold locally so a below-threshold score remains visible.
                SimilarityThreshold=0.0,
            )
            total_latency_ms += (time.perf_counter() - started) * 1000

            if not isinstance(response, dict):
                raise RecognitionProviderError("Rekognition returned a malformed comparison response.")
            matches = response.get("FaceMatches")
            if not isinstance(matches, list) or any(not isinstance(match, dict) for match in matches):
                raise RecognitionProviderError("Rekognition returned a malformed comparison response.")
            if not matches:
                return RekognitionMeasurement(similarity=None, aws_latency_ms=total_latency_ms)

            similarity = matches[0].get("Similarity")
            if isinstance(similarity, bool) or not isinstance(similarity, (int, float)) or not 0 <= similarity <= 100:
                raise RecognitionProviderError("Rekognition returned an invalid similarity score.")
            return RekognitionMeasurement(similarity=float(similarity), aws_latency_ms=total_latency_ms)
        except (FaceNotFoundError, MultipleFacesError, RecognitionProviderError):
            raise
        except (ConnectTimeoutError, ReadTimeoutError, TimeoutError) as error:
            raise RecognitionTimeoutError("Amazon Rekognition request timed out.") from error
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                raise RecognitionAccessError("Amazon Rekognition access was denied.") from error
            if code in {"ThrottlingException", "ProvisionedThroughputExceededException", "LimitExceededException"}:
                raise RecognitionThrottledError("Amazon Rekognition is throttling requests.") from error
            if code in {"InvalidS3ObjectException", "InvalidParameterException", "ImageTooLargeException"}:
                raise RecognitionProviderError("Amazon Rekognition rejected the supplied image.") from error
            raise RecognitionProviderError("Amazon Rekognition request failed.") from error
        except BotoCoreError as error:
            raise RecognitionProviderError("Amazon Rekognition could not complete the request.") from error
