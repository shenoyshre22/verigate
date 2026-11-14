"""Optional DeepFace adapter for the existing 1:1 face comparison interface."""

from __future__ import annotations

import math
import time
from io import BytesIO
from typing import Any

from .recognition_exceptions import (
    FaceNotFoundError,
    MultipleFacesError,
    RecognitionProviderError,
)
from .rekognition_client import RekognitionMeasurement


class DeepFaceRecognitionClient:
    """Use the imported upstream DeepFace package for one-to-one comparison.

    DeepFace is imported lazily so the normal Rekognition deployment does not
    need DeepFace's optional computer-vision dependencies.
    """

    def __init__(
        self,
        *,
        model_name: str = "ArcFace",
        detector_backend: str = "opencv",
        deepface_api: Any | None = None,
    ) -> None:
        if not model_name.strip() or not detector_backend.strip():
            raise ValueError("DeepFace model and detector names are required.")
        self._model_name = model_name
        self._detector_backend = detector_backend
        self._deepface_api = deepface_api

    def _api(self) -> tuple[Any, type[Exception]]:
        if self._deepface_api is not None:
            return self._deepface_api, type("NoFaceException", (Exception,), {})
        try:
            from deepface import DeepFace
            from deepface.modules.exceptions import FaceNotDetected
        except (ImportError, ModuleNotFoundError) as error:
            raise RecognitionProviderError(
                "DeepFace is selected but its isolated dependencies are not installed."
            ) from error
        return DeepFace, FaceNotDetected

    def compare(self, reference_image: bytes, submitted_image: bytes) -> RekognitionMeasurement:
        started = time.perf_counter()
        deepface, no_face_exception = self._api()
        reference = BytesIO(reference_image)
        submitted = BytesIO(submitted_image)

        try:
            for image in (reference, submitted):
                faces = deepface.extract_faces(
                    img_path=image,
                    detector_backend=self._detector_backend,
                    enforce_detection=True,
                    align=True,
                    anti_spoofing=False,
                )
                if not isinstance(faces, list):
                    raise RecognitionProviderError("DeepFace returned an invalid face detection response.")
                if not faces:
                    raise FaceNotFoundError("No face was detected in the reference or submitted image.")
                if len(faces) != 1:
                    raise MultipleFacesError("Exactly one face must be present in each image.")
                image.seek(0)

            result = deepface.verify(
                img1_path=reference,
                img2_path=submitted,
                model_name=self._model_name,
                detector_backend=self._detector_backend,
                distance_metric="cosine",
                enforce_detection=True,
                align=True,
                anti_spoofing=False,
            )
        except (FaceNotFoundError, MultipleFacesError, RecognitionProviderError):
            raise
        except no_face_exception as error:
            raise FaceNotFoundError("No face was detected in the reference or submitted image.") from error
        except Exception as error:
            raise RecognitionProviderError("DeepFace could not complete face comparison.") from error
        finally:
            reference.close()
            submitted.close()

        if not isinstance(result, dict):
            raise RecognitionProviderError("DeepFace returned an invalid comparison response.")
        confidence = result.get("confidence")
        provider_match = result.get("verified")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 100
            or not isinstance(provider_match, bool)
        ):
            raise RecognitionProviderError("DeepFace returned invalid comparison values.")

        return RekognitionMeasurement(
            similarity=float(confidence),
            aws_latency_ms=0.0,
            provider_match=provider_match,
            provider_latency_ms=(time.perf_counter() - started) * 1000,
        )
