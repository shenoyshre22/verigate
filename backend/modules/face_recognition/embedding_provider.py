"""VERIGATE adapter for DeepFace embedding generation."""

from __future__ import annotations

import math
import os
import tempfile
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from .errors import (
    FaceIdentityConfigurationError,
    FaceIdentityMultipleFaces,
    FaceIdentityNoFace,
    FaceIdentityProviderError,
)


@dataclass(frozen=True)
class FaceEmbedding:
    vector: tuple[float, ...]
    model_name: str
    model_version: str
    detector_backend: str


class DeepFaceEmbeddingProvider:
    """Generate a single DeepFace representation and model-specific threshold."""

    def __init__(
        self,
        *,
        model_name: str = "ArcFace",
        detector_backend: str = "opencv",
        deepface_api: Any | None = None,
        model_version: str | None = None,
        default_threshold: float | None = None,
    ) -> None:
        if not model_name.strip() or not detector_backend.strip():
            raise FaceIdentityConfigurationError("DeepFace model and detector names are required.")
        self.model_name = model_name
        self.detector_backend = detector_backend
        self._api_override = deepface_api
        self._model_version_override = model_version
        self._threshold_override = default_threshold
        self._api_instance: Any | None = None
        self._no_face_exception: type[Exception] = type("NoFaceException", (Exception,), {})
        self.model_version = model_version or ""
        self.default_threshold = default_threshold

        if deepface_api is not None:
            self._api_instance = deepface_api
            self.model_version = model_version or f"test:{model_name}:{detector_backend}"
            self.default_threshold = default_threshold if default_threshold is not None else 0.68

    def _load(self) -> Any:
        if self._api_instance is not None:
            return self._api_instance

        if not os.environ.get("DEEPFACE_HOME"):
            cache_root = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
            os.environ["DEEPFACE_HOME"] = os.path.join(cache_root, "VERIGATE")

        try:
            import deepface
            from deepface import DeepFace
            from deepface.commons.backend_utils import get_backend_engine
            from deepface.modules.exceptions import FaceNotDetected
            from deepface.modules.verification import find_threshold

            self._no_face_exception = FaceNotDetected
            DeepFace.build_model(self.model_name, task="facial_recognition")
            backend_engine = get_backend_engine()
            self.model_version = self._model_version_override or (
                f"{deepface.__version__}:{self.model_name}:{backend_engine}:{self.detector_backend}"
            )
            self.default_threshold = self._threshold_override
            if self.default_threshold is None:
                self.default_threshold = float(find_threshold(self.model_name, "cosine"))
            if not math.isfinite(self.default_threshold) or not 0 <= self.default_threshold <= 2:
                raise FaceIdentityConfigurationError("DeepFace cosine threshold is invalid.")
            self._api_instance = DeepFace
            return self._api_instance
        except FaceIdentityConfigurationError:
            raise
        except Exception as error:
            raise FaceIdentityConfigurationError(
                "DeepFace runtime or selected model could not be initialized."
            ) from error

    def initialize(self) -> None:
        """Load the model and threshold eagerly so invalid configuration fails closed."""
        self._load()

    def embed(self, image_bytes: bytes) -> FaceEmbedding:
        api = self._load()
        image = BytesIO(image_bytes)
        try:
            representations = api.represent(
                img_path=image,
                model_name=self.model_name,
                detector_backend=self.detector_backend,
                enforce_detection=True,
                align=True,
                anti_spoofing=False,
            )
        except self._no_face_exception as error:
            raise FaceIdentityNoFace("No face was detected in the supplied image.") from error
        except Exception as error:
            raise FaceIdentityProviderError("DeepFace could not create a face representation.") from error
        finally:
            image.close()

        if not isinstance(representations, list) or not representations:
            raise FaceIdentityNoFace("No face was detected in the supplied image.")
        if len(representations) != 1:
            raise FaceIdentityMultipleFaces("Exactly one face must be present in the supplied image.")
        representation = representations[0]
        vector = representation.get("embedding") if isinstance(representation, dict) else None
        if not isinstance(vector, (list, tuple)) or not vector:
            raise FaceIdentityProviderError("DeepFace returned an invalid embedding.")
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in vector
        ):
            raise FaceIdentityProviderError("DeepFace returned an invalid embedding.")
        if not self.model_version or self.default_threshold is None:
            raise FaceIdentityConfigurationError("DeepFace model metadata was not initialized.")

        return FaceEmbedding(
            vector=tuple(float(value) for value in vector),
            model_name=self.model_name,
            model_version=self.model_version,
            detector_backend=self.detector_backend,
        )
