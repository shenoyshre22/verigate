from io import BytesIO

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError
from fastapi.testclient import TestClient
from PIL import Image

from backend.modules.face_authentication.image_validator import MAX_IMAGE_BYTES, validate_image
from backend.modules.face_authentication.recognition_exceptions import (
    FaceNotFoundError,
    InvalidImageError,
    MultipleFacesError,
    RecognitionAccessError,
    RecognitionProviderError,
    RecognitionTimeoutError,
    ReferenceNotFoundError,
)
from backend.modules.face_authentication.recognition_service import FaceRecognitionService
from backend.modules.face_authentication.rekognition_client import RekognitionFaceRecognitionClient
from backend.app.main import app
from backend.modules.face_authentication import router as face_router


def make_image(image_format: str = "JPEG", size: tuple[int, int] = (128, 128)) -> bytes:
    output = BytesIO()
    Image.new("RGB", size, color="gray").save(output, format=image_format)
    return output.getvalue()


class MemoryReferenceProvider:
    def __init__(self, image: bytes | None) -> None:
        self.image = image

    def get_reference_image(self, user_id: str) -> bytes:
        if self.image is None:
            raise ReferenceNotFoundError("No enrolled reference image was found.")
        return self.image


class FixedRecognitionClient:
    def __init__(self, similarity: float | None) -> None:
        self.similarity = similarity

    def compare(self, reference_image: bytes, submitted_image: bytes):
        from backend.modules.face_authentication.rekognition_client import RekognitionMeasurement

        return RekognitionMeasurement(self.similarity, 12.5)


class FakeRekognitionApi:
    def __init__(self, detections: list[dict], comparison: dict | Exception | None = None) -> None:
        self.detections = iter(detections)
        self.comparison = comparison or {"FaceMatches": [{"Similarity": 91.25}]}
        self.compare_calls = 0

    def detect_faces(self, **kwargs):
        return next(self.detections)

    def compare_faces(self, **kwargs):
        self.compare_calls += 1
        if isinstance(self.comparison, Exception):
            raise self.comparison
        return self.comparison


@pytest.fixture
def jpeg_image() -> bytes:
    return make_image()


def test_validates_supported_image(jpeg_image: bytes) -> None:
    validated = validate_image(jpeg_image)

    assert validated.image_format == "JPEG"
    assert (validated.width, validated.height) == (128, 128)


def test_rejects_corrupted_image() -> None:
    with pytest.raises(InvalidImageError, match="corrupted"):
        validate_image(b"not an image")


def test_rejects_unsupported_format() -> None:
    with pytest.raises(InvalidImageError, match="Only JPEG and PNG"):
        validate_image(make_image("BMP"))


def test_rejects_oversized_image() -> None:
    with pytest.raises(InvalidImageError, match="smaller than 5 MB"):
        validate_image(b"x" * (MAX_IMAGE_BYTES + 1))


def test_successful_face_match(jpeg_image: bytes) -> None:
    client = FixedRecognitionClient(91.25)
    service = FaceRecognitionService(MemoryReferenceProvider(jpeg_image), client, 85)

    result = service.recognize("user-1", jpeg_image)

    assert result.status == "MATCH"
    assert result.matched is True
    assert result.similarity == 91.25
    assert result.threshold == 85
    assert result.preprocessing_latency_ms >= 0
    assert result.aws_latency_ms == 12.5
    assert result.total_latency_ms >= result.preprocessing_latency_ms


def test_face_mismatch(jpeg_image: bytes) -> None:
    result = FaceRecognitionService(
        MemoryReferenceProvider(jpeg_image), FixedRecognitionClient(42.0), 80
    ).recognize("user-1", jpeg_image)

    assert result.status == "NO_MATCH"
    assert result.matched is False
    assert result.similarity == 42.0


def test_missing_reference_image(jpeg_image: bytes) -> None:
    service = FaceRecognitionService(MemoryReferenceProvider(None), FixedRecognitionClient(99))

    with pytest.raises(ReferenceNotFoundError):
        service.recognize("missing-user", jpeg_image)


def test_rekognition_match_uses_actual_similarity(jpeg_image: bytes) -> None:
    api = FakeRekognitionApi(
        [{"FaceDetails": [{}]}, {"FaceDetails": [{}]}],
        {"FaceMatches": [{"Similarity": 93.4}]},
    )

    result = RekognitionFaceRecognitionClient(api).compare(jpeg_image, jpeg_image)

    assert result.similarity == 93.4
    assert result.aws_latency_ms >= 0
    assert api.compare_calls == 1


@pytest.mark.parametrize(
    ("detections", "expected_error"),
    [
        ([{"FaceDetails": []}, {"FaceDetails": [{}]}], FaceNotFoundError),
        ([{"FaceDetails": [{}, {}]}, {"FaceDetails": [{}]}], MultipleFacesError),
    ],
)
def test_rejects_no_face_and_multiple_faces(jpeg_image, detections, expected_error) -> None:
    api = FakeRekognitionApi(detections)

    with pytest.raises(expected_error):
        RekognitionFaceRecognitionClient(api).compare(jpeg_image, jpeg_image)
    assert api.compare_calls == 0


def test_aws_timeout(jpeg_image: bytes) -> None:
    api = FakeRekognitionApi(
        [{"FaceDetails": [{}]}, {"FaceDetails": [{}]}],
        ReadTimeoutError(endpoint_url="https://rekognition.invalid"),
    )

    with pytest.raises(RecognitionTimeoutError):
        RekognitionFaceRecognitionClient(api).compare(jpeg_image, jpeg_image)


def test_malformed_face_detection_response(jpeg_image: bytes) -> None:
    api = FakeRekognitionApi([{"Unexpected": []}])

    with pytest.raises(RecognitionProviderError, match="malformed face detection"):
        RekognitionFaceRecognitionClient(api).compare(jpeg_image, jpeg_image)


def test_aws_access_denied(jpeg_image: bytes) -> None:
    denied = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "CompareFaces",
    )
    api = FakeRekognitionApi([{"FaceDetails": [{}]}, {"FaceDetails": [{}]}], denied)

    with pytest.raises(RecognitionAccessError):
        RekognitionFaceRecognitionClient(api).compare(jpeg_image, jpeg_image)


def test_malformed_aws_response(jpeg_image: bytes) -> None:
    api = FakeRekognitionApi(
        [{"FaceDetails": [{}]}, {"FaceDetails": [{}]}],
        {"FaceMatches": [{"Similarity": "high"}]},
    )

    with pytest.raises(RecognitionProviderError, match="invalid similarity"):
        RekognitionFaceRecognitionClient(api).compare(jpeg_image, jpeg_image)


def test_recognition_http_endpoint_and_health(jpeg_image: bytes, monkeypatch) -> None:
    service = FaceRecognitionService(
        MemoryReferenceProvider(jpeg_image), FixedRecognitionClient(91.25), 80
    )
    monkeypatch.setattr(face_router, "get_recognition_service", lambda: service)

    with TestClient(app) as client:
        health = client.get("/health")
        response = client.post(
            "/api/v1/face-auth/recognize",
            data={"user_id": "user-1"},
            files={"image": ("capture.jpg", jpeg_image, "image/jpeg")},
        )

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert response.status_code == 200
    assert response.json()["status"] == "MATCH"
    assert response.json()["similarity"] == 91.25
