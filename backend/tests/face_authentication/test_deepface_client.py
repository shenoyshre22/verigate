from io import BytesIO

from io import BytesIO

import pytest
from PIL import Image

from backend.modules.face_authentication.deepface_client import DeepFaceRecognitionClient
from backend.modules.face_authentication.recognition_exceptions import (
    MultipleFacesError,
    RecognitionProviderError,
)


class FakeDeepFace:
    def __init__(self, result=None, face_counts=None):
        self.result = {"verified": True, "confidence": 91.0} if result is None else result
        self.face_counts = iter(face_counts or (1, 1))
        self.calls = []

    def extract_faces(self, **kwargs):
        self.calls.append(("extract_faces", kwargs))
        return [{} for _ in range(next(self.face_counts))]

    def verify(self, **kwargs):
        self.calls.append(("verify", kwargs))
        return self.result


def test_deepface_client_checks_one_face_and_uses_upstream_verification():
    deepface = FakeDeepFace()
    result = DeepFaceRecognitionClient(deepface_api=deepface).compare(b"reference", b"probe")

    assert result.similarity == 91.0
    assert result.provider_match is True
    assert result.aws_latency_ms == 0
    assert result.provider_latency_ms >= 0
    assert [call[0] for call in deepface.calls] == ["extract_faces", "extract_faces", "verify"]
    verify_args = deepface.calls[-1][1]
    assert verify_args["model_name"] == "ArcFace"
    assert verify_args["anti_spoofing"] is False
    assert isinstance(verify_args["img1_path"], BytesIO)


def test_deepface_client_rejects_multiple_faces():
    deepface = FakeDeepFace(face_counts=(2,))

    with pytest.raises(MultipleFacesError):
        DeepFaceRecognitionClient(deepface_api=deepface).compare(b"reference", b"probe")


@pytest.mark.parametrize("result", [None, {}, {"verified": "yes", "confidence": 99},
                                    {"verified": True, "confidence": float("nan")}])
def test_deepface_client_rejects_malformed_provider_result(result):
    deepface = FakeDeepFace(result=result)
    if result is None:
        deepface.result = None

    with pytest.raises(RecognitionProviderError):
        DeepFaceRecognitionClient(deepface_api=deepface).compare(b"reference", b"probe")


def test_recognition_service_never_overrides_deepface_rejection():
    from backend.modules.face_authentication.recognition_service import FaceRecognitionService
    from backend.modules.face_authentication.rekognition_client import RekognitionMeasurement

    output = BytesIO()
    Image.new("RGB", (128, 128), color="gray").save(output, format="JPEG")
    valid_image = output.getvalue()

    class ReferenceProvider:
        def get_reference_image(self, user_id):
            return valid_image

    class RejectingProvider:
        def compare(self, reference_image, submitted_image):
            return RekognitionMeasurement(99.0, 1.0, provider_match=False)

    service = FaceRecognitionService(ReferenceProvider(), RejectingProvider())
    assert service.recognize("user-1", valid_image).matched is False
