from backend.modules.face_authentication.liveness.rekognition_liveness_client import (
    RekognitionLivenessClient,
)


class FakeRekognition:
    def __init__(self):
        self.calls = []

    def get_face_liveness_session_results(self, **kwargs):
        self.calls.append(kwargs)
        return {"Status": "IN_PROGRESS"}


def test_result_lookup_uses_boto3_session_id_parameter():
    client = FakeRekognition()

    response = RekognitionLivenessClient(client=client).get_results("session-123")

    assert client.calls == [{"SessionId": "session-123"}]
    assert response["Status"] == "IN_PROGRESS"
