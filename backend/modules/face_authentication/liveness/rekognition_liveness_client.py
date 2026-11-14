"""Thin boto3 adapter for Amazon Rekognition Face Liveness."""

from typing import Any, Protocol


class RekognitionLivenessAPI(Protocol):
    def create_face_liveness_session(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_face_liveness_session_results(self, **kwargs: Any) -> dict[str, Any]: ...


class RekognitionLivenessClient:
    def __init__(self, client: RekognitionLivenessAPI | None = None, region_name: str | None = None) -> None:
        if client is None:
            import boto3

            client = boto3.client("rekognition", region_name=region_name)
        self._client = client

    def create_session(self, *, output_config: dict[str, Any] | None = None, audit_images_limit: int = 0) -> dict[str, Any]:
        params: dict[str, Any] = {"Settings": {"AuditImagesLimit": audit_images_limit}}
        if output_config:
            params["OutputConfig"] = output_config
        return self._client.create_face_liveness_session(**params)

    def get_results(self, session_id: str) -> dict[str, Any]:
        return self._client.get_face_liveness_session_results( livenessSessionId=session_id)
