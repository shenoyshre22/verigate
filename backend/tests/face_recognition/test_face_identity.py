from __future__ import annotations

import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from backend.app.main import app
from backend.modules.face_recognition.embedding_provider import FaceEmbedding
from backend.modules.face_recognition.errors import FaceEnrollmentExists, FaceIdentityStorageError
from backend.modules.face_authentication.recognition_exceptions import InvalidImageError
from backend.modules.face_recognition.router import (
    AuthenticatedPrincipal,
    get_authenticated_principal,
    get_evidence_sink,
    get_face_identity_service,
)
from backend.modules.face_recognition.service import FaceIdentityService
from backend.modules.face_recognition.storage import SQLiteFaceEnrollmentStore


class TestProtector:
    def protect(self, data: bytes, context: bytes) -> bytes:
        return b"test-ciphertext:" + bytes(byte ^ 0x5A for byte in data)

    def unprotect(self, data: bytes, context: bytes) -> bytes:
        if not data.startswith(b"test-ciphertext:"):
            raise ValueError("invalid ciphertext")
        return bytes(byte ^ 0x5A for byte in data[len(b"test-ciphertext:"):])


class FakeProvider:
    model_name = "TestModel"
    model_version = "test-model-v1"
    default_threshold = 0.15

    def __init__(self, vectors: dict[bytes, tuple[float, ...]]) -> None:
        self.vectors = vectors

    def embed(self, image_bytes: bytes) -> FaceEmbedding:
        return FaceEmbedding(self.vectors[image_bytes], self.model_name, self.model_version, "test")


def image_bytes(color: str = "red") -> bytes:
    image = Image.new("RGB", (80, 80), color)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG")
    return buffer.getvalue()


@pytest.fixture
def service(tmp_path):
    alice = image_bytes("red")
    bob = image_bytes("blue")
    query_alice = image_bytes("green")
    unknown = image_bytes("yellow")
    provider = FakeProvider({
        alice: (1.0, 0.0),
        bob: (0.0, 1.0),
        query_alice: (0.99, 0.01),
        unknown: (-1.0, 0.0),
    })
    store = SQLiteFaceEnrollmentStore(tmp_path / "faces.sqlite3", TestProtector())
    instance = FaceIdentityService(provider, store)
    return instance, store, alice, bob, query_alice, unknown


def test_enroll_persists_across_store_restart_and_identifies_unknown_safely(service, tmp_path):
    instance, _, alice, bob, query_alice, unknown = service
    instance.enroll("STU1024", alice)
    instance.enroll("STU2048", bob)

    # Reopen the database to cover persistence across service/store reconstruction.
    reopened = SQLiteFaceEnrollmentStore(tmp_path / "faces.sqlite3", TestProtector())
    restarted = FaceIdentityService(instance._provider, reopened)
    match = restarted.identify(query_alice)
    assert (match.matched, match.user_id, match.recognition_status) == (True, "STU1024", "MATCH")
    result = restarted.identify(unknown)
    assert result.matched is False
    assert result.user_id is None
    assert result.recognition_status == "UNKNOWN"


def test_duplicate_replace_delete_status_and_sensitive_embedding_storage(service):
    instance, store, alice, _, _, _ = service
    instance.enroll("STU1024", alice)
    with pytest.raises(FaceEnrollmentExists):
        instance.enroll("STU1024", alice)
    replaced = instance.enroll("STU1024", alice, replace=True)
    assert replaced.status == "ACTIVE"

    ciphertext = store._path.read_bytes()
    assert b"1.0,0.0" not in ciphertext
    assert instance.delete_enrollment("STU1024").status == "DELETED"
    assert instance.enrollment_status("STU1024").status == "DELETED"
    assert store.active_embeddings("test-model-v1") == []


def test_incompatible_model_is_not_compared(service):
    instance, store, alice, _, query_alice, _ = service
    instance.enroll("STU1024", alice)
    incompatible = FaceEmbedding((1.0, 0.0), "TestModel", "different-model-v2", "test")
    store.enroll("STU2048", incompatible)
    assert instance.identify(query_alice).user_id == "STU1024"


def test_invalid_image_and_low_confidence_are_unknown(service):
    instance, _, _, _, _, unknown = service
    with pytest.raises(InvalidImageError):
        instance.identify(b"not an image")
    assert instance.enroll("STU1024", image_bytes("red")).status == "ACTIVE"
    result = instance.identify(unknown)
    assert result.recognition_status == "UNKNOWN"
    assert not result.matched


def test_multiple_qualifying_identities_are_ambiguous(service):
    instance, _, alice, _, query_alice, _ = service
    instance.enroll("STU1024", alice)
    instance.enroll("STU2048", query_alice)
    result = instance.identify(query_alice)
    assert result.recognition_status == "AMBIGUOUS"
    assert result.matched is False
    assert result.user_id is None


def test_storage_failure_is_surfaced_without_success(service, monkeypatch):
    instance, store, alice, _, _, _ = service
    instance.enroll("STU1024", alice)

    def broken(*args, **kwargs):
        raise FaceIdentityStorageError("storage unavailable")

    monkeypatch.setattr(store, "active_embeddings", broken)
    with pytest.raises(FaceIdentityStorageError):
        instance.identify(alice)


def test_fastapi_routes_registered_and_health_unchanged():
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    paths = set(app.openapi()["paths"])
    assert "/api/v1/face/enroll" in paths
    assert "/api/v1/face/recognize" in paths
    assert "/api/v1/face/verify" in paths
    assert "/api/v1/face/enrollment/{user_id}" in paths


def test_face_routes_fail_closed_without_host_auth_provider():
    client = TestClient(app)
    response = client.post(
        "/api/v1/face/recognize",
        files={"image": ("face.jpg", image_bytes(), "image/jpeg")},
    )
    assert response.status_code == 503


def test_verify_binds_match_to_authenticated_principal(service, monkeypatch):
    instance, _, alice, _, _, _ = service
    instance.enroll("STU1024", alice)
    monkeypatch.setattr("backend.modules.face_recognition.router.get_face_identity_service", lambda: instance)

    app.dependency_overrides[get_authenticated_principal] = lambda: AuthenticatedPrincipal(
        subject_id="STU9999", authentication_attempt_id="attempt-1"
    )
    app.dependency_overrides[get_evidence_sink] = lambda: object()
    try:
        response = TestClient(app).post(
            "/api/v1/face/verify",
            files={"image": ("face.jpg", alice, "image/jpeg")},
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 403

