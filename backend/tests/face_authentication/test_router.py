import pytest
from fastapi import HTTPException

from backend.modules.face_authentication.router import authenticate_face, router


def test_face_authentication_endpoint_is_registered() -> None:
    assert any(
        route.path == "/face-authentication" and "POST" in route.methods
        for route in router.routes
    )


def test_face_authentication_is_not_a_mock_success() -> None:
    with pytest.raises(HTTPException) as error:
        authenticate_face()

    assert error.value.status_code == 501
