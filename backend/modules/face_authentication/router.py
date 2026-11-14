"""HTTP routes for the face authentication module."""

from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/face-authentication", tags=["face-authentication"])


@router.post("", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def authenticate_face() -> None:
    """Reserve the face authentication endpoint until processing is implemented."""

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Face authentication is not implemented yet.",
    )
