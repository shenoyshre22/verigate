"""Interfaces for retrieving enrolled reference images."""

from pathlib import Path
from typing import Protocol

from .recognition_exceptions import ReferenceNotFoundError


class ReferenceImageProvider(Protocol):
    """Provides an enrolled reference image for a stable user identifier."""

    def get_reference_image(self, user_id: str) -> bytes:
        """Return the user's enrolled JPEG or PNG bytes."""


class DirectoryReferenceImageProvider:
    """Local-development provider for controlled references stored as <user_id>.jpg/png."""

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory).resolve()

    def get_reference_image(self, user_id: str) -> bytes:
        if not user_id or Path(user_id).name != user_id or user_id in {".", ".."}:
            raise ReferenceNotFoundError("No enrolled reference image was found.")
        for suffix in (".jpg", ".jpeg", ".png"):
            candidate = (self._directory / f"{user_id}{suffix}").resolve()
            if candidate.parent == self._directory and candidate.is_file():
                try:
                    return candidate.read_bytes()
                except OSError as error:
                    raise ReferenceNotFoundError("No enrolled reference image was found.") from error
        raise ReferenceNotFoundError("No enrolled reference image was found.")
