"""Validation for image evidence before calling a recognition provider."""

from dataclasses import dataclass
from io import BytesIO

from PIL import Image, UnidentifiedImageError

from .recognition_exceptions import InvalidImageError

# Rekognition requires image payloads to be smaller than 5 MB.
MAX_IMAGE_BYTES = 5_000_000 - 1
MIN_IMAGE_DIMENSION = 64
MAX_IMAGE_DIMENSION = 10_000
MAX_IMAGE_PIXELS = 20_000_000
SUPPORTED_FORMATS = {"JPEG", "PNG"}


@dataclass(frozen=True)
class ValidatedImage:
    data: bytes
    image_format: str
    width: int
    height: int


def validate_image(data: bytes) -> ValidatedImage:
    """Validate image bytes and return inspected metadata without retaining them."""

    if not data:
        raise InvalidImageError("Image is empty.")
    if len(data) > MAX_IMAGE_BYTES:
        raise InvalidImageError("Image must be smaller than 5 MB.")

    try:
        with Image.open(BytesIO(data)) as image:
            image_format = image.format
            width, height = image.size
            image.verify()
        if image_format not in SUPPORTED_FORMATS:
            raise InvalidImageError("Only JPEG and PNG images are supported.")
        if (
            width < MIN_IMAGE_DIMENSION
            or height < MIN_IMAGE_DIMENSION
            or width > MAX_IMAGE_DIMENSION
            or height > MAX_IMAGE_DIMENSION
            or width * height > MAX_IMAGE_PIXELS
        ):
            raise InvalidImageError("Image dimensions are outside supported limits.")
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError) as error:
        if isinstance(error, InvalidImageError):
            raise
        raise InvalidImageError("Image content is corrupted or unreadable.") from error

    return ValidatedImage(data=data, image_format=image_format, width=width, height=height)
