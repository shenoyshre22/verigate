"""Domain errors for face recognition."""


class RecognitionError(Exception):
    """Base class for expected recognition failures."""


class InvalidImageError(RecognitionError):
    """The submitted image is invalid or unsuitable for recognition."""


class FaceNotFoundError(RecognitionError):
    """No face was detected in an image."""


class MultipleFacesError(RecognitionError):
    """More than one face was detected in an image."""


class ReferenceNotFoundError(RecognitionError):
    """No enrolled reference image exists for the requested user."""


class RecognitionProviderError(RecognitionError):
    """An upstream recognition provider failed or returned invalid data."""


class RecognitionTimeoutError(RecognitionProviderError):
    """The recognition provider request timed out."""


class RecognitionAccessError(RecognitionProviderError):
    """The configured AWS identity lacks permission for recognition."""


class RecognitionThrottledError(RecognitionProviderError):
    """The recognition provider throttled the request."""
