class FaceIdentityError(Exception):
    """Base exception for face enrollment and identification."""


class FaceIdentityConfigurationError(FaceIdentityError):
    """Required model, storage, or platform configuration is unavailable."""


class FaceEnrollmentNotFound(FaceIdentityError):
    """No enrollment metadata exists for the requested user."""


class FaceEnrollmentExists(FaceIdentityError):
    """An active face enrollment already exists."""


class FaceIdentityStorageError(FaceIdentityError):
    """Enrollment storage could not be read or updated safely."""


class FaceIdentityProviderError(FaceIdentityError):
    """DeepFace failed or returned unusable data."""


class FaceIdentityNoFace(FaceIdentityError):
    """No face was found in the supplied image."""


class FaceIdentityMultipleFaces(FaceIdentityError):
    """The workflow requires exactly one face per image."""
