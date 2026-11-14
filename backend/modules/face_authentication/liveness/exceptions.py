"""Safe domain errors for face liveness."""


class LivenessError(Exception):
    """Base class for expected liveness failures."""


class LivenessConfigurationError(LivenessError):
    """Required provider or ownership configuration is missing or invalid."""


class LivenessOwnershipError(LivenessError):
    """The caller does not own the attempt/session, or it is not known."""


class LivenessSessionExpiredError(LivenessError):
    """The session has expired before a result was available."""


class LivenessPendingError(LivenessError):
    """The session is still being processed or captured."""


class LivenessAccessError(LivenessError):
    """AWS denied the liveness operation."""


class LivenessThrottledError(LivenessError):
    """AWS throttled the liveness operation."""


class LivenessTimeoutError(LivenessError):
    """The AWS request timed out."""


class LivenessProviderError(LivenessError):
    """AWS failed or returned an invalid response."""
