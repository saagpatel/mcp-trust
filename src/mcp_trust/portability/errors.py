"""Portability-specific input and host errors."""


class PortabilityError(ValueError):
    """Base error for deterministic, user-fixable portability failures."""


class PortabilityInputError(PortabilityError):
    """Raised when an explicit input document is malformed or unsafe."""


class UnsupportedHostError(PortabilityError):
    """Raised when a requested adapter is not supported."""
