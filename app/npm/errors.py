"""Error hierarchy for NPM API interactions - see plan.md section on error
handling ("NPM nicht erreichbar", "NPM Login fehlgeschlagen", "JWT
abgelaufen", ...).
"""
from __future__ import annotations


class NpmError(Exception):
    """Base class for all NPM-client related errors."""


class NpmAuthError(NpmError):
    """Login failed, or the token was rejected/expired and re-login also failed."""


class NpmNotFoundError(NpmError):
    """The requested certificate (or other resource) does not exist in NPM."""


class NpmValidationError(NpmError):
    """NPM rejected the request payload (e.g. invalid certificate/key, or the
    certificate is not a custom ('other') provider certificate).
    """


class NpmConnectionError(NpmError):
    """Network-level failure (DNS, connection refused, timeout, ...)."""
