"""Domain/IP validation for user-supplied SAN identities.

Deliberately avoids any shell/subprocess usage - see plan.md "Command
Injection / Path Traversal": inputs are validated with a strict regex (for
DNS names) and Python's ``ipaddress`` module (for IPs) before ever being
passed into a `cryptography` SAN object.
"""
from __future__ import annotations

import ipaddress
import re

# RFC 1035 style hostname label: starts/ends alphanumeric, may contain
# hyphens in the middle; total hostname length <= 253.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^({_LABEL}\.)*{_LABEL}$")


class InvalidIdentityError(ValueError):
    pass


def validate_domain(value: str) -> str:
    if not value or len(value) > 253:
        raise InvalidIdentityError(f"Invalid domain name: {value!r}")
    if not _HOSTNAME_RE.match(value):
        raise InvalidIdentityError(f"Invalid domain name: {value!r}")
    return value


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise InvalidIdentityError(f"Invalid IP address: {value!r}") from exc
    return value


def classify_and_validate(value: str) -> tuple[str, str]:
    """Returns (identity_type, normalized_value) - "DNS" or "IP"."""
    try:
        ipaddress.ip_address(value)
        return "IP", value
    except ValueError:
        return "DNS", validate_domain(value)
