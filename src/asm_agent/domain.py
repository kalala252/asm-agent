"""Strict domain and hostname normalization."""

from __future__ import annotations

import ipaddress
import re

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class DomainValidationError(ValueError):
    """Raised when a supplied domain is not safe for passive collection."""


def normalize_hostname(value: str, *, require_dot: bool = True) -> str:
    """Return a lowercase ASCII hostname or raise a validation error."""
    if not isinstance(value, str):
        raise DomainValidationError("domain must be text")
    candidate = value.strip().rstrip(".").lower()
    if not candidate:
        raise DomainValidationError("domain must not be empty")
    if any(character in candidate for character in (":", "/", "\\", "*", "@")):
        raise DomainValidationError("URLs, ports, paths, wildcards, and userinfo are not allowed")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise DomainValidationError("IP addresses are not allowed")
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as error:
        raise DomainValidationError("domain contains an invalid IDN") from error
    if len(ascii_name) > 253:
        raise DomainValidationError("domain is too long")
    labels = ascii_name.split(".")
    if require_dot and len(labels) < 2:
        raise DomainValidationError("an apex domain must contain a public suffix")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise DomainValidationError("domain contains an invalid label")
    return ascii_name


def normalize_domain(value: str) -> str:
    """Validate and normalize an apex-domain input."""
    domain = normalize_hostname(value)
    if domain == "localhost" or domain.endswith(".local"):
        raise DomainValidationError("local names are not allowed")
    return domain


def is_in_scope(hostname: str, apex_domain: str) -> bool:
    """Return whether a valid hostname is the apex or one of its descendants."""
    try:
        normalized_host = normalize_hostname(hostname)
        normalized_apex = normalize_domain(apex_domain)
    except DomainValidationError:
        return False
    return normalized_host == normalized_apex or normalized_host.endswith(f".{normalized_apex}")
