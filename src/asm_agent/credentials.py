"""Credential access backed by the operating system keyring."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Protocol, cast

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

SERVICE_NAME = "asm-agent"
SUPPORTED_SECRETS = frozenset({"SHODAN_API_KEY", "OPENAI_API_KEY"})


class CredentialError(RuntimeError):
    """A credential-store error that never contains a secret value."""


class KeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


def resolve_secret(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
    backend: KeyringBackend | None = None,
) -> str | None:
    """Resolve a secret from the environment, then the OS keyring."""
    _validate_name(name)
    environment = os.environ if environ is None else environ
    environment_value = environment.get(name, "").strip()
    if environment_value:
        return environment_value
    try:
        value = _backend(backend).get_password(SERVICE_NAME, name)
    except KeyringError as error:
        raise CredentialError("the operating system credential store is unavailable") from error
    return value.strip() if value and value.strip() else None


def store_secret(
    name: str,
    value: str,
    *,
    backend: KeyringBackend | None = None,
) -> None:
    """Store a supported secret in the OS keyring."""
    _validate_name(name)
    normalized = value.strip()
    if not normalized:
        raise CredentialError("credential must not be empty")
    try:
        _backend(backend).set_password(SERVICE_NAME, name, normalized)
    except KeyringError as error:
        raise CredentialError(
            "failed to store credential in the operating system keyring"
        ) from error


def delete_secret(name: str, *, backend: KeyringBackend | None = None) -> None:
    """Remove a supported secret from the OS keyring."""
    _validate_name(name)
    try:
        _backend(backend).delete_password(SERVICE_NAME, name)
    except PasswordDeleteError as error:
        raise CredentialError("credential is not stored or could not be deleted") from error
    except KeyringError as error:
        raise CredentialError("the operating system credential store is unavailable") from error


def _validate_name(name: str) -> None:
    if name not in SUPPORTED_SECRETS:
        raise CredentialError("unsupported credential name")


def _backend(backend: KeyringBackend | None) -> KeyringBackend:
    return backend or cast(KeyringBackend, keyring)
