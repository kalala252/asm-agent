from collections.abc import Mapping

import pytest
from keyring.errors import KeyringError, PasswordDeleteError

from asm_agent.credentials import CredentialError, delete_secret, resolve_secret, store_secret


class FakeKeyring:
    def __init__(self, values: Mapping[tuple[str, str], str] | None = None) -> None:
        self.values = dict(values or {})
        self.get_calls = 0

    def get_password(self, service: str, username: str) -> str | None:
        self.get_calls += 1
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.values:
            raise RuntimeError("missing")
        del self.values[(service, username)]


def test_environment_takes_precedence_without_keyring_access() -> None:
    backend = FakeKeyring({("asm-agent", "SHODAN_API_KEY"): "stored"})
    assert (
        resolve_secret(
            "SHODAN_API_KEY",
            environ={"SHODAN_API_KEY": "from-environment"},
            backend=backend,
        )
        == "from-environment"
    )
    assert backend.get_calls == 0


def test_secret_falls_back_to_keyring() -> None:
    backend = FakeKeyring({("asm-agent", "SHODAN_API_KEY"): "stored"})
    assert resolve_secret("SHODAN_API_KEY", environ={}, backend=backend) == "stored"


def test_store_and_delete_secret() -> None:
    backend = FakeKeyring()
    store_secret("SHODAN_API_KEY", "secret", backend=backend)
    assert resolve_secret("SHODAN_API_KEY", environ={}, backend=backend) == "secret"
    delete_secret("SHODAN_API_KEY", backend=backend)
    assert resolve_secret("SHODAN_API_KEY", environ={}, backend=backend) is None


def test_openai_key_is_supported() -> None:
    backend = FakeKeyring()
    store_secret("OPENAI_API_KEY", "openai-secret", backend=backend)
    assert resolve_secret("OPENAI_API_KEY", environ={}, backend=backend) == "openai-secret"
    delete_secret("OPENAI_API_KEY", backend=backend)


def test_empty_secret_is_rejected() -> None:
    with pytest.raises(CredentialError, match="must not be empty"):
        store_secret("SHODAN_API_KEY", "  ", backend=FakeKeyring())


class BrokenKeyring(FakeKeyring):
    def get_password(self, service: str, username: str) -> str | None:
        raise KeyringError("top-secret")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise KeyringError(password)

    def delete_password(self, service: str, username: str) -> None:
        raise PasswordDeleteError("top-secret")


def test_keyring_errors_are_sanitized() -> None:
    with pytest.raises(CredentialError) as get_error:
        resolve_secret("SHODAN_API_KEY", environ={}, backend=BrokenKeyring())
    with pytest.raises(CredentialError) as set_error:
        store_secret("SHODAN_API_KEY", "top-secret", backend=BrokenKeyring())
    with pytest.raises(CredentialError) as delete_error:
        delete_secret("SHODAN_API_KEY", backend=BrokenKeyring())
    assert all(
        "top-secret" not in str(error.value) for error in (get_error, set_error, delete_error)
    )


def test_unsupported_secret_name_is_rejected() -> None:
    with pytest.raises(CredentialError, match="unsupported"):
        resolve_secret("ARBITRARY_SECRET", environ={}, backend=FakeKeyring())
