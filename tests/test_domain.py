import pytest

from asm_agent.domain import DomainValidationError, is_in_scope, normalize_domain


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://example.com",
        "1.2.3.4",
        "example.com:443",
        "example.com/path",
        "*.example.com",
        "localhost",
        "host.local",
        "-bad.example",
    ],
)
def test_rejects_unsafe_domain_inputs(value: str) -> None:
    with pytest.raises(DomainValidationError):
        normalize_domain(value)


def test_normalizes_idn_and_scope() -> None:
    assert normalize_domain("BÜCHER.Example.") == "xn--bcher-kva.example"
    assert is_in_scope("WWW.XN--BCHER-KVA.EXAMPLE.", "xn--bcher-kva.example")
    assert not is_in_scope("notexample.com", "example.com")


def test_rejects_invalid_idn() -> None:
    with pytest.raises(DomainValidationError):
        normalize_domain("\ud800.example")
