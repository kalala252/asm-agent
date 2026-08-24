import re
from collections.abc import Sequence
from datetime import UTC, datetime

import dns.resolver
import httpx
import pytest
import respx

from asm_agent.collectors import CollectorFailure, CrtNameCollector, DnsCollector, ShodanCollector


def _mock_empty_shodan_host_information() -> respx.Route:
    return respx.get(
        url__regex=re.compile(
            r"https://api\.shodan\.io/shodan/host/(?!search(?:\?|$))[^?]+"
        )
    ).mock(return_value=httpx.Response(200, json={"data": []}))


@respx.mock
def test_crt_name_normalizes_filters_and_limits() -> None:
    route = respx.get("https://crt.name/v1/search").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"sub": "WWW.Example.com.", "first_seen": "2026-01-01T00:00:00Z"},
                {"sub": "www.example.com", "first_seen": "2026-01-01T00:00:00Z"},
                {"sub": "evil.test", "first_seen": "2026-01-02T00:00:00Z"},
                {"sub": "_bad.example.com", "first_seen": None},
                {"sub": "a.example.com", "first_seen": "2026-01-03T00:00:00Z"},
            ],
        )
    )
    result = CrtNameCollector(max_hosts=2).collect("example.com")
    assert [asset.value for asset in result.assets] == ["a.example.com", "www.example.com"]
    assert result.received_count == 5
    assert result.accepted_count == 2
    assert result.available_count == 2
    assert result.partial is False
    assert {item.source_observed_at for item in result.evidence} == {
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 3, tzinfo=UTC),
    }
    assert route.calls[0].request.url.params["dates"] == "1"
    assert route.calls[0].request.url.params["format"] == "json"
    assert route.call_count == 1


@respx.mock
def test_crt_name_marks_local_limit_as_partial() -> None:
    respx.get("https://crt.name/v1/search").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"sub": "a.example.com", "first_seen": None},
                {"sub": "b.example.com", "first_seen": "2026-01-01T00:00:00Z"},
                {"sub": "c.example.com", "first_seen": "2026-01-02T00:00:00Z"},
            ],
        )
    )
    result = CrtNameCollector(max_hosts=2).collect("example.com")
    assert result.received_count == 3
    assert result.accepted_count == 2
    assert result.available_count == 3
    assert result.partial is True
    assert result.limit == 2


@respx.mock
def test_http_timeout_has_bounded_retries_without_secret_leak() -> None:
    route = respx.get("https://api.shodan.io/shodan/host/search").mock(
        side_effect=httpx.ReadTimeout("secret-token")
    )
    with pytest.raises(CollectorFailure) as error:
        ShodanCollector(api_key="secret-token", retries=2).collect("example.com")
    assert route.call_count == 3
    assert "secret-token" not in str(error.value)


@respx.mock
def test_response_size_limit() -> None:
    respx.get("https://crt.name/v1/search").mock(
        return_value=httpx.Response(200, content=b"a" * 101)
    )
    with pytest.raises(CollectorFailure, match="size limit"):
        CrtNameCollector(max_response_bytes=100).collect("example.com")


class FakeAnswer:
    def __init__(self, values: Sequence[str]) -> None:
        self.values = values

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter([FakeRecord(value) for value in self.values])


class FakeRecord:
    def __init__(self, value: str) -> None:
        self.value = value

    def to_text(self) -> str:
        return self.value


class FakeResolver:
    def resolve(self, hostname: str, record_type: str, **_: object) -> FakeAnswer:
        records = {
            "A": ["192.0.2.10"],
            "AAAA": ["2001:db8::10"],
            "CNAME": ["Origin.Example.com."],
        }
        return FakeAnswer(records[record_type])


def test_dns_collects_a_aaaa_and_cname() -> None:
    result = DnsCollector(resolver=FakeResolver()).collect(["www.example.com"], "example.com")
    assert {(asset.asset_type.value, asset.value) for asset in result.assets} == {
        ("hostname", "origin.example.com"),
        ("ip", "192.0.2.10"),
        ("ip", "2001:db8::10"),
    }
    assert {e.relation for e in result.evidence} == {"aliases_to", "resolves_to"}


class NxResolver:
    def resolve(self, *_: object, **__: object) -> FakeAnswer:
        raise dns.resolver.NXDOMAIN


def test_dns_nxdomain_is_not_a_collector_failure() -> None:
    result = DnsCollector(resolver=NxResolver()).collect(["gone.example.com"], "example.com")
    assert not result.assets
    assert result.warnings == ["DNS NXDOMAIN: gone.example.com"]


def test_shodan_requires_credentials_before_network() -> None:
    with pytest.raises(CollectorFailure, match="SHODAN_API_KEY"):
        ShodanCollector(api_key=None).collect("example.com")


@respx.mock
def test_api_rate_limit() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(429, json={"error": "rate limited"})
    )
    with pytest.raises(CollectorFailure, match="rate limit"):
        ShodanCollector(api_key="x", retries=0).collect("example.com")


@respx.mock
def test_shodan_success_filters_scope_and_normalizes_service() -> None:
    _mock_empty_shodan_host_information()
    route = respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 3,
                "matches": [
                    {
                        "hostnames": ["WWW.Example.com.", "outside.test"],
                        "ip_str": "192.0.2.5",
                        "port": 443,
                        "transport": "TCP",
                        "timestamp": "2026-01-20T12:34:56.123456",
                        "product": "Example Server",
                        "version": "1.2.3",
                        "cpe": ["cpe:/a:example:server:1.2.3"],
                        "vulns": {
                            "CVE-2026-1234": {
                                "verified": False,
                                "cvss": 7.5,
                                "summary": "Example vulnerability",
                                "references": ["https://example.test/CVE-2026-1234"],
                            }
                        },
                    },
                    {
                        "hostnames": ["ignored.example.com"],
                        "ip_str": "192.0.2.6",
                        "port": 80,
                    },
                ]
            },
        )
    )
    result = ShodanCollector(api_key="token", max_hosts=1).collect("example.com")
    assert {(asset.asset_type.value, asset.value) for asset in result.assets} == {
        ("hostname", "www.example.com"),
        ("ip", "192.0.2.5"),
        ("service", "192.0.2.5:443/tcp"),
    }
    assert all(not item.inferred for item in result.evidence)
    assert all(item.collected_at.tzinfo is not None for item in result.evidence)
    assert {item.source_observed_at for item in result.evidence} == {
        datetime(2026, 1, 20, 12, 34, 56, 123456, tzinfo=UTC)
    }
    assert result.received_count == 2
    assert result.accepted_count == 1
    assert result.available_count == 3
    assert result.partial is True
    assert result.next_page_available is True
    assert len(result.vulnerabilities) == 1
    vulnerability = result.vulnerabilities[0]
    assert vulnerability.service == "192.0.2.5:443/tcp"
    assert vulnerability.vulnerability_id == "CVE-2026-1234"
    assert vulnerability.verified is False
    assert vulnerability.cvss == 7.5
    assert vulnerability.product == "Example Server"
    assert vulnerability.version == "1.2.3"
    assert vulnerability.cpes == ["cpe:/a:example:server:1.2.3"]
    vulnerability_evidence = next(
        item for item in result.evidence if item.relation == "reports_vulnerability"
    )
    assert vulnerability_evidence.subject == "192.0.2.5:443/tcp"
    assert vulnerability_evidence.object == "CVE-2026-1234"
    request_params = route.calls[0].request.url.params
    assert set(request_params) == {"key", "query", "minify", "fields"}
    assert request_params["query"] == "hostname:example.com"
    assert request_params["minify"] == "false"
    assert request_params["fields"] == (
        "ip_str,port,transport,hostnames,timestamp,product,version,cpe,vulns"
    )


@respx.mock
def test_shodan_accepts_vulnerability_id_list_with_unknown_verification() -> None:
    _mock_empty_shodan_host_information()
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 1,
                "matches": [
                    {
                        "hostnames": ["www.example.com"],
                        "ip_str": "192.0.2.5",
                        "port": 443,
                        "transport": "tcp",
                        "timestamp": "2026-01-20T12:34:56Z",
                        "vulns": ["cve-2026-9999", "not-a-cve", 123],
                    }
                ],
            },
        )
    )

    result = ShodanCollector(api_key="token").collect("example.com")

    assert [item.vulnerability_id for item in result.vulnerabilities] == [
        "CVE-2026-9999"
    ]
    assert result.vulnerabilities[0].verified is None


@respx.mock
def test_shodan_follows_pages_only_up_to_explicit_limit() -> None:
    _mock_empty_shodan_host_information()
    first_page = [
        {
            "hostnames": [f"host-{index}.example.com"],
            "ip_str": "192.0.2.1",
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-01-20T00:00:00Z",
        }
        for index in range(100)
    ]
    route = respx.get("https://api.shodan.io/shodan/host/search").mock(
        side_effect=[
            httpx.Response(200, json={"total": 101, "matches": first_page}),
            httpx.Response(
                200,
                json={
                    "total": 101,
                    "matches": [
                        {
                            "hostnames": ["last.example.com"],
                            "ip_str": "198.51.100.1",
                            "port": 80,
                            "transport": "tcp",
                            "timestamp": "2026-01-21T00:00:00Z",
                        }
                    ],
                },
            ),
        ]
    )
    result = ShodanCollector(api_key="token", max_hosts=200, max_pages=2).collect(
        "example.com"
    )
    assert route.call_count == 2
    assert "page" not in route.calls[0].request.url.params
    assert route.calls[1].request.url.params["page"] == "2"
    assert result.received_count == 101
    assert result.accepted_count == 101
    assert result.partial is False
    assert result.next_page_available is False


@respx.mock
def test_invalid_provider_timestamp_is_kept_as_unknown_with_warning() -> None:
    _mock_empty_shodan_host_information()
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 1,
                "matches": [
                    {
                        "hostnames": ["www.example.com"],
                        "ip_str": "192.0.2.5",
                        "port": 443,
                        "transport": "tcp",
                        "timestamp": "not-a-time",
                    }
                ],
            },
        )
    )
    result = ShodanCollector(api_key="token").collect("example.com")
    assert all(item.source_observed_at is None for item in result.evidence)
    assert result.warnings == [
        "Shodan returned an invalid timestamp for match:0",
        "Shodan Host Information queried 1 of 1 in-scope IP addresses; "
        "1 succeeded and 0 failed",
    ]


@respx.mock
def test_shodan_host_information_adds_services_and_vulnerability_metadata() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 1,
                "matches": [
                    {
                        "hostnames": ["dev.example.com"],
                        "ip_str": "192.0.2.5",
                        "port": 443,
                        "transport": "tcp",
                        "timestamp": "2026-08-22T08:52:27Z",
                    }
                ],
            },
        )
    )
    host_route = respx.get("https://api.shodan.io/shodan/host/192.0.2.5").mock(
        return_value=httpx.Response(
            200,
            json={
                "ip_str": "192.0.2.5",
                "last_update": "2026-08-24T05:48:24Z",
                "hostnames": ["dev.example.com", "outside.test"],
                "data": [
                    {
                        "port": 8009,
                        "transport": "tcp",
                        "timestamp": "2026-08-17T23:26:21Z",
                        "product": "Apache Tomcat",
                        "version": "9.0.30",
                        "cpe": ["cpe:/a:apache:tomcat"],
                        "vulns": {
                            "CVE-2020-1938": {
                                "verified": False,
                                "cvss": 9.8,
                                "cvss_v2": 7.5,
                                "cvss_version": 3.0,
                                "epss": 0.9927,
                                "ranking_epss": 0.99933,
                                "kev": True,
                                "summary": "Example summary",
                                "references": ["https://example.test/CVE-2020-1938"],
                            }
                        },
                    }
                ],
            },
        )
    )

    result = ShodanCollector(api_key="token").collect("example.com")

    assert host_route.call_count == 1
    assert {asset.value for asset in result.assets} >= {
        "192.0.2.5:443/tcp",
        "192.0.2.5:8009/tcp",
    }
    vulnerability = result.vulnerabilities[0]
    assert vulnerability.vulnerability_id == "CVE-2020-1938"
    assert vulnerability.product == "Apache Tomcat"
    assert vulnerability.version == "9.0.30"
    assert vulnerability.cvss == 9.8
    assert vulnerability.cvss_v2 == 7.5
    assert vulnerability.cvss_version == "3.0"
    assert vulnerability.epss == 0.9927
    assert vulnerability.ranking_epss == 0.99933
    assert vulnerability.kev is True
    assert vulnerability.source_observed_at == datetime(
        2026, 8, 17, 23, 26, 21, tzinfo=UTC
    )
    assert any(
        item.subject == "192.0.2.5:8009/tcp"
        and item.object == "CVE-2020-1938"
        and item.relation == "reports_vulnerability"
        for item in result.evidence
    )
    assert result.partial is False


@respx.mock
def test_shodan_host_information_limit_and_failure_are_reported_as_partial() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 3,
                "matches": [
                    {
                        "hostnames": [f"host-{index}.example.com"],
                        "ip_str": f"192.0.2.{index}",
                        "port": 443,
                    }
                    for index in range(1, 4)
                ],
            },
        )
    )
    respx.get("https://api.shodan.io/shodan/host/192.0.2.1").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.get("https://api.shodan.io/shodan/host/192.0.2.2").mock(
        return_value=httpx.Response(503, json={"error": "temporary"})
    )

    result = ShodanCollector(
        api_key="token", max_host_lookups=2, retries=0
    ).collect("example.com")

    assert result.partial is True
    assert any("queried 2 of 3" in warning for warning in result.warnings)
    assert any("lookup limit reached" in warning for warning in result.warnings)
    assert any("failed for 192.0.2.2" in warning for warning in result.warnings)


@respx.mock
def test_shodan_rejects_malformed_shape() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(CollectorFailure, match="unexpected response shape"):
        ShodanCollector(api_key="x", retries=0).collect("example.com")


@respx.mock
def test_api_authentication_error_is_sanitized() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(401, json={"error": "credential rejected"})
    )
    with pytest.raises(CollectorFailure, match="authentication failed"):
        ShodanCollector(api_key="x", retries=0).collect("example.com")


@respx.mock
def test_shodan_provider_error_is_reported_without_secret() -> None:
    respx.get("https://api.shodan.io/shodan/host/search").mock(
        return_value=httpx.Response(
            400,
            json={"error": "Invalid request for secret-token"},
        )
    )
    with pytest.raises(CollectorFailure) as error:
        ShodanCollector(api_key="secret-token", retries=0).collect("example.com")
    assert "Invalid request" in str(error.value)
    assert "secret-token" not in str(error.value)


@respx.mock
def test_malformed_json_and_invalid_utf8_are_rejected() -> None:
    route = respx.get("https://api.shodan.io/shodan/host/search")
    route.mock(return_value=httpx.Response(200, content=b"not-json"))
    with pytest.raises(CollectorFailure, match="malformed JSON"):
        ShodanCollector(api_key="x").collect("example.com")

    crt_route = respx.get("https://crt.name/v1/search")
    crt_route.mock(return_value=httpx.Response(200, content=b"\xff"))
    with pytest.raises(CollectorFailure, match="invalid UTF-8"):
        CrtNameCollector().collect("example.com")


class DefensiveResolver:
    def resolve(self, hostname: str, record_type: str, **_: object) -> FakeAnswer:
        if record_type == "A":
            return FakeAnswer(["not-an-ip"])
        if record_type == "AAAA":
            raise dns.resolver.NoAnswer
        return FakeAnswer(["outside.test."])


def test_dns_rejects_invalid_and_out_of_scope_answers() -> None:
    result = DnsCollector(resolver=DefensiveResolver()).collect(["www.example.com"], "example.com")
    assert not result.assets
    assert result.warnings == [
        "DNS returned invalid A for www.example.com",
        "DNS CNAME outside scope ignored for www.example.com",
    ]


class TimeoutResolver:
    def resolve(self, *_: object, **__: object) -> FakeAnswer:
        raise dns.exception.Timeout


def test_dns_timeout_becomes_a_warning() -> None:
    result = DnsCollector(resolver=TimeoutResolver()).collect(["www.example.com"], "example.com")
    assert len(result.warnings) == 3
    assert all("Timeout" in warning for warning in result.warnings)
