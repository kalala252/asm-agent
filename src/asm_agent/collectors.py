"""Collectors restricted to approved passive data sources and DNS."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import dns.exception
import dns.resolver
import httpx

from asm_agent.domain import DomainValidationError, is_in_scope, normalize_hostname
from asm_agent.models import Asset, AssetType, Evidence, VulnerabilityObservation

USER_AGENT = "asm-agent/0.1 (+passive-recon)"


class CollectorFailure(RuntimeError):
    """A sanitized collector error safe to include in a report."""


@dataclass(slots=True)
class CollectorResult:
    assets: list[Asset] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityObservation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    received_count: int = 0
    accepted_count: int = 0
    available_count: int | None = None
    limit: int | None = None
    partial: bool = False
    next_page_available: bool = False


class DomainCollector(Protocol):
    def collect(self, domain: str) -> CollectorResult: ...


class Resolver(Protocol):
    def resolve(self, hostname: str, record_type: str, **kwargs: object) -> Iterable[Any]: ...


class _HttpCollector:
    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
        retries: int = 2,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if not 0 <= retries <= 5:
            raise ValueError("retries must be between 0 and 5")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._client = client or httpx.Client(follow_redirects=False)
        self._timeout = timeout
        self._retries = retries
        self._max_response_bytes = max_response_bytes

    def _get(
        self,
        url: str,
        *,
        params: Mapping[str, str | int],
        auth: tuple[str, str] | None = None,
    ) -> bytes:
        return self._request("GET", url, params=params, auth=auth)

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str | int],
        json_body: Mapping[str, object] | None = None,
        auth: tuple[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        sensitive_values: Iterable[str] = (),
    ) -> bytes:
        last_kind = "request"
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain",
            **(headers or {}),
        }
        for attempt in range(self._retries + 1):
            response: httpx.Response | None = None
            try:
                request_kwargs: dict[str, Any] = {
                    "params": params,
                    "headers": request_headers,
                    "timeout": self._timeout,
                }
                if json_body is not None:
                    request_kwargs["json"] = json_body
                request = self._client.build_request(method, url, **request_kwargs)
                response = self._client.send(request, stream=True, auth=auth)
                body = self._read_limited(response)
                detail = self._provider_error(
                    body,
                    params=params,
                    auth=auth,
                    sensitive_values=sensitive_values,
                )
                if response.status_code == 429:
                    last_kind = "rate limit"
                    if attempt < self._retries:
                        continue
                    raise CollectorFailure(_with_detail("upstream rate limit exceeded", detail))
                if response.status_code in {401, 403}:
                    raise CollectorFailure(_with_detail("upstream authentication failed", detail))
                if response.status_code >= 500:
                    last_kind = "server"
                    if attempt < self._retries:
                        continue
                    raise CollectorFailure(_with_detail("upstream server failure", detail))
                if not 200 <= response.status_code < 300:
                    message = f"upstream returned HTTP {response.status_code}"
                    raise CollectorFailure(_with_detail(message, detail))
                return body
            except (httpx.TimeoutException, httpx.NetworkError):
                last_kind = "timeout or network"
                if attempt >= self._retries:
                    raise CollectorFailure("upstream request timed out or failed") from None
            except (TypeError, ValueError) as error:
                raise CollectorFailure("upstream returned invalid metadata") from error
            finally:
                if response is not None:
                    response.close()
        raise CollectorFailure(f"upstream {last_kind} failure")

    def _read_limited(self, response: httpx.Response) -> bytes:
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > self._max_response_bytes:
            raise CollectorFailure("upstream response exceeded size limit")
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > self._max_response_bytes:
                raise CollectorFailure("upstream response exceeded size limit")
        return bytes(body)

    @staticmethod
    def _provider_error(
        body: bytes,
        *,
        params: Mapping[str, str | int],
        auth: tuple[str, str] | None,
        sensitive_values: Iterable[str] = (),
    ) -> str | None:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        raw_detail = next(
            (
                payload[name]
                for name in ("error", "detail", "title")
                if isinstance(payload.get(name), str)
            ),
            None,
        )
        if raw_detail is None:
            return None
        detail = " ".join(raw_detail.split())
        secrets = [
            str(value)
            for name, value in params.items()
            if any(marker in name.lower() for marker in ("key", "secret", "token"))
        ]
        secrets.extend(auth or ())
        secrets.extend(sensitive_values)
        for secret in secrets:
            if secret:
                detail = detail.replace(secret, "[REDACTED]")
        return detail[:200] or None

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CollectorFailure("upstream returned malformed JSON") from error
        if not isinstance(payload, dict):
            raise CollectorFailure("upstream returned an unexpected JSON shape")
        return payload


class CrtNameCollector(_HttpCollector):
    URL = "https://crt.name/v1/search"

    def __init__(self, *, max_hosts: int = 1_000, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._max_hosts = max_hosts

    def collect(self, domain: str) -> CollectorResult:
        body = self._get(
            self.URL,
            params={"apex": domain, "dates": 1, "format": "json"},
        )
        try:
            payload = json.loads(body)
        except UnicodeDecodeError as error:
            raise CollectorFailure("crt.name returned invalid UTF-8") from error
        except json.JSONDecodeError as error:
            raise CollectorFailure("crt.name returned malformed JSON") from error
        if not isinstance(payload, list):
            raise CollectorFailure("crt.name returned an unexpected JSON shape")
        hostnames: dict[str, datetime | None] = {}
        warnings: list[str] = []
        for raw_record in payload:
            if not isinstance(raw_record, dict):
                continue
            hostname_text = raw_record.get("sub")
            if not isinstance(hostname_text, str):
                continue
            try:
                hostname = normalize_hostname(hostname_text)
            except DomainValidationError:
                continue
            if is_in_scope(hostname, domain):
                raw_timestamp = raw_record.get("first_seen")
                source_observed_at = _parse_source_timestamp(raw_timestamp)
                if raw_timestamp is not None and source_observed_at is None:
                    warnings.append(f"crt.name returned an invalid timestamp for {hostname}")
                current = hostnames.get(hostname)
                if current is None or (
                    source_observed_at is not None and source_observed_at < current
                ):
                    hostnames[hostname] = source_observed_at
        collected_at = datetime.now(UTC)
        assets: list[Asset] = []
        evidence: list[Evidence] = []
        selected_hostnames = sorted(hostnames)[: self._max_hosts]
        for index, hostname in enumerate(selected_hostnames, start=1):
            source_observed_at = hostnames[hostname]
            assets.append(
                _asset(AssetType.HOSTNAME, hostname, source_observed_at or collected_at)
            )
            evidence.append(
                _evidence(
                    hostname,
                    "observed_in",
                    domain,
                    "crt.name",
                    collected_at,
                    f"line:{index}",
                    source_observed_at=source_observed_at,
                )
            )
        available_count = len(hostnames)
        return CollectorResult(
            assets=assets,
            evidence=evidence,
            warnings=warnings,
            received_count=len(payload),
            accepted_count=len(selected_hostnames),
            available_count=available_count,
            limit=self._max_hosts,
            partial=available_count > len(selected_hostnames),
        )


class DnsCollector:
    def __init__(self, *, resolver: Resolver | None = None, timeout: float = 5.0) -> None:
        self._resolver = cast(Resolver, resolver or dns.resolver.Resolver())
        self._timeout = timeout

    def collect(self, hostnames: Iterable[str], domain: str) -> CollectorResult:
        result = CollectorResult()
        for hostname in sorted(set(hostnames)):
            nxdomain = False
            for record_type in ("A", "AAAA", "CNAME"):
                try:
                    answer = self._resolver.resolve(
                        hostname,
                        record_type,
                        lifetime=self._timeout,
                        search=False,
                    )
                except dns.resolver.NXDOMAIN:
                    nxdomain = True
                    break
                except dns.resolver.NoAnswer:
                    continue
                except (dns.exception.Timeout, dns.resolver.NoNameservers) as error:
                    result.warnings.append(
                        f"DNS {record_type} failed for {hostname}: {type(error).__name__}"
                    )
                    continue
                collected_at = datetime.now(UTC)
                for record in answer:
                    result.received_count += 1
                    value = record.to_text().strip()
                    if record_type in {"A", "AAAA"}:
                        try:
                            normalized_ip = str(ipaddress.ip_address(value))
                        except ValueError:
                            result.warnings.append(
                                f"DNS returned invalid {record_type} for {hostname}"
                            )
                            continue
                        result.assets.append(_asset(AssetType.IP, normalized_ip, collected_at))
                        result.accepted_count += 1
                        result.evidence.append(
                            _evidence(
                                hostname,
                                "resolves_to",
                                normalized_ip,
                                "dns",
                                collected_at,
                                record_type,
                            )
                        )
                    else:
                        try:
                            target = normalize_hostname(value)
                        except DomainValidationError:
                            result.warnings.append(f"DNS returned invalid CNAME for {hostname}")
                            continue
                        if not is_in_scope(target, domain):
                            result.warnings.append(
                                f"DNS CNAME outside scope ignored for {hostname}"
                            )
                            continue
                        result.assets.append(_asset(AssetType.HOSTNAME, target, collected_at))
                        result.accepted_count += 1
                        result.evidence.append(
                            _evidence(hostname, "aliases_to", target, "dns", collected_at, "CNAME")
                        )
            if nxdomain:
                result.warnings.append(f"DNS NXDOMAIN: {hostname}")
        return result


class ShodanCollector(_HttpCollector):
    HTTP_METHOD = "GET"
    URL = "https://api.shodan.io/shodan/host/search"
    HOST_URL_TEMPLATE = "https://api.shodan.io/shodan/host/{ip}"

    def __init__(
        self,
        *,
        api_key: str | None,
        max_hosts: int = 1_000,
        max_pages: int = 1,
        max_host_lookups: int = 100,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("max_response_bytes", 10_000_000)
        super().__init__(**kwargs)
        if not 1 <= max_pages <= 10:
            raise ValueError("max_pages must be between 1 and 10")
        if not 1 <= max_host_lookups <= 1_000:
            raise ValueError("max_host_lookups must be between 1 and 1000")
        self._api_key = api_key
        self._max_hosts = max_hosts
        self._max_pages = max_pages
        self._max_host_lookups = max_host_lookups

    def collect(self, domain: str) -> CollectorResult:
        if not self._api_key:
            raise CollectorFailure("SHODAN_API_KEY is required when Shodan is enabled")
        all_matches: list[object] = []
        total: int | None = None
        for page in range(1, self._max_pages + 1):
            params: dict[str, str | int] = {
                "key": self._api_key,
                "query": f"hostname:{domain}",
                "minify": "false",
                "fields": (
                    "ip_str,port,transport,hostnames,timestamp,product,version,cpe,vulns"
                ),
            }
            if page > 1:
                params["page"] = page
            payload = self._json(self._get(self.URL, params=params))
            matches = payload.get("matches")
            if not isinstance(matches, list):
                raise CollectorFailure("Shodan returned an unexpected response shape")
            all_matches.extend(matches)
            payload_total = _nonnegative_int(payload.get("total"))
            if payload_total is not None:
                total = payload_total
            if len(all_matches) >= self._max_hosts or not matches:
                break
            if total is not None and len(all_matches) >= total:
                break
        selected_matches = all_matches[: self._max_hosts]
        result = _observations_from_shodan(selected_matches, domain)
        available_count = total if total is not None else len(all_matches)
        result.received_count = len(all_matches)
        result.available_count = available_count
        result.limit = self._max_hosts
        result.next_page_available = available_count > len(all_matches)
        search_partial = available_count > len(selected_matches) or len(all_matches) > len(
            selected_matches
        )
        in_scope_ips = _in_scope_shodan_ips(selected_matches, domain)
        selected_ips = in_scope_ips[: self._max_host_lookups]
        detail_failures: list[tuple[str, str]] = []
        detail_successes = 0
        for ip in selected_ips:
            try:
                payload = self._json(
                    self._get(
                        self.HOST_URL_TEMPLATE.format(ip=ip),
                        params={"key": self._api_key, "minify": "false"},
                    )
                )
                detail_result = _observations_from_shodan_host(payload, ip, domain)
            except CollectorFailure as error:
                detail_failures.append((ip, str(error)))
                if "authentication failed" in str(error) or "rate limit" in str(error):
                    break
                continue
            detail_successes += 1
            _merge_collector_results(result, detail_result)

        attempted_details = detail_successes + len(detail_failures)
        detail_partial = len(in_scope_ips) > len(selected_ips) or bool(detail_failures)
        if in_scope_ips:
            result.warnings.append(
                "Shodan Host Information queried "
                f"{attempted_details} of {len(in_scope_ips)} in-scope IP addresses; "
                f"{detail_successes} succeeded and {len(detail_failures)} failed"
            )
        if len(in_scope_ips) > len(selected_ips):
            result.warnings.append(
                "Shodan Host Information lookup limit reached: "
                f"{len(selected_ips)} of {len(in_scope_ips)} IP addresses were selected"
            )
        for ip, message in detail_failures[:20]:
            result.warnings.append(f"Shodan Host Information failed for {ip}: {message}")
        if len(detail_failures) > 20:
            result.warnings.append(
                f"Shodan Host Information omitted {len(detail_failures) - 20} failure messages"
            )
        result.partial = search_partial or detail_partial
        return result


def _in_scope_shodan_ips(matches: list[object], domain: str) -> list[str]:
    ips: set[str] = set()
    for raw_match in matches:
        if not isinstance(raw_match, dict):
            continue
        if not _safe_hostnames(raw_match.get("hostnames", []), domain):
            continue
        raw_ip = raw_match.get("ip_str")
        if not isinstance(raw_ip, str):
            continue
        try:
            ips.add(str(ipaddress.ip_address(raw_ip)))
        except ValueError:
            continue
    return sorted(ips, key=lambda value: (ipaddress.ip_address(value).version, value))


def _observations_from_shodan_host(
    payload: dict[str, Any], requested_ip: str, domain: str
) -> CollectorResult:
    payload_ip = payload.get("ip_str")
    if payload_ip is not None:
        try:
            normalized_payload_ip = str(ipaddress.ip_address(payload_ip))
        except (TypeError, ValueError) as error:
            raise CollectorFailure("Shodan Host Information returned an invalid IP") from error
        if normalized_payload_ip != requested_ip:
            raise CollectorFailure("Shodan Host Information returned a different IP")
    banners = payload.get("data")
    if not isinstance(banners, list):
        raise CollectorFailure("Shodan Host Information returned an unexpected response shape")

    result = CollectorResult(received_count=len(banners))
    collected_at = datetime.now(UTC)
    raw_last_update = payload.get("last_update")
    host_observed_at = _parse_source_timestamp(raw_last_update)
    if raw_last_update is not None and host_observed_at is None:
        result.warnings.append(
            f"Shodan returned an invalid last_update for host:{requested_ip}"
        )
    top_level_hostnames = _safe_hostnames(payload.get("hostnames", []), domain)
    for hostname in top_level_hostnames:
        result.assets.append(
            _asset(AssetType.HOSTNAME, hostname, host_observed_at or collected_at)
        )
        result.evidence.append(
            _evidence(
                hostname,
                "resolves_to",
                requested_ip,
                "shodan",
                collected_at,
                f"host:{requested_ip}",
                source_observed_at=host_observed_at,
            )
        )

    for index, raw_banner in enumerate(banners):
        if not isinstance(raw_banner, dict):
            continue
        raw_timestamp = raw_banner.get("timestamp")
        source_observed_at = _parse_source_timestamp(raw_timestamp)
        reference = f"host:{requested_ip}:banner:{index}"
        if raw_timestamp is not None and source_observed_at is None:
            result.warnings.append(
                f"Shodan returned an invalid timestamp for {reference}"
            )
        before_assets = len(result.assets)
        result.assets.append(
            _asset(AssetType.IP, requested_ip, source_observed_at or collected_at)
        )
        _append_service(
            result,
            raw_banner,
            requested_ip,
            "shodan",
            index,
            collected_at,
            source_observed_at,
            reference_prefix=reference,
        )
        if len(result.assets) > before_assets + 1:
            result.accepted_count += 1
        for hostname in _safe_hostnames(raw_banner.get("hostnames", []), domain):
            result.assets.append(
                _asset(AssetType.HOSTNAME, hostname, source_observed_at or collected_at)
            )
            result.evidence.append(
                _evidence(
                    hostname,
                    "resolves_to",
                    requested_ip,
                    "shodan",
                    collected_at,
                    reference,
                    source_observed_at=source_observed_at,
                )
            )
    return result


def _merge_collector_results(target: CollectorResult, additional: CollectorResult) -> None:
    target.assets.extend(additional.assets)
    target.evidence.extend(additional.evidence)
    target.vulnerabilities.extend(additional.vulnerabilities)
    target.warnings.extend(additional.warnings)


def _asset(asset_type: AssetType, value: str, timestamp: datetime) -> Asset:
    return Asset(asset_type=asset_type, value=value, first_seen=timestamp, last_seen=timestamp)


def _with_detail(message: str, detail: str | None) -> str:
    return f"{message}: {detail}" if detail else message


def _evidence(
    subject: str,
    relation: str,
    object_value: str,
    source: str,
    collected_at: datetime,
    reference: str,
    *,
    source_observed_at: datetime | None = None,
) -> Evidence:
    return Evidence(
        subject=subject,
        relation=relation,
        object=object_value,
        source=source,
        collected_at=collected_at,
        source_observed_at=source_observed_at,
        confidence=1.0,
        raw_reference=reference,
        inferred=False,
    )


def _safe_hostnames(value: object, domain: str) -> list[str]:
    candidates = value if isinstance(value, list) else [value]
    hostnames: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            hostname = normalize_hostname(candidate)
        except DomainValidationError:
            continue
        if is_in_scope(hostname, domain):
            hostnames.add(hostname)
    return sorted(hostnames)


def _observations_from_shodan(matches: list[object], domain: str) -> CollectorResult:
    result = CollectorResult()
    for index, raw_match in enumerate(matches):
        if not isinstance(raw_match, dict):
            continue
        hostnames = _safe_hostnames(raw_match.get("hostnames", []), domain)
        if not hostnames:
            continue
        collected_at = datetime.now(UTC)
        raw_timestamp = raw_match.get("timestamp")
        source_observed_at = _parse_source_timestamp(raw_timestamp)
        if raw_timestamp is not None and source_observed_at is None:
            result.warnings.append(f"Shodan returned an invalid timestamp for match:{index}")
        ip_value = raw_match.get("ip_str")
        try:
            ip = str(ipaddress.ip_address(ip_value)) if isinstance(ip_value, str) else None
        except ValueError:
            ip = None
        result.accepted_count += 1
        for hostname in hostnames:
            asset_time = source_observed_at or collected_at
            result.assets.append(_asset(AssetType.HOSTNAME, hostname, asset_time))
            result.evidence.append(
                _evidence(
                    hostname,
                    "observed_in",
                    domain,
                    "shodan",
                    collected_at,
                    f"match:{index}",
                    source_observed_at=source_observed_at,
                )
            )
            if ip:
                result.evidence.append(
                    _evidence(
                        hostname,
                        "resolves_to",
                        ip,
                        "shodan",
                        collected_at,
                        f"match:{index}",
                        source_observed_at=source_observed_at,
                    )
                )
        if not ip:
            continue
        result.assets.append(_asset(AssetType.IP, ip, source_observed_at or collected_at))
        _append_service(
            result,
            raw_match,
            ip,
            "shodan",
            index,
            collected_at,
            source_observed_at,
        )
    return result


def _append_service(
    result: CollectorResult,
    raw: dict[str, Any],
    ip: str,
    source: str,
    index: int,
    collected_at: datetime,
    source_observed_at: datetime | None,
    *,
    reference_prefix: str | None = None,
) -> None:
    port = raw.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return
    transport_value = raw.get("transport", raw.get("transport_protocol", "tcp"))
    transport = transport_value.lower() if isinstance(transport_value, str) else "tcp"
    if transport not in {"tcp", "udp"}:
        transport = "unknown"
    value = f"{ip}:{port}/{transport}"
    service_reference = (
        f"record:{index}" if reference_prefix is None else f"{reference_prefix}:service"
    )
    result.assets.append(_asset(AssetType.SERVICE, value, source_observed_at or collected_at))
    result.evidence.append(
        _evidence(
            ip,
            "exposes",
            value,
            source,
            collected_at,
            service_reference,
            source_observed_at=source_observed_at,
        )
    )
    _append_vulnerabilities(
        result,
        raw,
        ip=ip,
        port=port,
        transport=transport,
        service=value,
        index=index,
        collected_at=collected_at,
        source_observed_at=source_observed_at,
        reference_prefix=reference_prefix,
    )


def _append_vulnerabilities(
    result: CollectorResult,
    raw: dict[str, Any],
    *,
    ip: str,
    port: int,
    transport: str,
    service: str,
    index: int,
    collected_at: datetime,
    source_observed_at: datetime | None,
    reference_prefix: str | None,
) -> None:
    raw_vulnerabilities = raw.get("vulns")
    if isinstance(raw_vulnerabilities, dict):
        entries = list(raw_vulnerabilities.items())
    elif isinstance(raw_vulnerabilities, list):
        entries = [(item, None) for item in raw_vulnerabilities]
    else:
        return

    product = _bounded_string(raw.get("product"), 200)
    version = _bounded_string(raw.get("version"), 200)
    cpes = _bounded_strings(raw.get("cpe"), count=20, length=300)
    for raw_identifier, raw_details in entries:
        vulnerability_id = _normalize_cve(raw_identifier)
        if vulnerability_id is None:
            continue
        details = raw_details if isinstance(raw_details, dict) else {}
        verified_value = details.get("verified")
        verified = verified_value if isinstance(verified_value, bool) else None
        cvss_value = details.get("cvss")
        cvss = (
            float(cvss_value)
            if isinstance(cvss_value, (int, float))
            and not isinstance(cvss_value, bool)
            and 0 <= cvss_value <= 10
            else None
        )
        cvss_v2 = _bounded_score(details.get("cvss_v2"), maximum=10.0)
        epss = _bounded_score(details.get("epss"), maximum=1.0)
        ranking_epss = _bounded_score(details.get("ranking_epss"), maximum=1.0)
        kev_value = details.get("kev")
        kev = kev_value if isinstance(kev_value, bool) else None
        reference = (
            f"match:{index}:vuln:{vulnerability_id}"
            if reference_prefix is None
            else f"{reference_prefix}:vuln:{vulnerability_id}"
        )
        result.vulnerabilities.append(
            VulnerabilityObservation(
                service=service,
                ip=ip,
                port=port,
                transport=transport,  # type: ignore[arg-type]
                vulnerability_id=vulnerability_id,
                verified=verified,
                cvss=cvss,
                cvss_v2=cvss_v2,
                cvss_version=_bounded_scalar_string(details.get("cvss_version"), 20),
                epss=epss,
                ranking_epss=ranking_epss,
                kev=kev,
                summary=_bounded_string(details.get("summary"), 2_000),
                references=_bounded_strings(
                    details.get("references"), count=20, length=2_000
                ),
                product=product,
                version=version,
                cpes=cpes,
                collected_at=collected_at,
                source_observed_at=source_observed_at,
                raw_reference=reference,
            )
        )
        result.evidence.append(
            _evidence(
                service,
                "reports_vulnerability",
                vulnerability_id,
                "shodan",
                collected_at,
                reference,
                source_observed_at=source_observed_at,
            )
        )


def _normalize_cve(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        return None
    return normalized


def _bounded_string(value: object, length: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split())
    return normalized[:length] or None


def _bounded_scalar_string(value: object, length: int) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)[:length]
    return _bounded_string(value, length)


def _bounded_score(value: object, *, maximum: float) -> float | None:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= maximum
    ):
        return float(value)
    return None


def _bounded_strings(value: object, *, count: int, length: int) -> list[str]:
    candidates = value if isinstance(value, list) else [value]
    strings = {
        normalized
        for candidate in candidates
        if (normalized := _bounded_string(candidate, length)) is not None
    }
    return sorted(strings)[:count]


def _parse_source_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.lower() == "unknown":
        return None
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None
