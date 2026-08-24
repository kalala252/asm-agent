import json
from datetime import UTC, datetime
from pathlib import Path

from asm_agent.collectors import CollectorFailure, CollectorResult
from asm_agent.engine import ReconEngine, ScanOptions
from asm_agent.models import Asset, AssetType, Evidence, VulnerabilityObservation
from asm_agent.reporting import write_reports

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class StaticCollector:
    def collect(self, domain: str) -> CollectorResult:
        host = "www.example.com"
        return CollectorResult(
            assets=[
                Asset(asset_type=AssetType.HOSTNAME, value=host, first_seen=NOW, last_seen=NOW),
                Asset(asset_type=AssetType.HOSTNAME, value=host, first_seen=NOW, last_seen=NOW),
            ],
            evidence=[
                Evidence(
                    subject=host,
                    relation="observed_in",
                    object=domain,
                    source="crt.name",
                    collected_at=NOW,
                    source_observed_at=datetime(2025, 12, 31, tzinfo=UTC),
                    confidence=0.9,
                    raw_reference="line:1",
                    inferred=False,
                )
            ],
            received_count=1,
            accepted_count=1,
            available_count=1,
            limit=1_000,
        )


class FailingCollector:
    def collect(self, domain: str) -> CollectorResult:
        raise CollectorFailure("upstream unavailable")


class RelatedVulnerabilityCollector:
    def collect(self, domain: str) -> CollectorResult:
        ip = "192.0.2.10"
        hostname = f"dev.{domain}"
        service = f"{ip}:8009/tcp"
        return CollectorResult(
            assets=[
                Asset(
                    asset_type=AssetType.HOSTNAME,
                    value=hostname,
                    first_seen=NOW,
                    last_seen=NOW,
                ),
                Asset(asset_type=AssetType.IP, value=ip, first_seen=NOW, last_seen=NOW),
                Asset(
                    asset_type=AssetType.SERVICE,
                    value=service,
                    first_seen=NOW,
                    last_seen=NOW,
                ),
            ],
            evidence=[
                Evidence(
                    subject=hostname,
                    relation="resolves_to",
                    object=ip,
                    source="shodan",
                    collected_at=NOW,
                    source_observed_at=NOW,
                    confidence=1.0,
                    raw_reference="host:192.0.2.10",
                    inferred=False,
                ),
                Evidence(
                    subject=service,
                    relation="reports_vulnerability",
                    object="CVE-2020-1938",
                    source="shodan",
                    collected_at=NOW,
                    source_observed_at=NOW,
                    confidence=1.0,
                    raw_reference="host:192.0.2.10:vuln:CVE-2020-1938",
                    inferred=False,
                ),
            ],
            vulnerabilities=[
                VulnerabilityObservation(
                    service=service,
                    ip=ip,
                    port=8009,
                    transport="tcp",
                    vulnerability_id="CVE-2020-1938",
                    verified=False,
                    product="Apache Tomcat",
                    version="9.0.30",
                    collected_at=NOW,
                    source_observed_at=NOW,
                    raw_reference="host:192.0.2.10:vuln:CVE-2020-1938",
                )
            ],
            received_count=1,
            accepted_count=1,
            available_count=1,
            limit=100,
        )


def test_partial_failure_still_builds_deduplicated_stable_report(tmp_path: Path) -> None:
    engine = ReconEngine(
        crt_collector=StaticCollector(),
        shodan_collector=FailingCollector(),
        clock=lambda: NOW,
    )
    report = engine.scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True, enable_shodan=True)
    )
    assert len([a for a in report.assets if a.value == "www.example.com"]) == 1
    assert report.collector_errors[0].collector == "shodan"
    assert [(run.collector, run.status) for run in report.collector_runs] == [
        ("crt.name", "success"),
        ("shodan", "failed"),
    ]
    json_path, md_path = write_reports(report, tmp_path)
    first_json = json_path.read_bytes()
    payload = json.loads(first_json)
    assert payload["assets"] == sorted(
        payload["assets"], key=lambda item: (item["asset_type"], item["value"])
    )
    markdown = md_path.read_text()
    assert "Passive調査" in markdown
    assert "upstream unavailable" in markdown
    assert "## コレクター実行結果" in markdown
    write_reports(report, tmp_path)
    assert json_path.read_bytes() == first_json


def test_report_describes_shodan_vulnerability_as_observation_not_fact(
    tmp_path: Path,
) -> None:
    report = ReconEngine(crt_collector=EmptyCollector(), clock=lambda: NOW).scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True)
    )
    report = report.model_copy(
        update={
            "vulnerability_observations": [
                VulnerabilityObservation(
                    service="192.0.2.10:443/tcp",
                    ip="192.0.2.10",
                    port=443,
                    transport="tcp",
                    vulnerability_id="CVE-2026-1234",
                    verified=False,
                    cvss=7.5,
                    product="Example Server",
                    version="1.2.3",
                    collected_at=NOW,
                    source_observed_at=NOW,
                    raw_reference="match:0:vuln:CVE-2026-1234",
                )
            ]
        }
    )

    _, markdown_path = write_reports(report, tmp_path)
    markdown = markdown_path.read_text()

    assert "## Shodanが関連付けた脆弱性候補" in markdown
    assert "CVE-2026-1234" in markdown
    assert "未検証" in markdown
    assert "現在の脆弱性を確定するものではありません" in markdown


def test_report_links_vulnerability_to_related_hostname(tmp_path: Path) -> None:
    report = ReconEngine(
        crt_collector=EmptyCollector(),
        shodan_collector=RelatedVulnerabilityCollector(),
        clock=lambda: NOW,
    ).scan(
        ScanOptions(
            domain="example.com",
            output_dir=tmp_path,
            skip_dns=True,
            enable_shodan=True,
        )
    )

    assert report.vulnerability_observations[0].related_hostnames == [
        "dev.example.com"
    ]


def test_max_hosts_and_skip_dns_are_honored(tmp_path: Path) -> None:
    collector = StaticCollector()
    report = ReconEngine(crt_collector=collector, clock=lambda: NOW).scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True, max_hosts=1)
    )
    assert {asset.value for asset in report.assets} == {"example.com", "www.example.com"}


def test_invalid_max_hosts_is_rejected(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="max_hosts"):
        ScanOptions(domain="example.com", output_dir=tmp_path, max_hosts=0)


def test_invalid_max_api_pages_is_rejected(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="max_api_pages"):
        ScanOptions(domain="example.com", output_dir=tmp_path, max_api_pages=0)


def test_invalid_max_shodan_host_lookups_is_rejected(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="max_shodan_host_lookups"):
        ScanOptions(
            domain="example.com",
            output_dir=tmp_path,
            max_shodan_host_lookups=0,
        )


class EmptyCollector:
    def collect(self, domain: str) -> CollectorResult:
        return CollectorResult(limit=1_000)


class RejectedCollector:
    def collect(self, domain: str) -> CollectorResult:
        return CollectorResult(received_count=1, accepted_count=0, limit=1_000)


def test_empty_successful_domain_collector_is_visible(tmp_path: Path) -> None:
    report = ReconEngine(crt_collector=EmptyCollector(), clock=lambda: NOW).scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True)
    )
    assert report.collector_runs[0].status == "success"
    assert report.collector_runs[0].received_count == 0
    assert report.warnings == ["crt.name returned no records"]


def test_all_rejected_domain_records_are_visible(tmp_path: Path) -> None:
    report = ReconEngine(crt_collector=RejectedCollector(), clock=lambda: NOW).scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True)
    )
    assert report.warnings == ["crt.name accepted no records from 1 received"]


class ServiceCollector:
    def __init__(self, source_observed_at: datetime | None) -> None:
        self._source_observed_at = source_observed_at

    def collect(self, domain: str) -> CollectorResult:
        service = "192.0.2.10:443/tcp"
        return CollectorResult(
            assets=[
                Asset(asset_type=AssetType.SERVICE, value=service, first_seen=NOW, last_seen=NOW)
            ],
            evidence=[
                Evidence(
                    subject="192.0.2.10",
                    relation="exposes",
                    object=service,
                    source="shodan",
                    collected_at=NOW,
                    source_observed_at=self._source_observed_at,
                    confidence=1.0,
                    raw_reference="record:0",
                    inferred=False,
                )
            ],
            received_count=1,
            accepted_count=1,
            available_count=1,
            limit=1_000,
        )


def test_service_priority_requires_recent_source_observation(tmp_path: Path) -> None:
    fresh = ReconEngine(
        crt_collector=EmptyCollector(),
        shodan_collector=ServiceCollector(datetime(2025, 12, 15, tzinfo=UTC)),
        clock=lambda: NOW,
    ).scan(
        ScanOptions(
            domain="example.com",
            output_dir=tmp_path,
            skip_dns=True,
            enable_shodan=True,
        )
    )
    stale = ReconEngine(
        crt_collector=EmptyCollector(),
        shodan_collector=ServiceCollector(datetime(2025, 1, 1, tzinfo=UTC)),
        clock=lambda: NOW,
    ).scan(
        ScanOptions(
            domain="example.com",
            output_dir=tmp_path,
            skip_dns=True,
            enable_shodan=True,
        )
    )
    unknown = ReconEngine(
        crt_collector=EmptyCollector(),
        shodan_collector=ServiceCollector(None),
        clock=lambda: NOW,
    ).scan(
        ScanOptions(
            domain="example.com",
            output_dir=tmp_path,
            skip_dns=True,
            enable_shodan=True,
        )
    )
    future = ReconEngine(
        crt_collector=EmptyCollector(),
        shodan_collector=ServiceCollector(datetime(2026, 2, 1, tzinfo=UTC)),
        clock=lambda: NOW,
    ).scan(
        ScanOptions(
            domain="example.com",
            output_dir=tmp_path,
            skip_dns=True,
            enable_shodan=True,
        )
    )
    fresh_service = next(
        item for item in fresh.findings if item.asset_type is AssetType.SERVICE
    )
    stale_service = next(
        item for item in stale.findings if item.asset_type is AssetType.SERVICE
    )
    assert fresh_service.priority == "high"
    assert stale_service.priority == "review_required"
    assert next(
        item for item in unknown.findings if item.asset_type is AssetType.SERVICE
    ).priority == "review_required"
    assert next(
        item for item in future.findings if item.asset_type is AssetType.SERVICE
    ).priority == "review_required"


class CorroboratedCollector:
    def collect(self, domain: str) -> CollectorResult:
        hostname = "api.example.com"
        ip = "192.0.2.20"
        service = f"{ip}:443/tcp"
        observed_at = datetime(2025, 12, 20, tzinfo=UTC)
        return CollectorResult(
            assets=[
                Asset(asset_type=AssetType.HOSTNAME, value=hostname, first_seen=NOW, last_seen=NOW),
                Asset(asset_type=AssetType.IP, value=ip, first_seen=NOW, last_seen=NOW),
                Asset(asset_type=AssetType.SERVICE, value=service, first_seen=NOW, last_seen=NOW),
            ],
            evidence=[
                Evidence(
                    subject=hostname,
                    relation="observed_in",
                    object=domain,
                    source="crt.name",
                    collected_at=NOW,
                    source_observed_at=observed_at,
                    confidence=1.0,
                    raw_reference="line:1",
                ),
                Evidence(
                    subject=hostname,
                    relation="resolves_to",
                    object=ip,
                    source="dns",
                    collected_at=NOW,
                    confidence=1.0,
                    raw_reference="A",
                ),
                Evidence(
                    subject=hostname,
                    relation="resolves_to",
                    object=ip,
                    source="shodan",
                    collected_at=NOW,
                    source_observed_at=observed_at,
                    confidence=1.0,
                    raw_reference="match:0",
                ),
                Evidence(
                    subject=ip,
                    relation="exposes",
                    object=service,
                    source="shodan",
                    collected_at=NOW,
                    source_observed_at=observed_at,
                    confidence=1.0,
                    raw_reference="record:0",
                ),
            ],
            received_count=1,
            accepted_count=1,
            available_count=1,
            limit=1_000,
        )


def test_association_confidence_uses_multiple_independent_signals(tmp_path: Path) -> None:
    report = ReconEngine(crt_collector=CorroboratedCollector(), clock=lambda: NOW).scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True)
    )
    assessments = {item.value: item for item in report.association_assessments}
    assert assessments["api.example.com"].confidence == "high"
    assert assessments["192.0.2.20"].confidence == "high"
    assert assessments["192.0.2.20:443/tcp"].confidence == "high"
    assert assessments["192.0.2.20"].evidence_sources == ["dns", "shodan"]
    assert all("ownership" in item.caveat.lower() for item in assessments.values())


def test_certificate_only_hostname_has_low_association_confidence(tmp_path: Path) -> None:
    report = ReconEngine(crt_collector=StaticCollector(), clock=lambda: NOW).scan(
        ScanOptions(domain="example.com", output_dir=tmp_path, skip_dns=True)
    )
    assessment = next(
        item for item in report.association_assessments if item.value == "www.example.com"
    )
    assert assessment.confidence == "low"
    assert assessment.evidence_sources == ["crt.name"]
