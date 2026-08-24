"""Deterministic orchestration for passive collectors."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from asm_agent.collectors import (
    CollectorFailure,
    CollectorResult,
    DnsCollector,
    DomainCollector,
)
from asm_agent.domain import normalize_domain
from asm_agent.models import (
    Asset,
    AssetType,
    AssociationAssessment,
    CollectorError,
    CollectorRun,
    Evidence,
    Finding,
    InputScope,
    ScanMetadata,
    ScanReport,
    VulnerabilityObservation,
)

FRESH_SERVICE_OBSERVATION_DAYS = 90


@dataclass(frozen=True, slots=True)
class ScanOptions:
    domain: str
    output_dir: Path
    skip_dns: bool = False
    enable_shodan: bool = False
    max_hosts: int = 1_000
    max_api_pages: int = 1
    max_shodan_host_lookups: int = 100

    def __post_init__(self) -> None:
        if not 1 <= self.max_hosts <= 10_000:
            raise ValueError("max_hosts must be between 1 and 10000")
        if not 1 <= self.max_api_pages <= 10:
            raise ValueError("max_api_pages must be between 1 and 10")
        if not 1 <= self.max_shodan_host_lookups <= 1_000:
            raise ValueError("max_shodan_host_lookups must be between 1 and 1000")


class ReconEngine:
    """Run explicitly configured collectors without recursively expanding scope."""

    def __init__(
        self,
        *,
        crt_collector: DomainCollector,
        dns_collector: DnsCollector | None = None,
        shodan_collector: DomainCollector | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._crt = crt_collector
        self._dns = dns_collector
        self._shodan = shodan_collector
        self._clock = clock or (lambda: datetime.now(UTC))

    def scan(self, options: ScanOptions) -> ScanReport:
        domain = normalize_domain(options.domain)
        started_at = self._clock()
        assets: list[Asset] = [_new_asset(AssetType.DOMAIN, domain, started_at)]
        evidence: list[Evidence] = []
        vulnerabilities: list[VulnerabilityObservation] = []
        errors: list[CollectorError] = []
        collector_runs: list[CollectorRun] = []
        warnings: list[str] = []

        crt_result, crt_run = self._collect_domain("crt.name", self._crt, domain, errors)
        collector_runs.append(crt_run)
        _extend(crt_result, assets, evidence, vulnerabilities, warnings)
        _append_run_warnings(crt_run, warnings)

        candidate_hosts = sorted(
            {asset.value for asset in assets if asset.asset_type is AssetType.HOSTNAME} | {domain}
        )[: options.max_hosts]
        if not options.skip_dns and self._dns is not None:
            dns_started_at = self._clock()
            try:
                dns_result = self._dns.collect(candidate_hosts, domain)
            except CollectorFailure as error:
                errors.append(CollectorError(collector="dns", message=str(error)))
                collector_runs.append(
                    _failed_run("dns", dns_started_at, self._clock(), options.max_hosts)
                )
            else:
                _extend(dns_result, assets, evidence, vulnerabilities, warnings)
                collector_runs.append(
                    _successful_run("dns", dns_started_at, self._clock(), dns_result)
                )

        if options.enable_shodan:
            shodan_result, shodan_run = self._collect_domain(
                "shodan", self._shodan, domain, errors
            )
            collector_runs.append(shodan_run)
            _extend(shodan_result, assets, evidence, vulnerabilities, warnings)
            _append_run_warnings(shodan_run, warnings)
        deduplicated_assets = _deduplicate_assets(assets)
        deduplicated_evidence = _deduplicate_evidence(evidence)
        associated_vulnerabilities = _associate_vulnerability_hostnames(
            vulnerabilities, deduplicated_evidence
        )
        completed_at = self._clock()
        return ScanReport(
            metadata=ScanMetadata(started_at=started_at, completed_at=completed_at),
            input_scope=InputScope(
                domain=domain,
                skip_dns=options.skip_dns,
                enable_shodan=options.enable_shodan,
                max_hosts=options.max_hosts,
                max_api_pages=options.max_api_pages,
                max_shodan_host_lookups=options.max_shodan_host_lookups,
            ),
            assets=deduplicated_assets,
            evidence=deduplicated_evidence,
            findings=_prioritize(deduplicated_assets, deduplicated_evidence, completed_at),
            collector_runs=collector_runs,
            collector_errors=sorted(errors, key=lambda item: item.collector),
            warnings=sorted(set(warnings)),
            association_assessments=_assess_associations(
                deduplicated_assets, deduplicated_evidence, completed_at
            ),
            vulnerability_observations=_deduplicate_vulnerabilities(
                associated_vulnerabilities
            ),
        )

    def _collect_domain(
        self,
        name: str,
        collector: DomainCollector | None,
        domain: str,
        errors: list[CollectorError],
    ) -> tuple[CollectorResult, CollectorRun]:
        started_at = self._clock()
        if collector is None:
            errors.append(CollectorError(collector=name, message="collector is not configured"))
            return (
                CollectorResult(),
                _failed_run(name, started_at, self._clock(), None),
            )
        try:
            result = collector.collect(domain)
        except CollectorFailure as error:
            errors.append(CollectorError(collector=name, message=str(error)))
            return (
                CollectorResult(),
                _failed_run(name, started_at, self._clock(), None),
            )
        return result, _successful_run(name, started_at, self._clock(), result)


def _new_asset(asset_type: AssetType, value: str, now: datetime) -> Asset:
    return Asset(asset_type=asset_type, value=value, first_seen=now, last_seen=now)


def _extend(
    result: CollectorResult,
    assets: list[Asset],
    evidence: list[Evidence],
    vulnerabilities: list[VulnerabilityObservation],
    warnings: list[str],
) -> None:
    assets.extend(result.assets)
    evidence.extend(result.evidence)
    vulnerabilities.extend(result.vulnerabilities)
    warnings.extend(result.warnings)


def _successful_run(
    name: str,
    started_at: datetime,
    completed_at: datetime,
    result: CollectorResult,
) -> CollectorRun:
    return CollectorRun(
        collector=name,
        status="success",
        started_at=started_at,
        completed_at=completed_at,
        received_count=result.received_count,
        accepted_count=result.accepted_count,
        available_count=result.available_count,
        limit=result.limit,
        partial=result.partial,
        next_page_available=result.next_page_available,
    )


def _failed_run(
    name: str,
    started_at: datetime,
    completed_at: datetime,
    limit: int | None,
) -> CollectorRun:
    return CollectorRun(
        collector=name,
        status="failed",
        started_at=started_at,
        completed_at=completed_at,
        received_count=0,
        accepted_count=0,
        available_count=None,
        limit=limit,
        partial=False,
        next_page_available=False,
    )


def _append_run_warnings(run: CollectorRun, warnings: list[str]) -> None:
    if run.status != "success":
        return
    if run.received_count == 0:
        warnings.append(f"{run.collector} returned no records")
    elif run.accepted_count == 0:
        warnings.append(
            f"{run.collector} accepted no records from {run.received_count} received"
        )
    if run.partial:
        available = run.available_count if run.available_count is not None else "unknown"
        warnings.append(
            f"{run.collector} reported partial results: accepted {run.accepted_count}; "
            f"upstream available records: {available}"
        )


def _deduplicate_assets(assets: Iterable[Asset]) -> list[Asset]:
    merged: dict[tuple[AssetType, str], Asset] = {}
    for asset in assets:
        key = (asset.asset_type, asset.value)
        current = merged.get(key)
        if current is None:
            merged[key] = asset
        else:
            merged[key] = Asset(
                asset_type=asset.asset_type,
                value=asset.value,
                first_seen=min(current.first_seen, asset.first_seen),
                last_seen=max(current.last_seen, asset.last_seen),
            )
    return sorted(merged.values(), key=lambda item: (item.asset_type.value, item.value))


def _deduplicate_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    merged: dict[tuple[str, str, str, str, str], Evidence] = {}
    for item in evidence:
        key = (item.subject, item.relation, item.object, item.source, item.raw_reference)
        current = merged.get(key)
        if current is None or item.collected_at < current.collected_at:
            merged[key] = item
    return sorted(
        merged.values(),
        key=lambda item: (
            item.subject,
            item.relation,
            item.object,
            item.source,
            item.raw_reference,
        ),
    )


def _deduplicate_vulnerabilities(
    observations: Iterable[VulnerabilityObservation],
) -> list[VulnerabilityObservation]:
    merged: dict[tuple[str, str], VulnerabilityObservation] = {}
    for observation in observations:
        key = (observation.service, observation.vulnerability_id)
        current = merged.get(key)
        if current is None or _vulnerability_sort_time(observation) > (
            _vulnerability_sort_time(current)
        ) or (observation.verified is True and current.verified is not True):
            merged[key] = observation
    return sorted(
        merged.values(),
        key=lambda item: (item.service, item.vulnerability_id),
    )


def _associate_vulnerability_hostnames(
    observations: Iterable[VulnerabilityObservation], evidence: Iterable[Evidence]
) -> list[VulnerabilityObservation]:
    hostnames_by_ip: dict[str, set[str]] = {}
    for item in evidence:
        if item.relation != "resolves_to":
            continue
        try:
            ipaddress.ip_address(item.object)
        except ValueError:
            continue
        hostnames_by_ip.setdefault(item.object, set()).add(item.subject)
    return [
        observation.model_copy(
            update={
                "related_hostnames": sorted(
                    set(observation.related_hostnames)
                    | hostnames_by_ip.get(observation.ip, set())
                )
            }
        )
        for observation in observations
    ]


def _vulnerability_sort_time(observation: VulnerabilityObservation) -> datetime:
    return observation.source_observed_at or observation.collected_at


def _prioritize(
    assets: list[Asset], evidence: list[Evidence], completed_at: datetime
) -> list[Finding]:
    findings: list[Finding] = []
    for asset in assets:
        if asset.asset_type is AssetType.DOMAIN:
            continue
        related = [
            item for item in evidence if item.subject == asset.value or item.object == asset.value
        ]
        sources = {item.source for item in related}
        resolves = any(
            item.relation == "resolves_to" and item.subject == asset.value for item in related
        )
        if asset.asset_type is AssetType.SERVICE:
            source_observations = [
                item.source_observed_at
                for item in related
                if item.relation == "exposes" and item.source_observed_at is not None
            ]
            if not source_observations:
                priority = "review_required"
                reason = "The passive service observation has no provider observation time."
            elif max(source_observations) > completed_at:
                priority = "review_required"
                reason = "The provider observation time is later than the report completion time."
            elif not _is_fresh_observation(max(source_observations), completed_at):
                priority = "review_required"
                reason = (
                    "The passive service observation is older than "
                    f"{FRESH_SERVICE_OBSERVATION_DAYS} days."
                )
            else:
                priority = "high"
                reason = "A passive service index observed this service within the last 90 days."
        elif asset.asset_type is AssetType.HOSTNAME and resolves and len(sources) >= 2:
            priority = "medium"
            reason = "The hostname resolves and is corroborated by multiple passive sources."
        elif asset.asset_type is AssetType.HOSTNAME and sources == {"crt.name"}:
            priority = "low"
            reason = "The hostname appears only in certificate-transparency data and may be stale."
        else:
            priority = "review_required"
            reason = (
                "The observation is passive, but ownership or current exposure needs human review."
            )
        findings.append(
            Finding(
                asset_type=asset.asset_type,
                value=asset.value,
                priority=priority,  # type: ignore[arg-type]
                reason=reason,
            )
        )
    order = {"high": 0, "medium": 1, "low": 2, "review_required": 3}
    return sorted(
        findings,
        key=lambda item: (order[item.priority], item.asset_type.value, item.value),
    )


def _assess_associations(
    assets: list[Asset], evidence: list[Evidence], completed_at: datetime
) -> list[AssociationAssessment]:
    assessments: dict[tuple[AssetType, str], AssociationAssessment] = {}
    for asset in assets:
        if asset.asset_type in {AssetType.DOMAIN, AssetType.SERVICE}:
            continue
        related = [
            item for item in evidence if item.subject == asset.value or item.object == asset.value
        ]
        sources = sorted({item.source for item in related})
        signals: list[str] = []
        confidence: Literal["high", "medium", "low"]
        if asset.asset_type is AssetType.HOSTNAME:
            has_current_dns = any(
                item.source == "dns"
                and item.relation in {"resolves_to", "aliases_to"}
                and item.subject == asset.value
                for item in related
            )
            if has_current_dns:
                signals.append("Resolved by DNS during this scan")
            if len(sources) >= 2:
                signals.append("Corroborated by multiple source types")
            confidence = "high" if has_current_dns and len(sources) >= 2 else (
                "medium" if has_current_dns or len(sources) >= 2 else "low"
            )
        elif asset.asset_type is AssetType.IP:
            has_current_dns = any(
                item.source == "dns"
                and item.relation == "resolves_to"
                and item.object == asset.value
                for item in related
            )
            has_passive_index = any(
                item.source == "shodan"
                and item.relation == "resolves_to"
                and item.object == asset.value
                for item in related
            )
            if has_current_dns:
                signals.append("Linked from an in-scope hostname by DNS during this scan")
            if has_passive_index:
                signals.append("Corroborated by a passive internet index")
            confidence = "high" if has_current_dns and has_passive_index else (
                "medium" if has_current_dns else "low"
            )
        else:
            confidence = "low"
        if not signals:
            signals.append("Only a passive or indirect association was observed")
        assessments[(asset.asset_type, asset.value)] = AssociationAssessment(
            asset_type=asset.asset_type,
            value=asset.value,
            confidence=confidence,
            evidence_sources=sources,
            signals=signals,
        )

    for asset in assets:
        if asset.asset_type is not AssetType.SERVICE:
            continue
        exposes = [
            item
            for item in evidence
            if item.relation == "exposes" and item.object == asset.value
        ]
        sources = sorted({item.source for item in exposes})
        parent_confidences = {
            assessments[(AssetType.IP, item.subject)].confidence
            for item in exposes
            if (AssetType.IP, item.subject) in assessments
        }
        fresh = any(
            item.source_observed_at is not None
            and _is_fresh_observation(item.source_observed_at, completed_at)
            for item in exposes
        )
        signals = ["Observed by a passive service index"] if exposes else []
        if fresh:
            signals.append("Provider observation is no older than 90 days")
        if "high" in parent_confidences and fresh:
            confidence = "high"
        elif parent_confidences.intersection({"high", "medium"}) and fresh:
            confidence = "medium"
        else:
            confidence = "low"
        if not signals:
            signals.append("No direct service evidence was retained")
        assessments[(asset.asset_type, asset.value)] = AssociationAssessment(
            asset_type=asset.asset_type,
            value=asset.value,
            confidence=confidence,
            evidence_sources=sources,
            signals=signals,
        )

    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        assessments.values(),
        key=lambda item: (order[item.confidence], item.asset_type.value, item.value),
    )


def _is_fresh_observation(source_observed_at: datetime, completed_at: datetime) -> bool:
    age = completed_at - source_observed_at
    return timedelta(0) <= age <= timedelta(days=FRESH_SERVICE_OBSERVATION_DAYS)
