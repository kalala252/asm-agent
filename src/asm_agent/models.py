"""Normalized data models for passive observations."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetType(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    SERVICE = "service"
    CERTIFICATE = "certificate"


def _timezone_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


class Asset(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_type: AssetType
    value: str
    first_seen: datetime
    last_seen: datetime

    _validate_first_seen = field_validator("first_seen")(_timezone_aware)
    _validate_last_seen = field_validator("last_seen")(_timezone_aware)


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    relation: str
    object: str
    source: str
    collected_at: datetime
    source_observed_at: datetime | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    raw_reference: str
    inferred: bool = False

    _validate_collected_at = field_validator("collected_at")(_timezone_aware)
    _validate_source_observed_at = field_validator("source_observed_at")(
        lambda value: _timezone_aware(value) if value is not None else None
    )


class VulnerabilityObservation(BaseModel):
    """A Shodan vulnerability association retained with its observation context."""

    model_config = ConfigDict(frozen=True)

    service: str
    ip: str
    port: int = Field(ge=1, le=65_535)
    transport: Literal["tcp", "udp", "unknown"]
    vulnerability_id: str = Field(min_length=1, max_length=100)
    verified: bool | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v2: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_version: str | None = Field(default=None, max_length=20)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    ranking_epss: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool | None = None
    summary: str | None = Field(default=None, max_length=2_000)
    references: list[str] = Field(default_factory=list, max_length=20)
    product: str | None = Field(default=None, max_length=200)
    version: str | None = Field(default=None, max_length=200)
    cpes: list[str] = Field(default_factory=list, max_length=20)
    related_hostnames: list[str] = Field(default_factory=list, max_length=1_000)
    source: Literal["shodan"] = "shodan"
    collected_at: datetime
    source_observed_at: datetime | None = None
    raw_reference: str

    _validate_collected_at = field_validator("collected_at")(_timezone_aware)
    _validate_source_observed_at = field_validator("source_observed_at")(
        lambda value: _timezone_aware(value) if value is not None else None
    )


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_type: AssetType
    value: str
    priority: Literal["high", "medium", "low", "review_required"]
    reason: str


class AssociationAssessment(BaseModel):
    """Evidence-based association strength, not an ownership assertion."""

    model_config = ConfigDict(frozen=True)

    asset_type: AssetType
    value: str
    confidence: Literal["high", "medium", "low"]
    evidence_sources: list[str]
    signals: list[str]
    caveat: str = "Association confidence is not proof of legal or operational ownership."


class CollectorError(BaseModel):
    model_config = ConfigDict(frozen=True)

    collector: str
    message: str


class CollectorRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    collector: str
    status: Literal["success", "failed"]
    started_at: datetime
    completed_at: datetime
    received_count: int = Field(ge=0)
    accepted_count: int = Field(ge=0)
    available_count: int | None = Field(default=None, ge=0)
    limit: int | None = Field(default=None, gt=0)
    partial: bool
    next_page_available: bool

    _validate_started_at = field_validator("started_at")(_timezone_aware)
    _validate_completed_at = field_validator("completed_at")(_timezone_aware)


class ScanMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool: str = "asm-agent"
    version: str = "0.1.0"
    started_at: datetime
    completed_at: datetime

    _validate_started_at = field_validator("started_at")(_timezone_aware)
    _validate_completed_at = field_validator("completed_at")(_timezone_aware)


class InputScope(BaseModel):
    model_config = ConfigDict(frozen=True)

    domain: str
    skip_dns: bool
    enable_shodan: bool
    max_hosts: int = Field(gt=0, le=10_000)
    max_api_pages: int = Field(default=1, gt=0, le=10)
    max_shodan_host_lookups: int = Field(default=100, gt=0, le=1_000)


class ScanReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    metadata: ScanMetadata
    input_scope: InputScope
    assets: list[Asset]
    evidence: list[Evidence]
    findings: list[Finding]
    collector_runs: list[CollectorRun]
    collector_errors: list[CollectorError]
    warnings: list[str]
    association_assessments: list[AssociationAssessment] = Field(default_factory=list)
    vulnerability_observations: list[VulnerabilityObservation] = Field(
        default_factory=list
    )
