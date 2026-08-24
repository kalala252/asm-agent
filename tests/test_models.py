from datetime import datetime

import pytest
from pydantic import ValidationError

from asm_agent.models import (
    Asset,
    AssetType,
    CollectorRun,
    Evidence,
    VulnerabilityObservation,
)


def test_asset_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Asset(
            asset_type=AssetType.DOMAIN,
            value="example.com",
            first_seen=datetime(2026, 1, 1),
            last_seen=datetime(2026, 1, 1),
        )


def test_evidence_and_collector_run_reject_naive_timestamps() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Evidence(
            subject="example.com",
            relation="observed_in",
            object="example.com",
            source="test",
            collected_at=datetime(2026, 1, 1),
            source_observed_at=None,
            confidence=1.0,
            raw_reference="record:1",
        )
    with pytest.raises(ValidationError, match="timezone-aware"):
        CollectorRun(
            collector="test",
            status="success",
            started_at=datetime(2026, 1, 1),
            completed_at=datetime(2026, 1, 1),
            received_count=0,
            accepted_count=0,
            partial=False,
            next_page_available=False,
        )


def test_vulnerability_observation_rejects_invalid_cvss_and_naive_time() -> None:
    with pytest.raises(ValidationError):
        VulnerabilityObservation(
            service="192.0.2.1:443/tcp",
            ip="192.0.2.1",
            port=443,
            transport="tcp",
            vulnerability_id="CVE-2026-1234",
            cvss=11,
            collected_at=datetime(2026, 1, 1),
            raw_reference="match:0:vuln:CVE-2026-1234",
        )
