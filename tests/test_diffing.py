import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from asm_agent.diffing import compare_reports, load_report, write_diff_reports
from asm_agent.models import (
    Asset,
    AssetType,
    Finding,
    InputScope,
    ScanMetadata,
    ScanReport,
)


def _report(
    domain: str,
    completed_at: datetime,
    assets: list[tuple[AssetType, str]],
    priorities: dict[str, str],
) -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(started_at=completed_at, completed_at=completed_at),
        input_scope=InputScope(
            domain=domain,
            skip_dns=True,
            enable_shodan=False,
            max_hosts=1_000,
        ),
        assets=[
            Asset(
                asset_type=asset_type,
                value=value,
                first_seen=completed_at,
                last_seen=completed_at,
            )
            for asset_type, value in assets
        ],
        evidence=[],
        findings=[
            Finding(
                asset_type=asset_type,
                value=value,
                priority=priorities[value],  # type: ignore[arg-type]
                reason="test",
            )
            for asset_type, value in assets
            if value in priorities
        ],
        collector_runs=[],
        collector_errors=[],
        warnings=[],
    )


def test_diff_reports_added_missing_and_priority_changes(tmp_path: Path) -> None:
    previous = _report(
        "example.com",
        datetime(2026, 1, 1, tzinfo=UTC),
        [
            (AssetType.DOMAIN, "example.com"),
            (AssetType.HOSTNAME, "old.example.com"),
            (AssetType.IP, "192.0.2.1"),
        ],
        {"192.0.2.1": "review_required"},
    )
    current = _report(
        "example.com",
        datetime(2026, 1, 2, tzinfo=UTC),
        [
            (AssetType.DOMAIN, "example.com"),
            (AssetType.HOSTNAME, "new.example.com"),
            (AssetType.IP, "192.0.2.1"),
        ],
        {"192.0.2.1": "high"},
    )
    diff = compare_reports(previous, current)
    assert [(item.asset_type, item.value) for item in diff.added_assets] == [
        (AssetType.HOSTNAME, "new.example.com")
    ]
    assert [(item.asset_type, item.value) for item in diff.missing_assets] == [
        (AssetType.HOSTNAME, "old.example.com")
    ]
    assert diff.unchanged_asset_count == 2
    assert diff.priority_changes[0].previous_priority == "review_required"
    assert diff.priority_changes[0].current_priority == "high"
    assert any("not confirmed" in warning for warning in diff.warnings)

    json_path, markdown_path = write_diff_reports(diff, tmp_path)
    assert json.loads(json_path.read_text())["domain"] == "example.com"
    assert "消滅や閉鎖を確認したものではありません" in markdown_path.read_text()


def test_diff_rejects_different_domains() -> None:
    first = _report("example.com", datetime(2026, 1, 1, tzinfo=UTC), [], {})
    second = _report("other.test", datetime(2026, 1, 2, tzinfo=UTC), [], {})
    with pytest.raises(ValueError, match="same domain"):
        compare_reports(first, second)


def test_load_report_accepts_existing_json_without_new_optional_fields(tmp_path: Path) -> None:
    report = _report("example.com", datetime(2026, 1, 1, tzinfo=UTC), [], {})
    payload = report.model_dump(mode="json")
    payload.pop("association_assessments", None)
    payload["input_scope"].pop("max_api_pages", None)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = load_report(path)
    assert loaded.input_scope.max_api_pages == 1
    assert loaded.association_assessments == []
