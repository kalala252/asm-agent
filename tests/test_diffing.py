import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from asm_agent.diffing import compare_reports, load_report, write_diff_reports
from asm_agent.models import (
    Asset,
    AssetType,
    CollectorError,
    CollectorRun,
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


@pytest.mark.parametrize(
    ("field", "value"),
    [("skip_dns", False), ("enable_shodan", True), ("max_hosts", 10),
     ("max_api_pages", 2), ("max_shodan_host_lookups", 5)],
)
def test_diff_explains_changed_collection_scope(field: str, value: object) -> None:
    previous = _report("example.com", datetime(2026, 1, 1, tzinfo=UTC), [], {})
    current = previous.model_copy(update={
        "input_scope": previous.input_scope.model_copy(update={field: value}),
    })
    diff = compare_reports(previous, current)
    assert not diff.comparable
    assert any(field in issue for issue in diff.comparison_issues)


@pytest.mark.parametrize("problem", ["failed", "partial", "next_page", "error", "missing"])
@pytest.mark.parametrize("side", ["previous", "current"])
def test_diff_explains_incomplete_collection(problem: str, side: str, tmp_path: Path) -> None:
    previous = _report("example.com", datetime(2026, 1, 1, tzinfo=UTC), [], {})
    current = _report("example.com", datetime(2026, 1, 2, tzinfo=UTC), [], {})
    run = CollectorRun(
        collector="crt.name", status="success", started_at=previous.metadata.started_at,
        completed_at=previous.metadata.completed_at, received_count=10, accepted_count=10,
        partial=False, next_page_available=False,
    )
    previous = previous.model_copy(update={"collector_runs": [run]})
    current = current.model_copy(update={"collector_runs": [run]})
    changes: dict[str, object] = {}
    if problem == "error":
        changes["collector_errors"] = [CollectorError(collector="crt.name", message="failed")]
    elif problem == "missing":
        changes["collector_runs"] = []
    else:
        run_changes: dict[str, object] = {
            "failed": {"status": "failed"}, "partial": {"partial": True},
            "next_page": {"next_page_available": True},
        }[problem]
        changes["collector_runs"] = [run.model_copy(update=run_changes)]
    if side == "previous":
        previous = previous.model_copy(update=changes)
    else:
        current = current.model_copy(update=changes)
    diff = compare_reports(previous, current)
    assert not diff.comparable
    assert any("crt.name" in issue for issue in diff.comparison_issues)
    _, markdown = write_diff_reports(diff, tmp_path)
    assert "収集条件・取得状況に注意" in markdown.read_text()
    assert all(issue in markdown.read_text() for issue in diff.comparison_issues)


def test_diff_rejects_reversed_chronology() -> None:
    previous = _report("example.com", datetime(2026, 1, 2, tzinfo=UTC), [], {})
    current = _report("example.com", datetime(2026, 1, 1, tzinfo=UTC), [], {})
    with pytest.raises(ValueError, match="earlier"):
        compare_reports(previous, current)
