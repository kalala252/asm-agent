import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from asm_agent.history import save_scan_report
from asm_agent.models import Asset, AssetType, CollectorRun, InputScope, ScanMetadata, ScanReport
from asm_agent.reporting import write_reports


def _report(day: int, hostname: str = "www.example.com", *, partial: bool = False) -> ScanReport:
    now = datetime(2026, 1, day, tzinfo=UTC)
    return ScanReport(
        metadata=ScanMetadata(started_at=now, completed_at=now),
        input_scope=InputScope(
            domain="example.com", skip_dns=True, enable_shodan=False, max_hosts=1000
        ),
        assets=[
            Asset(asset_type=AssetType.HOSTNAME, value=hostname, first_seen=now, last_seen=now)
        ],
        evidence=[],
        findings=[],
        collector_errors=[],
        warnings=[],
        collector_runs=[
            CollectorRun(
                collector="crt.name",
                status="success",
                started_at=now,
                completed_at=now,
                received_count=1,
                accepted_count=1,
                partial=partial,
                next_page_available=False,
            )
        ],
    )


def test_history_preserves_runs_and_writes_automatic_diff(tmp_path: Path) -> None:
    first = save_scan_report(_report(1), tmp_path)
    original = first.history_json_path.read_bytes()
    second = save_scan_report(_report(2, "new.example.com"), tmp_path)
    assert first.diff_paths is None
    assert first.history_json_path.read_bytes() == original
    assert second.previous_path == first.history_json_path
    assert second.diff_paths is not None
    diff = json.loads(second.diff_paths[0].read_text())
    assert diff["comparable"] is True
    assert diff["added_assets"][0]["value"] == "new.example.com"
    assert diff["missing_assets"][0]["value"] == "www.example.com"
    assert second.json_path == tmp_path / "example.com.json"
    assert second.json_path.read_bytes() == second.history_json_path.read_bytes()
    assert first.history_json_path.with_suffix(".md").exists()


def test_history_preserves_legacy_report_before_replacing_latest(tmp_path: Path) -> None:
    legacy, _ = write_reports(_report(1), tmp_path)
    original = legacy.read_bytes()
    saved = save_scan_report(_report(2), tmp_path)
    assert saved.previous_path is not None
    assert saved.previous_path != legacy
    assert saved.previous_path.read_bytes() == original


def test_history_does_not_overwrite_different_runs_with_the_same_time(tmp_path: Path) -> None:
    first = save_scan_report(_report(1), tmp_path)
    original = first.history_json_path.read_bytes()
    second = save_scan_report(_report(1, "other.example.com"), tmp_path)
    assert first.history_json_path != second.history_json_path
    assert first.history_json_path.read_bytes() == original
    assert second.previous_path is None
    repeated = save_scan_report(_report(1, "other.example.com"), tmp_path)
    assert repeated.history_json_path == second.history_json_path


@pytest.mark.parametrize("reason", ["partial", "scope"])
def test_history_prefers_complete_matching_baseline(reason: str, tmp_path: Path) -> None:
    first = save_scan_report(_report(1), tmp_path)
    unsuitable = _report(2, partial=reason == "partial")
    if reason == "scope":
        unsuitable = unsuitable.model_copy(
            update={
                "input_scope": unsuitable.input_scope.model_copy(update={"max_hosts": 10}),
            }
        )
    save_scan_report(unsuitable, tmp_path)
    saved = save_scan_report(_report(3), tmp_path)
    assert saved.previous_path == first.history_json_path


def test_history_falls_back_to_latest_with_comparison_warning(tmp_path: Path) -> None:
    first = save_scan_report(_report(1, partial=True), tmp_path)
    saved = save_scan_report(_report(2), tmp_path)
    assert saved.previous_path == first.history_json_path
    assert saved.diff_paths is not None
    assert json.loads(saved.diff_paths[0].read_text())["comparable"] is False


def test_history_ignores_corrupt_archives_with_warning(tmp_path: Path) -> None:
    first = save_scan_report(_report(1), tmp_path)
    corrupt = first.history_json_path.parent.parent / "corrupt"
    corrupt.mkdir()
    (corrupt / "example.com.json").write_text("not json")
    saved = save_scan_report(_report(2), tmp_path)
    assert saved.previous_path == first.history_json_path
    assert saved.warnings


@pytest.mark.parametrize("damage", ["json", "schema", "encoding", "mismatch", "missing"])
def test_history_recovers_latest_archive_without_losing_damaged_files(
    tmp_path: Path, damage: str,
) -> None:
    original_report = _report(1)
    first = save_scan_report(original_report, tmp_path)
    original_json = first.history_json_path.read_bytes()
    original_markdown = first.history_json_path.with_suffix(".md").read_bytes()
    damaged = {
        "json": b"broken JSON",
        "schema": b"{}",
        "encoding": b"\xff\xfe",
        "mismatch": _report(1, "other.example.com").model_dump_json().encode(),
        "missing": b"",
    }[damage]
    if damage == "missing":
        first.history_json_path.unlink()
    else:
        first.history_json_path.write_bytes(damaged)
    sidecar = first.history_json_path.parent / "notes.txt"
    sidecar.write_text("preserve this file too")

    saved = save_scan_report(_report(2, "new.example.com"), tmp_path)

    assert saved.previous_path == first.history_json_path
    assert first.history_json_path.read_bytes() == original_json
    assert first.history_json_path.with_suffix(".md").read_bytes() == original_markdown
    assert saved.diff_paths is not None
    diff = json.loads(saved.diff_paths[0].read_text())
    assert diff["comparable"] is True
    assert [item["value"] for item in diff["missing_assets"]] == ["www.example.com"]
    assert [item["value"] for item in diff["added_assets"]] == ["new.example.com"]
    assert any("退避" in warning for warning in saved.warnings)

    quarantined = list((first.history_json_path.parent.parent / ".quarantine").iterdir())
    assert len(quarantined) == 1
    backup_json = quarantined[0] / "example.com.json"
    if damage == "missing":
        assert not backup_json.exists()
    else:
        assert backup_json.read_bytes() == damaged
    assert (quarantined[0] / "example.com.md").read_bytes() == original_markdown
    assert (quarantined[0] / "notes.txt").read_text() == "preserve this file too"

    repeated = save_scan_report(original_report, tmp_path)
    assert repeated.history_json_path == first.history_json_path
    assert repeated.warnings == []
    assert len(list(quarantined[0].parent.iterdir())) == 1


def test_failed_quarantine_preserves_latest_and_damaged_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = save_scan_report(_report(1), tmp_path)
    latest = first.json_path.read_bytes()
    first.history_json_path.write_bytes(b"broken JSON")
    rename = Path.rename

    def fail_quarantine(source: Path, target: Path) -> Path:
        if source == first.history_json_path.parent:
            raise PermissionError("simulated quarantine failure")
        return rename(source, target)

    monkeypatch.setattr(Path, "rename", fail_quarantine)
    with pytest.raises(PermissionError, match="quarantine failure"):
        save_scan_report(_report(2), tmp_path)
    assert first.json_path.read_bytes() == latest
    assert first.history_json_path.read_bytes() == b"broken JSON"


def test_failed_recovery_write_keeps_backup_and_can_be_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = save_scan_report(_report(1), tmp_path)
    latest = first.json_path.read_bytes()
    first.history_json_path.write_bytes(b"broken JSON")

    def fail_write(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
        raise OSError("simulated recovery write failure")

    with monkeypatch.context() as context:
        context.setattr("asm_agent.history.write_reports", fail_write)
        with pytest.raises(OSError, match="recovery write failure"):
            save_scan_report(_report(2), tmp_path)
    assert first.json_path.read_bytes() == latest
    quarantine = first.history_json_path.parent.parent / ".quarantine"
    backups = list(quarantine.glob("*/example.com.json"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == b"broken JSON"

    saved = save_scan_report(_report(2), tmp_path)
    assert saved.previous_path == first.history_json_path
    assert first.history_json_path.read_bytes() == latest
    assert backups[0].read_bytes() == b"broken JSON"
    assert len(list(quarantine.iterdir())) == 1


def test_history_does_not_overwrite_invalid_legacy_report(tmp_path: Path) -> None:
    latest = tmp_path / "example.com.json"
    latest.write_text("not json")
    with pytest.raises(ValueError, match="latest report"):
        save_scan_report(_report(2), tmp_path)
    assert latest.read_text() == "not json"


def test_history_rejects_path_like_domain(tmp_path: Path) -> None:
    report = _report(1)
    report = report.model_copy(
        update={
            "input_scope": report.input_scope.model_copy(update={"domain": "../outside"}),
        }
    )
    with pytest.raises(ValueError):
        save_scan_report(report, tmp_path)
    assert not list(tmp_path.iterdir())


def test_failed_archive_does_not_publish_a_baseline_or_replace_latest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = save_scan_report(_report(1), tmp_path)
    original = first.json_path.read_bytes()
    real_writer = write_reports

    def fail_after_writing(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
        real_writer(report, output_dir)
        raise OSError("simulated disk failure")

    monkeypatch.setattr("asm_agent.history.write_reports", fail_after_writing)
    with pytest.raises(OSError, match="disk failure"):
        save_scan_report(_report(2), tmp_path)
    assert first.json_path.read_bytes() == original
    assert list(first.history_json_path.parent.parent.glob("*/example.com.json")) == [
        first.history_json_path,
    ]


def test_history_does_not_compare_to_future_or_another_domain(tmp_path: Path) -> None:
    future = save_scan_report(_report(3), tmp_path)
    foreign = future.history_json_path.parent.parent / "foreign"
    foreign.mkdir()
    payload = _report(1).model_dump(mode="json")
    payload["input_scope"]["domain"] = "other.test"
    (foreign / "example.com.json").write_text(json.dumps(payload))
    saved = save_scan_report(_report(2), tmp_path)
    assert saved.previous_path is None


def test_partial_current_report_still_uses_last_complete_baseline(tmp_path: Path) -> None:
    first = save_scan_report(_report(1), tmp_path)
    save_scan_report(_report(2, partial=True), tmp_path)
    saved = save_scan_report(_report(3, partial=True), tmp_path)
    assert saved.previous_path == first.history_json_path
    assert saved.diff_paths is not None
    assert not json.loads(saved.diff_paths[0].read_text())["comparable"]


def test_failed_latest_replacement_preserves_previous_file_and_new_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = save_scan_report(_report(1), tmp_path)
    original = first.json_path.read_bytes()
    replace = Path.replace

    def fail_latest(source: Path, target: Path) -> Path:
        if target == first.json_path:
            raise OSError("simulated replacement failure")
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_latest)
    with pytest.raises(OSError, match="replacement failure"):
        save_scan_report(_report(2), tmp_path)
    assert first.json_path.read_bytes() == original
    assert len(list(first.history_json_path.parent.parent.glob("*/example.com.json"))) == 2
    assert not list(tmp_path.glob(".report-*"))
