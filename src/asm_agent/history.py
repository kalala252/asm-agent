"""Immutable scan snapshots and automatic comparison of saved observations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from asm_agent.diffing import (
    collection_comparison_issues,
    collection_issues,
    compare_reports,
    load_report,
    write_diff_reports,
)
from asm_agent.domain import normalize_domain
from asm_agent.models import ScanReport
from asm_agent.reporting import write_reports


@dataclass(frozen=True)
class SavedScan:
    json_path: Path
    markdown_path: Path
    history_json_path: Path
    previous_path: Path | None
    diff_paths: tuple[Path, Path] | None
    warnings: list[str]


def save_scan_report(report: ScanReport, output_dir: Path) -> SavedScan:
    """Archive scans before updating the backwards-compatible latest report files."""
    domain = normalize_domain(report.input_scope.domain)
    if domain != report.input_scope.domain:
        raise ValueError("report domain must be normalized")
    history_dir = output_dir / "history" / domain
    latest_path = output_dir / f"{domain}.json"
    warnings: list[str] = []
    # Preserve reports created before history support, as well as the previous latest file.
    if latest_path.exists():
        try:
            latest = load_report(latest_path)
            if latest.input_scope.domain != domain:
                raise ValueError("domain mismatch")
        except ValueError as error:
            raise ValueError("invalid latest report; move it before saving a new scan") from error
        _archive(latest, history_dir, warnings)
    history_path = _archive(report, history_dir, warnings)
    previous_path, previous, comparison_warnings = _previous_report(report, history_dir)
    warnings.extend(comparison_warnings)
    diff_paths = None
    if previous is not None:
        # Keep each comparison next to the current snapshot, never in a shared latest file.
        diff_paths = write_diff_reports(compare_reports(previous, report), history_path.parent)
    json_path, markdown_path = write_reports(report, output_dir)
    return SavedScan(json_path, markdown_path, history_path, previous_path, diff_paths, warnings)


def _archive(report: ScanReport, history_dir: Path, warnings: list[str]) -> Path:
    payload = json.dumps(report.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    timestamp = report.metadata.completed_at.strftime("%Y%m%dT%H%M%S%fZ")
    destination = history_dir / f"{timestamp}-{digest}"
    json_path = destination / f"{report.input_scope.domain}.json"
    if destination.exists():
        if _matches_report(json_path, report):
            return json_path
        # Keep every file for diagnosis, and exclude the damaged copy from comparison.
        quarantine = history_dir / ".quarantine"
        quarantine.mkdir(exist_ok=True)
        backup = quarantine / f"{destination.name}-{uuid4().hex}"
        destination.rename(backup)
        warnings.append(
            f"破損または内容が一致しない履歴を退避し、正常なデータから再保存しました: {backup}"
        )
    history_dir.mkdir(parents=True, exist_ok=True)
    # Incomplete writes stay hidden and cannot become a comparison baseline.
    with TemporaryDirectory(prefix=".pending-", dir=history_dir) as temporary:
        staging = Path(temporary) / "snapshot"
        write_reports(report, staging)
        try:
            staging.rename(destination)
        except OSError:
            # Concurrent identical saves may publish the same content first.
            if not _matches_report(json_path, report):
                raise
    return json_path


def _matches_report(path: Path, report: ScanReport) -> bool:
    try:
        return load_report(path) == report
    except (ValueError, FileNotFoundError, IsADirectoryError):
        return False


def _previous_report(
    current: ScanReport, history_dir: Path
) -> tuple[Path | None, ScanReport | None, list[str]]:
    candidates: list[tuple[Path, ScanReport]] = []
    warnings = []
    for path in sorted(history_dir.glob(f"*/{current.input_scope.domain}.json")):
        if path.parent.name.startswith("."):
            continue
        try:
            candidate = load_report(path)
        except (OSError, ValueError):
            warnings.append(f"読み取れない履歴を比較対象から除外しました: {path}")
            continue
        if (
            candidate.input_scope.domain == current.input_scope.domain
            and candidate.metadata.completed_at < current.metadata.completed_at
        ):
            candidates.append((path, candidate))
    if not candidates:
        return None, None, warnings
    compatible = [
        item
        for item in candidates
        if item[1].input_scope == current.input_scope
        and item[1].metadata.version == current.metadata.version
        and {run.collector for run in item[1].collector_runs}
        == {run.collector for run in current.collector_runs}
        and not collection_issues(item[1])
    ]
    path, report = max(
        compatible or candidates,
        key=lambda item: (item[1].metadata.completed_at, item[0].name, str(item[0].parent)),
    )
    warnings.extend(collection_comparison_issues(report, current))
    return path, report, warnings
