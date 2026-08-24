"""Deterministic comparison of normalized passive scan reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from asm_agent.models import AssetType, ScanReport

Priority = Literal["high", "medium", "low", "review_required"]


class AssetDelta(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_type: AssetType
    value: str


class PriorityChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_type: AssetType
    value: str
    previous_priority: Priority
    current_priority: Priority


class ReportDiff(BaseModel):
    model_config = ConfigDict(frozen=True)

    domain: str
    previous_completed_at: datetime
    current_completed_at: datetime
    added_assets: list[AssetDelta]
    missing_assets: list[AssetDelta]
    priority_changes: list[PriorityChange]
    unchanged_asset_count: int
    warnings: list[str]


def load_report(path: Path) -> ScanReport:
    """Load and validate a scan report produced by this application."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON report: {path}") from error
    return ScanReport.model_validate(payload)


def compare_reports(previous: ScanReport, current: ScanReport) -> ReportDiff:
    """Compare reports without treating absence as proof of removal."""
    if previous.input_scope.domain != current.input_scope.domain:
        raise ValueError("reports must describe the same domain")
    previous_assets = {
        (asset.asset_type, asset.value): asset for asset in previous.assets
    }
    current_assets = {(asset.asset_type, asset.value): asset for asset in current.assets}
    previous_keys = set(previous_assets)
    current_keys = set(current_assets)

    def deltas(keys: set[tuple[AssetType, str]]) -> list[AssetDelta]:
        return [
            AssetDelta(asset_type=asset_type, value=value)
            for asset_type, value in sorted(keys, key=lambda item: (item[0].value, item[1]))
        ]

    previous_priorities = {
        (finding.asset_type, finding.value): finding.priority for finding in previous.findings
    }
    current_priorities = {
        (finding.asset_type, finding.value): finding.priority for finding in current.findings
    }
    priority_changes = [
        PriorityChange(
            asset_type=key[0],
            value=key[1],
            previous_priority=previous_priorities[key],
            current_priority=current_priorities[key],
        )
        for key in sorted(
            previous_priorities.keys() & current_priorities.keys(),
            key=lambda item: (item[0].value, item[1]),
        )
        if previous_priorities[key] != current_priorities[key]
    ]
    return ReportDiff(
        domain=current.input_scope.domain,
        previous_completed_at=previous.metadata.completed_at,
        current_completed_at=current.metadata.completed_at,
        added_assets=deltas(current_keys - previous_keys),
        missing_assets=deltas(previous_keys - current_keys),
        priority_changes=priority_changes,
        unchanged_asset_count=len(previous_keys & current_keys),
        warnings=[
            "A missing asset was not observed in the current report; "
            "removal or closure is not confirmed."
        ],
    )


def write_diff_reports(report_diff: ReportDiff, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{report_diff.domain}.diff.json"
    markdown_path = output_dir / f"{report_diff.domain}.diff.md"
    json_path.write_text(
        json.dumps(
            report_diff.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_diff_markdown(report_diff), encoding="utf-8")
    return json_path, markdown_path


def render_diff_markdown(report_diff: ReportDiff) -> str:
    lines = [
        f"# Passive Attack Surface Diff: {report_diff.domain}",
        "",
        f"- 前回: {report_diff.previous_completed_at.isoformat()}",
        f"- 今回: {report_diff.current_completed_at.isoformat()}",
        f"- 新規観測: {len(report_diff.added_assets)}",
        f"- 今回未観測: {len(report_diff.missing_assets)}",
        f"- 継続観測: {report_diff.unchanged_asset_count}",
        "",
        "## 新規に観測された資産",
        "",
    ]
    lines.extend(_render_assets(report_diff.added_assets))
    lines.extend(["", "## 今回は観測されなかった資産", ""])
    lines.extend(_render_assets(report_diff.missing_assets))
    lines.extend(["", "## 優先度の変化", ""])
    if report_diff.priority_changes:
        lines.extend(
            f"- `{item.value}` ({item.asset_type.value}): "
            f"{item.previous_priority} → {item.current_priority}"
            for item in report_diff.priority_changes
        )
    else:
        lines.append("変化なし")
    lines.extend(
        [
            "",
            "## 注意事項",
            "",
            "今回未観測の資産は、消滅や閉鎖を確認したものではありません。",
            "取得上限、データ源の更新時刻、一時的な応答差も確認してください。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_assets(assets: list[AssetDelta]) -> list[str]:
    if not assets:
        return ["該当なし"]
    return [f"- `{asset.value}` ({asset.asset_type.value})" for asset in assets]
