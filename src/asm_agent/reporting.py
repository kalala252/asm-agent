"""Stable JSON and readable Markdown report rendering."""

from __future__ import annotations

import json
from pathlib import Path

from asm_agent.models import ScanReport


def write_reports(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    domain = report.input_scope.domain
    json_path = output_dir / f"{domain}.json"
    markdown_path = output_dir / f"{domain}.md"
    payload = report.model_dump(mode="json")
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def render_markdown(report: ScanReport) -> str:
    lines = [
        f"# Passive Attack Surface Report: {report.input_scope.domain}",
        "",
        f"- 実行日時: {report.metadata.completed_at.isoformat()}",
        f"- 対象ドメイン: `{report.input_scope.domain}`",
        f"- 資産数: {len(report.assets)}",
        f"- 根拠数: {len(report.evidence)}",
        "",
        "## 概要",
        "",
        "許可された外部データ源とDNSから得た観測結果を正規化したレポートです。",
        "",
        "## Shodanが関連付けた脆弱性候補",
        "",
        "Shodanの観測記録であり、現在の脆弱性を確定するものではありません。"
        "未検証の候補は製品情報などから関連付けられ、誤検知を含む可能性があります。",
        "製品名、バージョン、CPEは同じサービス観測に含まれる情報であり、"
        "表示されたCVEの影響製品を確定するものではありません。",
        "",
        (
            "| 関連ホスト名 | サービス | 脆弱性ID | Shodanの確認状態 | CVSS | "
            "同じ観測の製品名 | 同じ観測のバージョン | 同じ観測のCPE | 観測日時 |"
        ),
        "|---|---|---|---|---:|---|---|---|---|",
    ]
    if report.vulnerability_observations:
        for observation in report.vulnerability_observations:
            verified = {
                True: "Shodanが観測時に確認",
                False: "製品情報などから推定、未確認",
                None: "確認状態の情報なし",
            }[observation.verified]
            cvss = observation.cvss if observation.cvss is not None else "-"
            product = _table_text(observation.product or "-")
            version = _table_text(observation.version or "-")
            cpes = _table_text("、".join(observation.cpes) or "-")
            observed_at = (
                observation.source_observed_at.isoformat()
                if observation.source_observed_at is not None
                else "観測日時なし"
            )
            hostnames = _table_text("、".join(observation.related_hostnames) or "-")
            lines.append(
                f"| {hostnames} | `{observation.service}` | "
                f"`{observation.vulnerability_id}` | "
                f"{verified} | {cvss} | {product} | {version} | {cpes} | {observed_at} |"
            )
    else:
        lines.append("| - | - | - | 該当なし | - | - | - | - | - |")
    lines.extend(
        [
            "",
        "## 優先度別の資産",
        "",
        ]
    )
    for priority in ("high", "medium", "low", "review_required"):
        lines.extend([f"### {priority}", ""])
        matching = [finding for finding in report.findings if finding.priority == priority]
        if not matching:
            lines.append("該当なし")
        else:
            for finding in matching:
                lines.append(f"- `{finding.value}` ({finding.asset_type.value}): {finding.reason}")
        lines.append("")
    lines.extend(
        [
            "## 対象との関連性の確信度",
            "",
            "この評価は複数の観測根拠による関連性を示し、法的・運用上の所有を断定しません。",
            "",
            "| 資産 | 種別 | 確信度 | 根拠データ源 | 判断材料 |",
            "|---|---|---|---|---|",
        ]
    )
    if report.association_assessments:
        for assessment in report.association_assessments:
            sources = ", ".join(assessment.evidence_sources) or "-"
            signals = "; ".join(assessment.signals)
            lines.append(
                f"| `{assessment.value}` | {assessment.asset_type.value} | "
                f"{assessment.confidence} | {sources} | {signals} |"
            )
    else:
        lines.append("| - | - | - | - | 評価対象なし |")
    lines.append("")
    lines.extend(
        [
            "## コレクター実行結果",
            "",
            (
                "| コレクター | 状態 | 受信件数 | 採用件数 | 利用可能件数 | "
                "上限 | 一部取得 | 次ページ |"
            ),
            "|---|---|---:|---:|---:|---:|---|---|",
        ]
    )
    for run in report.collector_runs:
        available_count = run.available_count if run.available_count is not None else "-"
        limit = run.limit if run.limit is not None else "-"
        lines.append(
            f"| {run.collector} | {run.status} | {run.received_count} | "
            f"{run.accepted_count} | {available_count} | {limit} | "
            f"{'yes' if run.partial else 'no'} | "
            f"{'yes' if run.next_page_available else 'no'} |"
        )
    lines.append("")
    lines.extend(["## コレクターごとのエラー", ""])
    if report.collector_errors:
        lines.extend(f"- {error.collector}: {error.message}" for error in report.collector_errors)
    else:
        lines.append("エラーなし")
    lines.extend(["", "## 警告", ""])
    if report.warnings:
        lines.extend(f"- {warning}" for warning in report.warnings)
    else:
        lines.append("警告なし")
    lines.extend(
        [
            "",
            "## 注意事項",
            "",
            "これはPassive調査の結果であり、脆弱性の存在や現在の稼働状態を証明するものではありません。",
            "CTログへの掲載だけでは、ホストが現在稼働中とは判断できません。",
            "",
        ]
    )
    return "\n".join(lines)


def _table_text(value: str) -> str:
    return " ".join(value.splitlines()).replace("|", "/")
