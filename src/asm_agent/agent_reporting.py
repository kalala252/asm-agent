"""JSON and Markdown rendering for grounded agent analyses."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from asm_agent.agent import AgentAnalysis
from asm_agent.models import Evidence

ASSOCIATION_LABELS = {
    "high": "かなり確か",
    "medium": "ある程度確か",
    "low": "根拠が限られる",
}

ASSET_TYPE_LABELS = {
    "domain": "ドメイン名",
    "hostname": "ホスト名",
    "ip": "IPアドレス",
    "service": "公開サービス、IPアドレスとポート番号",
}

PLAIN_LANGUAGE_REPLACEMENTS = {
    "全コレクター成功・部分取得なし": (
        "すべての情報収集処理が成功し、取得上限による省略もありません"
    ),
    "サービスはShodanの受動観測で、33件のうち報告上は"
    "直近90日以内の観測です。": (
        "Shodanでは33件のサービスが観測され、いずれも本ツールの"
        "基準である直近90日以内の記録です。"
    ),
    "複数ソースの相関": "複数の情報源の一致",
    "マテリアルな": "重要な",
    "stale": "古い記録",
    "association confidence": "対象との結びつきの確からしさ",
    "Evidence": "根拠情報",
    "コレクター": "情報収集処理",
    "受動観測": "外部データベース上の観測",
    "受動データ": "外部データベースの情報",
    "判定不能です": "判断できません",
    "複数ソース": "複数の情報源",
    "相関": "情報の一致",
    "スコープ外参照": "調査対象外への参照",
    "レート": "実行頻度",
    "DNS残骸": "不要になった可能性のあるDNS記録",
    "受動的に": "対象に接続せずに",
    "観測整合性": "観測内容の一致",
    "現行性": "現在の利用状況",
    "現在性": "情報が現在も有効かどうか",
    "現行資産": "現在管理している資産",
    "現行レコード": "現在のDNS記録",
    "一次チェック": "最初の確認",
    "名前空間": "ドメイン配下",
    "稼働候補": "現在も使われている可能性がある対象",
    "低影響で": "通信量を抑えて",
    "同じドメインドメイン配下": "同じドメイン配下",
}

SOURCE_LABELS = {
    "dns": "DNS照会",
    "shodan": "Shodan",
    "crt.name": "証明書透明性ログ",
}

JST = timezone(timedelta(hours=9), name="JST")


def write_analysis_reports(
    analysis: AgentAnalysis,
    *,
    report_path: Path,
    previous_path: Path | None,
    model_name: str,
    output_dir: Path,
    evidence_by_id: Mapping[str, Evidence] | None = None,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = report_path.stem
    json_path = output_dir / f"{base_name}.analysis.json"
    markdown_path = output_dir / f"{base_name}.analysis.md"
    generated_at = datetime.now(UTC)
    reporting_analysis = _analysis_for_report(
        analysis, include_diff=previous_path is not None
    )
    payload = {
        "metadata": {
            "tool": "asm-agent",
            "version": "0.1.0",
            "generated_at": generated_at.isoformat(),
            "model": model_name,
            "report": report_path.name,
            "previous_report": previous_path.name if previous_path else None,
            "openai_response_storage": False,
        },
        "analysis": reporting_analysis.model_dump(mode="json"),
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_analysis_markdown(
            reporting_analysis,
            model_name=model_name,
            generated_at=generated_at,
            evidence_by_id=evidence_by_id,
            include_diff=previous_path is not None,
        ),
        encoding="utf-8",
    )
    return json_path, markdown_path


def render_analysis_markdown(
    analysis: AgentAnalysis,
    *,
    model_name: str,
    generated_at: datetime,
    evidence_by_id: Mapping[str, Evidence] | None = None,
    include_diff: bool = False,
) -> str:
    lines = [
        f"# {analysis.domain} 公開情報調査レポート",
        "",
        "このレポートは、DNS、証明書透明性ログ、Shodanなどの公開情報をAIが整理したものです。"
        "調査対象へのポートスキャンや脆弱性検査は行っていません。",
        "",
        "## 調査結果",
        "",
    ]
    lines.extend(
        f"- {_plain_language(item)}"
        for item in _without_unavailable_diff(analysis.summary, include_diff=include_diff)
    )
    lines.extend(
        [
            "",
            "## 観測された主な対象",
            "",
            "| 対象 | 種類 | 公開情報で観測された内容 | 対象との結びつき | 未確定事項 | 根拠 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    if analysis.observed_assets:
        for observation in analysis.observed_assets:
            lines.append(
                f"| `{observation.value}` | "
                f"{ASSET_TYPE_LABELS[observation.asset_type.value]} | "
                f"{_table_text(_plain_language(observation.observation))} | "
                f"{ASSOCIATION_LABELS[observation.association_confidence]} | "
                f"{_table_text(_plain_language(observation.uncertainty))} | "
                f"{', '.join(observation.evidence_ids)} |"
            )
    else:
        lines.append("| 該当なし | - | - | - | - | - |")

    lines.extend(
        [
            "",
            "## Shodanが関連付けた脆弱性候補",
            "",
            "これはShodanの保存データに含まれていた候補です。"
            "本ツールが対象へ脆弱性検査を行った結果ではなく、現在も脆弱であることを証明しません。",
            "",
            "| サービス | 脆弱性識別子 | Shodanでの確認状態 | "
            "公開情報で観測された内容 | 未確定事項 | 根拠 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    if analysis.observed_vulnerabilities:
        for vulnerability in analysis.observed_vulnerabilities:
            lines.append(
                f"| `{vulnerability.service}` | "
                f"`{vulnerability.vulnerability_id}` | "
                f"{_verification_label(vulnerability.shodan_verified)} | "
                f"{_table_text(_plain_language(vulnerability.observation))} | "
                f"{_table_text(_plain_language(vulnerability.uncertainty))} | "
                f"{', '.join(vulnerability.evidence_ids)} |"
            )
    else:
        lines.append("| 該当なし | - | - | - | - | - |")

    evidence_ids = list(
        dict.fromkeys(
            [
                evidence_id
                for item in analysis.observed_assets
                for evidence_id in item.evidence_ids
            ]
            + [
                evidence_id
                for item in analysis.observed_vulnerabilities
                for evidence_id in item.evidence_ids
            ]
        )
    )
    evidence_lines = _render_evidence_lines(evidence_ids, evidence_by_id)
    if evidence_lines:
        lines.extend(["", "## 根拠の内容", "", *evidence_lines])

    lines.extend(
        [
            "",
            "## 推測を含む事項",
            "",
            "この節は公開情報から考えられる可能性を示します。"
            "確認済みの事実や所有権の証明ではありません。",
            "",
            "| 対象 | 推測の確かさ | 考えられること | まだ分からないこと | 根拠 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    if analysis.association_hypotheses:
        for hypothesis in analysis.association_hypotheses:
            lines.append(
                f"| `{hypothesis.subject}` | {ASSOCIATION_LABELS[hypothesis.confidence]} | "
                f"{_table_text(_plain_language(hypothesis.hypothesis))} | "
                f"{_table_text(_plain_language(hypothesis.uncertainty))} | "
                f"{', '.join(hypothesis.evidence_ids)} |"
            )
    else:
        lines.append("| 該当なし | - | - | - | - |")

    lines.extend(
        [
            "",
            "## 対象との結びつきの読み方",
            "",
            "所有権や管理責任を証明するものではありません。",
            "",
            "| 表示 | 意味 |",
            "| --- | --- |",
            "| かなり確か | 複数の独立した情報源が一致 |",
            "| ある程度確か | 結びつきを示す情報はあるが、未確認事項も残る |",
            "| 根拠が限られる | 情報源が一つ、または間接的な記録だけ |",
            "",
            "## このレポートだけでは判断できないこと",
            "",
        ]
    )
    lines.extend(
        f"- {_plain_language(item)}"
        for item in _without_unavailable_diff(analysis.limitations, include_diff=include_diff)
    )
    lines.extend(
        [
            "",
            "## 用語の説明",
            "",
            "- DNS: ドメイン名やホスト名をIPアドレスに対応付ける仕組みです。",
            "- 証明書透明性ログ、略称CTログ: HTTPS証明書の発行履歴を"
            "公開記録する仕組みです。現在の稼働を証明するものではありません。",
            "- Shodan: インターネット上で過去に観測したIPアドレスや"
            "サービス情報を検索できる外部サービスです。",
            "- CVE: 公開された脆弱性を識別するための共通番号です。"
            "番号が表示されても、現在の対象に脆弱性があると確定した意味ではありません。",
            "- NXDOMAIN: DNSに対象名の現在の登録が見つからないという応答です。",
            "- TCPポート: サービスの通信窓口を示す番号です。"
            "ポート番号だけで実際の用途や安全性は確定できません。",
            "- HTTPとHTTPS: WebサイトやWebシステムの通信方式です。"
            "HTTPSは通信を暗号化します。",
            "- SMTP: 電子メールを送信・転送するための通信方式です。",
            "- VPN: 外部から組織内のネットワークへ安全に接続するための"
            "仕組みです。名前にVPNが含まれるだけで実際の用途は確定できません。",
            "- CNAME: あるホスト名を別のホスト名に対応付けるDNS設定です。",
            "- TTL: DNSの回答を一時保存してよい時間を示す値です。",
            "- CDN: Webサイトなどの内容を複数拠点から配信する外部基盤です。",
            "- 根拠番号: 元の調査レポートに保存された観測記録を参照する番号です。",
            "",
            "## データの取り扱い",
            "",
            "分析のため、元の調査レポートをOpenAI APIへ送信しています。"
            "送信した内容と生成結果を後からAPIで取得するための保存機能は使用していません。"
            "ただし、OpenAIによるすべてのデータ保持が無効になる意味ではありません。",
            "",
            "## 作成情報",
            "",
            f"- 作成日時: {generated_at.astimezone(JST).strftime('%Y-%m-%d %H:%M JST')}",
            "- 日時表記: 日本標準時、略称JST",
            f"- 分析に使用したAIモデル: `{model_name}`",
            "",
            "この分析は公開情報を整理したものです。"
            "現在の公開状態、脆弱性、所有関係を新たに証明するものではありません。",
            "",
        ]
    )
    return "\n".join(lines)


def _plain_language(value: str) -> str:
    for original, replacement in PLAIN_LANGUAGE_REPLACEMENTS.items():
        value = value.replace(original, replacement)
    return value.replace(" 古い記録 ", "古い記録")


def _table_text(value: str) -> str:
    return " ".join(value.splitlines()).replace("|", "/")


def _verification_label(value: bool | None) -> str:
    if value is True:
        return "Shodanが観測時に確認"
    if value is False:
        return "製品情報などから推定、未確認"
    return "確認状態の情報なし"


def _without_unavailable_diff(values: list[str], *, include_diff: bool) -> list[str]:
    if include_diff:
        return values
    unavailable_diff_markers = ("前回レポート", "前回報告", "比較対象")
    return [
        value
        for value in values
        if "差分" not in value
        and not any(marker in value for marker in unavailable_diff_markers)
    ]


def _analysis_for_report(
    analysis: AgentAnalysis, *, include_diff: bool
) -> AgentAnalysis:
    if include_diff:
        return analysis
    return analysis.model_copy(
        update={
            "summary": _without_unavailable_diff(
                analysis.summary, include_diff=False
            ),
            "limitations": _without_unavailable_diff(
                analysis.limitations, include_diff=False
            ),
        }
    )


def _render_evidence_lines(
    evidence_ids: list[str], evidence_by_id: Mapping[str, Evidence] | None
) -> list[str]:
    if evidence_by_id is None:
        return []
    return [
        f"- {evidence_id}: {_describe_evidence(evidence)}"
        for evidence_id in evidence_ids
        if (evidence := evidence_by_id.get(evidence_id)) is not None
    ]


def _describe_evidence(evidence: Evidence) -> str:
    source = SOURCE_LABELS.get(evidence.source, evidence.source)
    descriptions = {
        "exposes": f"{evidence.subject}で{evidence.object}を公開サービスとして記録",
        "resolves_to": f"{evidence.subject}が{evidence.object}に対応",
        "aliases_to": f"{evidence.subject}が{evidence.object}の別名として登録",
        "observed_in": f"{evidence.subject}を{evidence.object}に関連する名前として記録",
        "reports_vulnerability": (
            f"{evidence.subject}に{evidence.object}を脆弱性候補として記録"
        ),
    }
    description = descriptions.get(
        evidence.relation,
        f"{evidence.subject}と{evidence.object}の結びつきを記録",
    )
    timestamp = evidence.source_observed_at or evidence.collected_at
    timestamp_label = "観測日時" if evidence.source_observed_at else "取得日時"
    formatted_time = timestamp.astimezone(JST).strftime("%Y-%m-%d %H:%M JST")
    return f"{source}。{description}。{timestamp_label} {formatted_time}"
