from datetime import UTC, datetime

from asm_agent.agent import (
    AgentAnalysis,
    AssetObservation,
    AssociationHypothesis,
    VulnerabilitySummary,
)
from asm_agent.agent_reporting import render_analysis_markdown
from asm_agent.models import AssetType, Evidence


def _analysis() -> AgentAnalysis:
    return AgentAnalysis(
        domain="example.com",
        summary=[
            "CTのみで観測されたstaleの可能性があるホスト名です。",
            "マテリアルな変更は判定できません。",
            "比較対象となる前回報告がないため、増減は記載していません。",
        ],
        observed_assets=[
            AssetObservation(
                asset_type=AssetType.HOSTNAME,
                value="www.example.com",
                observation="Shodanの受動観測があります。",
                evidence_ids=["E0001"],
                association_confidence="medium",
                uncertainty="現在も公開されているかは分かりません。",
            )
        ],
        association_hypotheses=[
            AssociationHypothesis(
                subject="www.example.com",
                hypothesis="管理対象の可能性があります。",
                confidence="low",
                evidence_ids=["E0001"],
                uncertainty="所有関係は未確認です。",
            )
        ],
        limitations=["association confidenceは所有権を証明しません。"],
    )


def test_markdown_reports_observations_without_actions_or_priorities() -> None:
    markdown = render_analysis_markdown(
        _analysis(),
        model_name="gpt-5.6-luna",
        generated_at=datetime(2026, 8, 22, 7, 19, tzinfo=UTC),
    )

    assert "# example.com 公開情報調査レポート" in markdown
    assert "## 観測された主な対象" in markdown
    assert "| `www.example.com` | ホスト名 |" in markdown
    assert "| `www.example.com` | 根拠が限られる |" in markdown
    assert "E0001" in markdown
    assert "優先順位" not in markdown
    assert "## 次の対応" not in markdown
    assert "事前承認" not in markdown
    assert "OpenAI応答保存" not in markdown
    assert "manual_review" not in markdown
    assert "association confidence" not in markdown


def test_markdown_explains_shodan_vulnerability_candidates() -> None:
    analysis = _analysis().model_copy(
        update={
            "observed_vulnerabilities": [
                VulnerabilitySummary(
                    service="192.0.2.1:443/tcp",
                    vulnerability_id="CVE-2026-1234",
                    shodan_verified=False,
                    observation="Shodanが製品情報から関連付けた候補です。",
                    evidence_ids=["E0002"],
                    uncertainty="誤検出の可能性があり、現在の状態は未確認です。",
                )
            ]
        }
    )
    evidence = Evidence(
        subject="192.0.2.1:443/tcp",
        relation="reports_vulnerability",
        object="CVE-2026-1234",
        source="shodan",
        collected_at=datetime(2026, 8, 22, 6, 0, tzinfo=UTC),
        source_observed_at=datetime(2026, 8, 21, 6, 0, tzinfo=UTC),
        confidence=0.7,
        raw_reference="match:1:vuln:CVE-2026-1234",
    )

    markdown = render_analysis_markdown(
        analysis,
        model_name="gpt-5.6-luna",
        generated_at=datetime(2026, 8, 22, 7, 19, tzinfo=UTC),
        evidence_by_id={"E0002": evidence},
    )

    assert "## Shodanが関連付けた脆弱性候補" in markdown
    assert "本ツールが対象へ脆弱性検査を行った結果ではなく" in markdown
    assert "CVE-2026-1234" in markdown
    assert "製品情報などから推定、未確認" in markdown
    assert "E0002: Shodan。192.0.2.1:443/tcpにCVE-2026-1234" in markdown


def test_markdown_replaces_unexplained_english_and_includes_glossary() -> None:
    markdown = render_analysis_markdown(
        _analysis(),
        model_name="gpt-5.6-luna",
        generated_at=datetime(2026, 8, 22, 7, 19, tzinfo=UTC),
    )

    assert "重要な変更" in markdown
    assert "古い記録の可能性" in markdown
    assert "証明書透明性ログ、略称CTログ" in markdown
    assert "## 用語の説明" in markdown
    assert "## データの取り扱い" in markdown
    assert "後からAPIで取得するための保存機能は使用していません" in markdown
    assert "OpenAIによるすべてのデータ保持が無効になる意味ではありません" in markdown


def test_markdown_explains_association_labels_and_evidence_details() -> None:
    evidence = Evidence(
        subject="www.example.com",
        relation="resolves_to",
        object="192.0.2.1",
        source="dns",
        collected_at=datetime(2026, 8, 22, 6, 0, tzinfo=UTC),
        confidence=1.0,
        raw_reference="A",
    )
    markdown = render_analysis_markdown(
        _analysis(),
        model_name="gpt-5.6-luna",
        generated_at=datetime(2026, 8, 22, 7, 19, tzinfo=UTC),
        evidence_by_id={"E0001": evidence},
    )

    assert "## 対象との結びつきの読み方" in markdown
    assert "所有権や管理責任を証明するものではありません" in markdown
    assert "E0001: DNS照会" in markdown
    assert "www.example.comが192.0.2.1に対応" in markdown
    assert "取得日時 2026-08-22 15:00 JST" in markdown
    assert "作成日時: 2026-08-22 16:19 JST" in markdown


def test_markdown_leads_with_a_compact_decision_summary() -> None:
    markdown = render_analysis_markdown(
        _analysis(),
        model_name="gpt-5.6-luna",
        generated_at=datetime(2026, 8, 22, 7, 19, tzinfo=UTC),
    )

    assert "## 調査結果" in markdown
    assert "## 観測された主な対象" in markdown
    assert "| 対象 | 種類 | 公開情報で観測された内容 |" in markdown
    assert "### 1." not in markdown
    assert len(markdown.splitlines()) < 160


def test_markdown_hides_diff_noise_without_previous_report() -> None:
    markdown = render_analysis_markdown(
        _analysis(),
        model_name="gpt-5.6-luna",
        generated_at=datetime(2026, 8, 22, 7, 19, tzinfo=UTC),
    )

    assert "差分" not in markdown
    assert "前回レポート" not in markdown
    assert "前回報告" not in markdown
    assert "比較対象" not in markdown
