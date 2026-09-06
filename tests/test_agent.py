from datetime import UTC, datetime

import pytest
from pydantic_ai import models
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from asm_agent.agent import (
    AgentAnalysis,
    AnalysisDependencies,
    AssetObservation,
    AssociationHypothesis,
    VulnerabilitySummary,
    run_analysis,
    validate_analysis,
)
from asm_agent.models import (
    Asset,
    AssetType,
    AssociationAssessment,
    Evidence,
    Finding,
    InputScope,
    ScanMetadata,
    ScanReport,
    VulnerabilityObservation,
)

NOW = datetime(2026, 8, 22, tzinfo=UTC)
models.ALLOW_MODEL_REQUESTS = False


def _report() -> ScanReport:
    hostname = "www.example.com"
    return ScanReport(
        metadata=ScanMetadata(started_at=NOW, completed_at=NOW),
        input_scope=InputScope(
            domain="example.com",
            skip_dns=False,
            enable_shodan=True,
            max_hosts=1_000,
        ),
        assets=[
            Asset(
                asset_type=AssetType.DOMAIN,
                value="example.com",
                first_seen=NOW,
                last_seen=NOW,
            ),
            Asset(
                asset_type=AssetType.HOSTNAME,
                value=hostname,
                first_seen=NOW,
                last_seen=NOW,
            ),
        ],
        evidence=[
            Evidence(
                subject=hostname,
                relation="observed_in",
                object="example.com",
                source="crt.name",
                collected_at=NOW,
                source_observed_at=NOW,
                confidence=1.0,
                raw_reference="line:1",
            )
        ],
        findings=[
            Finding(
                asset_type=AssetType.HOSTNAME,
                value=hostname,
                priority="low",
                reason="Certificate transparency observation only.",
            )
        ],
        collector_runs=[],
        collector_errors=[],
        warnings=[],
        association_assessments=[
            AssociationAssessment(
                asset_type=AssetType.HOSTNAME,
                value=hostname,
                confidence="low",
                evidence_sources=["crt.name"],
                signals=["Only a passive association was observed"],
            )
        ],
    )


def _analysis() -> AgentAnalysis:
    return AgentAnalysis(
        domain="example.com",
        summary=["証明書透明性ログだけで観測されたホスト名があります。"],
        observed_assets=[
            AssetObservation(
                asset_type=AssetType.HOSTNAME,
                value="www.example.com",
                observation="証明書透明性ログに記録されています。",
                evidence_ids=["E0001"],
                association_confidence="low",
                uncertainty="現在のDNS応答と利用状況は分かりません。",
            )
        ],
        association_hypotheses=[],
        limitations=["受動観測だけでは現在の稼働状態を証明できません。"],
    )


def test_analysis_schema_contains_observations_not_actions_or_priorities() -> None:
    schema = AgentAnalysis.model_json_schema()
    properties = schema["properties"]
    assert "observed_assets" in properties
    assert "prioritized_assets" not in properties
    assert "next_checks" not in properties


def test_analysis_is_grounded_in_report_assets_and_evidence() -> None:
    dependencies = AnalysisDependencies.from_reports(_report())
    assert validate_analysis(dependencies, _analysis()).domain == "example.com"

    invalid = _analysis().model_copy(deep=True)
    invalid.observed_assets[0] = invalid.observed_assets[0].model_copy(
        update={"value": "outside.example.net", "evidence_ids": ["E9999"]}
    )
    with pytest.raises(ValueError, match="unknown asset"):
        validate_analysis(dependencies, invalid)


@pytest.mark.parametrize("kind", ["asset", "hypothesis"])
@pytest.mark.parametrize("include_matching", [False, True])
def test_analysis_rejects_unrelated_existing_evidence(kind: str, include_matching: bool) -> None:
    report = _report()
    report = report.model_copy(update={"evidence": [
        *report.evidence,
        report.evidence[0].model_copy(update={"subject": "other.example.com"}),
    ]})
    ids = ["E0001", "E0002"] if include_matching else ["E0002"]
    analysis = _analysis().model_copy(deep=True)
    if kind == "asset":
        analysis.observed_assets[0] = analysis.observed_assets[0].model_copy(
            update={"evidence_ids": ids}
        )
    else:
        analysis.association_hypotheses.append(AssociationHypothesis(
            subject="www.example.com", hypothesis="対象と関係する可能性があります。",
            confidence="low", evidence_ids=ids, uncertainty="管理者は未確認です。",
        ))
    with pytest.raises(ValueError, match="evidence does not match"):
        validate_analysis(AnalysisDependencies.from_reports(report), analysis)


def test_analysis_accepts_asset_on_object_side_of_evidence() -> None:
    analysis = _analysis().model_copy(deep=True)
    analysis.observed_assets[0] = analysis.observed_assets[0].model_copy(
        update={"asset_type": AssetType.DOMAIN, "value": "example.com"}
    )
    assert validate_analysis(AnalysisDependencies.from_reports(_report()), analysis) == analysis


def test_vulnerability_summary_must_match_retained_shodan_observation() -> None:
    report = _report().model_copy(
        update={
            "evidence": [
                *_report().evidence,
                Evidence(
                    subject="192.0.2.1:443/tcp",
                    relation="reports_vulnerability",
                    object="CVE-2026-1234",
                    source="shodan",
                    collected_at=NOW,
                    source_observed_at=NOW,
                    confidence=0.7,
                    raw_reference="match:1:vuln:CVE-2026-1234",
                ),
            ],
            "vulnerability_observations": [
                VulnerabilityObservation(
                    service="192.0.2.1:443/tcp",
                    ip="192.0.2.1",
                    port=443,
                    transport="tcp",
                    vulnerability_id="CVE-2026-1234",
                    verified=False,
                    product="Example Server",
                    version="1.0",
                    collected_at=NOW,
                    source_observed_at=NOW,
                    raw_reference="match:1:vuln:CVE-2026-1234",
                )
            ],
        }
    )
    analysis = _analysis().model_copy(
        update={
            "observed_vulnerabilities": [
                VulnerabilitySummary(
                    service="192.0.2.1:443/tcp",
                    vulnerability_id="CVE-2026-1234",
                    shodan_verified=False,
                    observation="Shodanが製品情報から関連付けた候補です。",
                    evidence_ids=["E0002"],
                    uncertainty="現在の脆弱性は確認していません。",
                )
            ]
        }
    )
    dependencies = AnalysisDependencies.from_reports(report)

    assert validate_analysis(dependencies, analysis) == analysis

    invalid = analysis.model_copy(deep=True)
    invalid.observed_vulnerabilities[0] = (
        invalid.observed_vulnerabilities[0].model_copy(
            update={"vulnerability_id": "CVE-2026-9999"}
        )
    )
    with pytest.raises(ValueError, match="unknown vulnerability observation"):
        validate_analysis(dependencies, invalid)

    wrong_verification = analysis.model_copy(deep=True)
    wrong_verification.observed_vulnerabilities[0] = (
        wrong_verification.observed_vulnerabilities[0].model_copy(
            update={"shodan_verified": True}
        )
    )
    with pytest.raises(ValueError, match="shodan_verified does not match"):
        validate_analysis(dependencies, wrong_verification)

    wrong_evidence = analysis.model_copy(deep=True)
    wrong_evidence.observed_vulnerabilities[0] = (
        wrong_evidence.observed_vulnerabilities[0].model_copy(
            update={"evidence_ids": ["E0001"]}
        )
    )
    with pytest.raises(ValueError, match="vulnerability evidence does not match"):
        validate_analysis(dependencies, wrong_evidence)


def test_agent_runs_with_test_model_without_external_requests() -> None:
    dependencies = AnalysisDependencies.from_reports(_report())
    expected = _analysis()
    result = run_analysis(
        dependencies,
        model=TestModel(custom_output_args=expected.model_dump(mode="json")),
    )
    assert result == expected


def test_agent_allows_four_sequential_tool_calls_before_final_output() -> None:
    expected = _analysis()
    calls = [
        ("get_report_overview", {}),
        ("get_report_diff", {}),
        ("get_asset_evidence", {"asset_values": ["www.example.com"]}),
        ("get_asset_evidence", {"asset_values": ["example.com"]}),
    ]
    request_count = 0

    def model_function(
        _messages: list[ModelMessage], agent_info: AgentInfo
    ) -> ModelResponse:
        nonlocal request_count
        if request_count < len(calls):
            tool_name, args = calls[request_count]
        else:
            tool_name = agent_info.output_tools[0].name
            args = expected.model_dump(mode="json")
        request_count += 1
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=tool_name,
                    args=args,
                    tool_call_id=f"call-{request_count}",
                )
            ]
        )

    result = run_analysis(
        AnalysisDependencies.from_reports(_report()),
        model=FunctionModel(model_function),
    )
    assert result == expected
    assert request_count == 5


def test_agent_tools_have_no_path_or_shell_parameters() -> None:
    dependencies = AnalysisDependencies.from_reports(_report())
    test_model = TestModel(custom_output_args=_analysis().model_dump(mode="json"))
    run_analysis(dependencies, model=test_model)
    tools = test_model.last_model_request_parameters.function_tools
    assert {tool.name for tool in tools} == {
        "get_asset_evidence",
        "get_report_diff",
        "get_report_overview",
    }
    assert all("path" not in tool.parameters_json_schema.get("properties", {}) for tool in tools)
    assert all("command" not in tool.parameters_json_schema.get("properties", {}) for tool in tools)
