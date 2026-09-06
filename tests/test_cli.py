import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from asm_agent.agent import AgentAnalysis
from asm_agent.cli import app

runner = CliRunner()


def test_cli_spec_only_exposes_supported_providers() -> None:
    scan_help = runner.invoke(app, ["scan", "--help"])
    credentials_help = runner.invoke(app, ["credentials", "--help"])
    assert scan_help.exit_code == 0
    assert credentials_help.exit_code == 0
    unsupported_provider = "".join(("cen", "sys"))
    assert unsupported_provider not in scan_help.output.lower()
    assert unsupported_provider not in credentials_help.output.lower()


def test_analyze_uses_gpt_5_6_luna_by_default() -> None:
    analyze_help = runner.invoke(app, ["analyze", "--help"])
    assert analyze_help.exit_code == 0
    assert "gpt-5.6-luna" in analyze_help.output


def test_cli_rejects_invalid_input_with_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", "--domain", "https://example.com", "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 2


def test_cli_missing_enabled_api_credential_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("asm_agent.cli.resolve_secret", lambda *_args, **_kwargs: None)
    result = runner.invoke(
        app,
        ["scan", "--domain", "example.com", "--output-dir", str(tmp_path), "--enable-shodan"],
        env={"SHODAN_API_KEY": ""},
    )
    assert result.exit_code == 2
    assert "SHODAN_API_KEY" in result.output


def test_cli_stores_shodan_key_without_echoing_it(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "asm_agent.cli.store_secret",
        lambda name, value: captured.append((name, value)),
    )
    result = runner.invoke(
        app,
        ["credentials", "set-shodan"],
        input="top-secret\ntop-secret\n",
    )
    assert result.exit_code == 0
    assert captured == [("SHODAN_API_KEY", "top-secret")]
    assert "top-secret" not in result.output


def test_cli_keyring_status_and_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("asm_agent.cli.resolve_secret", lambda *_args, **_kwargs: "stored")
    deleted: list[str] = []
    monkeypatch.setattr("asm_agent.cli.delete_secret", lambda name: deleted.append(name))
    status_result = runner.invoke(app, ["credentials", "status"])
    delete_result = runner.invoke(app, ["credentials", "delete-shodan"])
    assert status_result.exit_code == 0
    assert status_result.output.splitlines() == [
        "Shodan API key: stored",
        "OpenAI API key: stored",
    ]
    assert delete_result.exit_code == 0
    assert deleted == ["SHODAN_API_KEY"]


def test_cli_stores_and_deletes_openai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, str]] = []
    deleted: list[str] = []
    monkeypatch.setattr(
        "asm_agent.cli.store_secret",
        lambda name, value: captured.append((name, value)),
    )
    monkeypatch.setattr("asm_agent.cli.delete_secret", lambda name: deleted.append(name))
    set_result = runner.invoke(
        app,
        ["credentials", "set-openai"],
        input="openai-secret\nopenai-secret\n",
    )
    delete_result = runner.invoke(app, ["credentials", "delete-openai"])
    assert set_result.exit_code == 0
    assert "openai-secret" not in set_result.output
    assert delete_result.exit_code == 0
    assert captured == [("OPENAI_API_KEY", "openai-secret")]
    assert deleted == ["OPENAI_API_KEY"]


def test_cli_analyze_requires_openai_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("asm_agent.cli.resolve_secret", lambda *_args, **_kwargs: None)
    result = runner.invoke(
        app,
        ["analyze", "--report", str(tmp_path / "report.json")],
    )
    assert result.exit_code == 2
    assert "OPENAI_API_KEY" in result.output


@respx.mock
def test_cli_analyze_writes_structured_reports_without_exposing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    respx.get("https://crt.name/v1/search").mock(
        return_value=httpx.Response(200, json=[])
    )
    scan_result = runner.invoke(
        app,
        [
            "scan",
            "--domain",
            "example.com",
            "--output-dir",
            str(tmp_path),
            "--skip-dns",
        ],
    )
    assert scan_result.exit_code == 0
    analysis = AgentAnalysis(
        domain="example.com",
        summary=["観測対象はapexドメインだけです。"],
        observed_assets=[],
        association_hypotheses=[],
        limitations=["公開情報だけを利用しています。"],
    )
    monkeypatch.setattr(
        "asm_agent.cli.resolve_secret", lambda *_args, **_kwargs: "openai-secret"
    )
    monkeypatch.setattr("asm_agent.cli.run_analysis", lambda *_args, **_kwargs: analysis)
    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--report",
            str(tmp_path / "example.com.json"),
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert analyze_result.exit_code == 0
    json_path = tmp_path / "example.com.analysis.json"
    markdown_path = tmp_path / "example.com.analysis.md"
    assert json_path.exists()
    assert markdown_path.exists()
    payload = json.loads(json_path.read_text())
    assert payload["metadata"]["openai_response_storage"] is False
    assert payload["analysis"]["domain"] == "example.com"
    assert "observed_assets" in payload["analysis"]
    assert "prioritized_assets" not in payload["analysis"]
    assert "next_checks" not in payload["analysis"]
    assert "openai-secret" not in json_path.read_text()
    assert "openai-secret" not in markdown_path.read_text()


@respx.mock
def test_mock_end_to_end_cli_writes_reports(tmp_path: Path) -> None:
    respx.get("https://crt.name/v1/search").mock(
        return_value=httpx.Response(
            200,
            json=[{"sub": "www.example.com", "first_seen": "2026-01-01T00:00:00Z"}],
        )
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--domain",
            "example.com",
            "--output-dir",
            str(tmp_path),
            "--skip-dns",
            "--verbose",
        ],
    )
    assert result.exit_code == 0
    assert "assets=2 evidence=1" in result.output
    assert (tmp_path / "example.com.json").exists()
    assert (tmp_path / "example.com.md").exists()
    diff_result = runner.invoke(
        app,
        [
            "diff",
            "--previous",
            str(tmp_path / "example.com.json"),
            "--current",
            str(tmp_path / "example.com.json"),
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert diff_result.exit_code == 0
    assert (tmp_path / "example.com.diff.json").exists()
    assert (tmp_path / "example.com.diff.md").exists()


@respx.mock
def test_cli_collector_failure_writes_partial_report_and_exits_1(tmp_path: Path) -> None:
    route = respx.get("https://crt.name/v1/search").mock(
        return_value=httpx.Response(503, text="unavailable")
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--domain",
            "example.com",
            "--output-dir",
            str(tmp_path),
            "--skip-dns",
        ],
    )
    assert result.exit_code == 1
    assert route.call_count == 3
    assert (tmp_path / "example.com.json").exists()


@respx.mock
def test_scan_retains_history_and_prints_automatic_diff(tmp_path: Path) -> None:
    route = respx.get("https://crt.name/v1/search")
    args = ["scan", "--domain", "example.com", "--skip-dns", "--output-dir", str(tmp_path)]
    route.mock(return_value=httpx.Response(200, json=[{"sub": "old.example.com"}]))
    first = runner.invoke(app, args)
    assert first.exit_code == 0
    assert "History JSON:" in first.output
    first_payload = (tmp_path / "example.com.json").read_bytes()
    route.mock(return_value=httpx.Response(200, json=[{"sub": "new.example.com"}]))
    second = runner.invoke(app, args)
    assert second.exit_code == 0
    assert "Previous JSON:" in second.output
    assert "Diff JSON:" in second.output
    histories = list((tmp_path / "history" / "example.com").glob("*/example.com.json"))
    assert len(histories) == 2
    assert first_payload in [path.read_bytes() for path in histories]
    diffs = list((tmp_path / "history" / "example.com").rglob("*.diff.json"))
    assert len(diffs) == 1
    payload = json.loads(diffs[0].read_text())
    assert payload["added_assets"][0]["value"] == "new.example.com"


@respx.mock
def test_scan_reports_invalid_latest_file_without_overwriting_it(tmp_path: Path) -> None:
    respx.get("https://crt.name/v1/search").mock(return_value=httpx.Response(200, json=[]))
    latest = tmp_path / "example.com.json"
    latest.write_text("broken")
    result = runner.invoke(app, [
        "scan", "--domain", "example.com", "--skip-dns", "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 2
    assert "invalid latest report" in result.output
    assert latest.read_text() == "broken"


@respx.mock
def test_scan_recovers_corrupt_latest_archive_and_outputs_warning(tmp_path: Path) -> None:
    route = respx.get("https://crt.name/v1/search")
    args = ["scan", "--domain", "example.com", "--skip-dns", "--output-dir", str(tmp_path)]
    route.respond(200, json=[{"sub": "old.example.com"}])
    first = runner.invoke(app, args)
    assert first.exit_code == 0
    archive = next((tmp_path / "history" / "example.com").glob("*/example.com.json"))
    original = archive.read_bytes()
    archive.write_text("broken archive")

    route.respond(200, json=[{"sub": "new.example.com"}])
    result = runner.invoke(app, args)

    assert result.exit_code == 0
    assert "退避" in result.output
    assert "Diff JSON:" in result.output
    assert archive.read_bytes() == original
    assert json.loads((tmp_path / "example.com.json").read_text())["assets"][-1]["value"] == (
        "new.example.com"
    )
    diffs = list((tmp_path / "history" / "example.com").glob("*/*.diff.json"))
    assert len(diffs) == 1
    diff = json.loads(diffs[0].read_text())
    assert diff["comparable"] is True
    assert diff["missing_assets"][0]["value"] == "old.example.com"
