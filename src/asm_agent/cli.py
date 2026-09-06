"""Command-line interface for the passive recon engine."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic_ai.exceptions import AgentRunError, UsageLimitExceeded
from pydantic_ai.models.openai import OpenAIResponsesModel
from pydantic_ai.providers.openai import OpenAIProvider

from asm_agent.agent import AnalysisDependencies, run_analysis
from asm_agent.agent_reporting import write_analysis_reports
from asm_agent.collectors import CrtNameCollector, DnsCollector, ShodanCollector
from asm_agent.credentials import CredentialError, delete_secret, resolve_secret, store_secret
from asm_agent.diffing import compare_reports, load_report, write_diff_reports
from asm_agent.domain import DomainValidationError, normalize_domain
from asm_agent.engine import ReconEngine, ScanOptions
from asm_agent.history import save_scan_report

app = typer.Typer(no_args_is_help=True, help="Passive Attack Surface調査CLI")
credentials_app = typer.Typer(no_args_is_help=True, help="API認証情報を安全に管理")
app.add_typer(credentials_app, name="credentials")


@app.callback()
def main() -> None:
    """Collect passive observations without probing target hosts."""


@credentials_app.command("set-shodan")
def set_shodan_credential() -> None:
    """Store the Shodan API key in the operating system keyring."""
    api_key = typer.prompt("Shodan API key", hide_input=True, confirmation_prompt=True)
    try:
        store_secret("SHODAN_API_KEY", api_key)
    except CredentialError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    typer.echo("Shodan API key stored in the operating system keyring.")


@credentials_app.command("set-openai")
def set_openai_credential() -> None:
    """Store the OpenAI API key in the operating system keyring."""
    api_key = typer.prompt("OpenAI API key", hide_input=True, confirmation_prompt=True)
    try:
        store_secret("OPENAI_API_KEY", api_key)
    except CredentialError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    typer.echo("OpenAI API key stored in the operating system keyring.")


@credentials_app.command("status")
def credential_status() -> None:
    """Show whether API keys are stored without revealing them."""
    try:
        shodan_stored = resolve_secret("SHODAN_API_KEY", environ={}) is not None
        openai_stored = resolve_secret("OPENAI_API_KEY", environ={}) is not None
    except CredentialError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    typer.echo(f"Shodan API key: {'stored' if shodan_stored else 'not stored'}")
    typer.echo(f"OpenAI API key: {'stored' if openai_stored else 'not stored'}")


@credentials_app.command("delete-shodan")
def delete_shodan_credential() -> None:
    """Delete the Shodan API key from the operating system keyring."""
    try:
        delete_secret("SHODAN_API_KEY")
    except CredentialError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    typer.echo("Shodan API key deleted from the operating system keyring.")


@credentials_app.command("delete-openai")
def delete_openai_credential() -> None:
    """Delete the OpenAI API key from the operating system keyring."""
    try:
        delete_secret("OPENAI_API_KEY")
    except CredentialError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    typer.echo("OpenAI API key deleted from the operating system keyring.")


@app.command()
def scan(
    domain: Annotated[str, typer.Option("--domain", help="調査対象のapexドメイン")],
    output_dir: Annotated[Path, typer.Option("--output-dir", help="レポート出力先")] = Path(
        "reports"
    ),
    skip_dns: Annotated[bool, typer.Option("--skip-dns", help="DNS解決を省略")] = False,
    enable_shodan: Annotated[
        bool, typer.Option("--enable-shodan", help="Shodan照会を有効化")
    ] = False,
    max_hosts: Annotated[
        int, typer.Option("--max-hosts", min=1, max=10_000, help="処理するホスト名数の上限")
    ] = 1_000,
    max_api_pages: Annotated[
        int,
        typer.Option(
            "--max-api-pages",
            min=1,
            max=10,
            help="Shodanで取得する最大ページ数 (追加クエリクレジットを消費)",
        ),
    ] = 1,
    max_shodan_host_lookups: Annotated[
        int,
        typer.Option(
            "--max-shodan-host-lookups",
            min=1,
            max=1_000,
            help="Shodan Host Informationで詳細取得するIP数の上限",
        ),
    ] = 100,
    timeout: Annotated[
        float, typer.Option("--timeout", min=0.1, max=120.0, help="外部通信タイムアウト (秒)")
    ] = 10.0,
    verbose: Annotated[bool, typer.Option("--verbose", help="詳細ログ")] = False,
) -> None:
    """Scan one explicitly allowed apex domain using passive sources."""
    try:
        normalized_domain = normalize_domain(domain)
    except DomainValidationError as error:
        raise typer.BadParameter(str(error), param_hint="--domain") from error

    try:
        shodan_key = resolve_secret("SHODAN_API_KEY") if enable_shodan else None
    except CredentialError as error:
        raise typer.BadParameter(str(error), param_hint="API credential") from error
    if enable_shodan and not shodan_key:
        raise typer.BadParameter(
            "SHODAN_API_KEY is required when --enable-shodan is used",
            param_hint="--enable-shodan",
        )
    engine = ReconEngine(
        crt_collector=CrtNameCollector(max_hosts=max_hosts, timeout=timeout),
        dns_collector=None if skip_dns else DnsCollector(timeout=timeout),
        shodan_collector=(
            ShodanCollector(
                api_key=shodan_key,
                max_hosts=max_hosts,
                max_pages=max_api_pages,
                max_host_lookups=max_shodan_host_lookups,
                timeout=timeout,
            )
            if enable_shodan
            else None
        ),
    )
    report = engine.scan(
        ScanOptions(
            domain=normalized_domain,
            output_dir=output_dir,
            skip_dns=skip_dns,
            enable_shodan=enable_shodan,
            max_hosts=max_hosts,
            max_api_pages=max_api_pages,
            max_shodan_host_lookups=max_shodan_host_lookups,
        )
    )
    try:
        saved = save_scan_report(report, output_dir)
    except (OSError, ValueError) as error:
        typer.echo(f"Error saving report: {error}", err=True)
        raise typer.Exit(code=2) from error
    if verbose:
        typer.echo(f"assets={len(report.assets)} evidence={len(report.evidence)}")
    typer.echo(f"JSON: {saved.json_path}")
    typer.echo(f"Markdown: {saved.markdown_path}")
    typer.echo(f"History JSON: {saved.history_json_path}")
    if saved.previous_path is not None:
        typer.echo(f"Previous JSON: {saved.previous_path}")
    if saved.diff_paths is not None:
        typer.echo(f"Diff JSON: {saved.diff_paths[0]}")
        typer.echo(f"Diff Markdown: {saved.diff_paths[1]}")
    for warning in saved.warnings:
        typer.echo(f"Warning: {warning}", err=True)
    if report.collector_errors:
        raise typer.Exit(code=1)


@app.command()
def analyze(
    report: Annotated[Path, typer.Option("--report", help="分析するJSONレポート")],
    previous: Annotated[
        Path | None, typer.Option("--previous", help="差分分析に使う前回JSONレポート")
    ] = None,
    output_dir: Annotated[Path, typer.Option("--output-dir", help="分析レポート出力先")] = Path(
        "reports"
    ),
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="使用するOpenAIモデルID",
            show_default=True,
        ),
    ] = "gpt-5.6-luna",
    question: Annotated[
        str | None, typer.Option("--question", help="分析で重視する質問")
    ] = None,
) -> None:
    """Analyze a saved passive report with a grounded, read-only AI agent."""
    try:
        api_key = resolve_secret("OPENAI_API_KEY")
    except CredentialError as error:
        raise typer.BadParameter(str(error), param_hint="--report") from error
    if not api_key:
        raise typer.BadParameter(
            "OPENAI_API_KEY is required for AI analysis",
            param_hint="--report",
        )
    try:
        current_report = load_report(report)
        previous_report = load_report(previous) if previous is not None else None
        dependencies = AnalysisDependencies.from_reports(current_report, previous_report)
        openai_model = OpenAIResponsesModel(
            model,
            provider=OpenAIProvider(api_key=api_key),
        )
        analysis = run_analysis(dependencies, model=openai_model, question=question)
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    except (AgentRunError, UsageLimitExceeded) as error:
        message = str(error).replace(api_key, "[REDACTED]")[:300]
        typer.echo(f"AI analysis failed: {message}", err=True)
        raise typer.Exit(code=1) from error
    json_path, markdown_path = write_analysis_reports(
        analysis,
        report_path=report,
        previous_path=previous,
        model_name=model,
        output_dir=output_dir,
        evidence_by_id=dependencies.evidence_by_id,
    )
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")


@app.command("diff")
def diff_reports(
    previous: Annotated[Path, typer.Option("--previous", help="前回のJSONレポート")],
    current: Annotated[Path, typer.Option("--current", help="今回のJSONレポート")],
    output_dir: Annotated[Path, typer.Option("--output-dir", help="差分レポート出力先")] = Path(
        "reports"
    ),
) -> None:
    """Compare two normalized scan reports for the same domain."""
    try:
        report_diff = compare_reports(load_report(previous), load_report(current))
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=2) from error
    json_path, markdown_path = write_diff_reports(report_diff, output_dir)
    typer.echo(f"JSON: {json_path}")
    typer.echo(f"Markdown: {markdown_path}")
