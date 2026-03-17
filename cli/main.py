"""PIT — Prompt Injection Tester CLI."""
import json
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import questionary
import typer
import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.rule import Rule
from rich.table import Table

from cli.wizard import STYLE, fill_interactively
from core.attacks.loader import load_builtin_attacks
from core.models import TestRun, TestRunConfig, Verdict
from core.reporter import (
    SEVERITY_STYLE,
    VERDICT_ICON,
    VERDICT_STYLE,
    build_summary,
    save_json_report,
)
from core.runner import run_tests

app = typer.Typer(
    name="pit",
    help="PIT — Prompt Injection Tester. Security testing for LLM applications.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()

JOBS_DIR = Path(".pit/jobs")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_system_prompt(
    system_prompt: Optional[str],
    system_prompt_file: Optional[Path],
) -> str:
    if system_prompt:
        return system_prompt
    if system_prompt_file:
        if not system_prompt_file.exists():
            console.print(f"[red]Error:[/red] file not found: {system_prompt_file}")
            raise typer.Exit(1)
        return system_prompt_file.read_text().strip()
    console.print("[red]Error:[/red] provide [bold]--system-prompt[/bold] or [bold]--system-prompt-file[/bold].")
    raise typer.Exit(1)


def _spawn_background_worker(job_id: str, jobs_base: Path) -> subprocess.Popen:
    """Launch a detached background worker process and return the Popen handle."""
    worker_script = (
        f"import sys; sys.path.insert(0, {repr(str(Path.cwd()))}); "
        f"from cli.background_worker import execute_job; "
        f"execute_job({repr(job_id)}, {repr(str(jobs_base))})"
    )
    log_path = jobs_base / job_id / "worker.log"
    return subprocess.Popen(
        [sys.executable, "-c", worker_script],
        start_new_session=True,
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
    )


def _read_status(job_id: str) -> Optional[dict]:
    f = JOBS_DIR / job_id / "status.json"
    return json.loads(f.read_text()) if f.exists() else None


def _read_results(job_id: str) -> list[dict]:
    f = JOBS_DIR / job_id / "results.jsonl"
    if not f.exists():
        return []
    results = []
    for line in f.read_text().splitlines():
        line = line.strip()
        if line:
            results.append(json.loads(line))
    return results


def _render_results_table(raw_results: list[dict]) -> Table:
    table = Table("Test", "Category", "Sev", "Verdict", "Reasoning",
                  show_lines=True, expand=True)
    for r in raw_results:
        tc      = r["test_case"]
        verdict = Verdict(r["verdict"])
        v_style = VERDICT_STYLE[verdict]
        s_style = SEVERITY_STYLE.get(r["severity"], "")
        icon    = VERDICT_ICON[verdict]
        reason  = r["reasoning"]
        short   = reason[:72] + "…" if len(reason) > 75 else reason
        table.add_row(
            f"[bold]{tc['name']}[/bold]",
            f"[dim]{tc['category']}[/dim]",
            f"[{s_style}]{r['severity'].upper()}[/{s_style}]",
            f"[{v_style}]{icon} {verdict.value.upper()}[/{v_style}]",
            short,
        )
    return table


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------

@app.command()
def run(
    api_key: Optional[str] = typer.Option(
        None, "--api-key", "-k", envvar="PIT_API_KEY",
        help="API key for the target model provider.",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m",
        help="Target model name (e.g. gpt-4o, claude-sonnet-4-6).",
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p",
        help="Model provider: openai | anthropic.",
    ),
    system_prompt: Optional[str] = typer.Option(
        None, "--system-prompt", "-s",
        help="System prompt of the AI application under test (inline string).",
    ),
    system_prompt_file: Optional[Path] = typer.Option(
        None, "--system-prompt-file",
        help="Path to a file containing the system prompt.",
    ),
    judge_model: Optional[str] = typer.Option(
        None, "--judge-model",
        help="Model for the judge LLM. Defaults to the target model.",
    ),
    judge_provider: Optional[str] = typer.Option(
        None, "--judge-provider",
        help="Provider for the judge LLM. Defaults to the target provider.",
    ),
    judge_api_key: Optional[str] = typer.Option(
        None, "--judge-api-key", envvar="PIT_JUDGE_API_KEY",
        help="API key for the judge LLM. Defaults to the target API key.",
    ),
    max_calls: Optional[int] = typer.Option(
        None, "--max-calls",
        help="Hard limit on total API calls (target + judge combined).",
    ),
    max_tokens: Optional[int] = typer.Option(
        None, "--max-tokens",
        help="Hard limit on total tokens consumed across all calls.",
    ),
    categories: Optional[str] = typer.Option(
        None, "--categories", "-c",
        help="Comma-separated attack categories to run.",
    ),
    tests_file: Optional[Path] = typer.Option(
        None, "--tests-file", "-t",
        help="Path to a YAML file with additional custom test cases.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Save the full JSON report to this file path.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Print the full model response for every test.",
    ),
    no_judge: bool = typer.Option(
        False, "--no-judge",
        help="Skip the judge LLM and use keyword evaluation only.",
    ),
    background: bool = typer.Option(
        False, "--background", "-b",
        help="Run tests in the background. Returns a job ID immediately.",
    ),
) -> None:
    """Run prompt injection tests against an AI application."""

    # --- Wizard: trigger when any required arg is missing ---
    needs_wizard = (
        api_key is None
        or model is None
        or provider is None
        or (system_prompt is None and system_prompt_file is None)
    )

    if needs_wizard:
        try:
            cat_list_pre: Optional[list[str]] = (
                [c.strip() for c in categories.split(",")] if categories else None
            )
            w = fill_interactively(
                api_key=api_key,
                model=model,
                provider=provider,
                system_prompt=system_prompt,
                system_prompt_file=system_prompt_file,
                judge_model=judge_model,
                judge_provider=judge_provider,
                judge_api_key=judge_api_key,
                max_calls=max_calls,
                max_tokens=max_tokens,
                categories=cat_list_pre,
                extra_tests_file=str(tests_file) if tests_file else None,
                output=output,
                verbose=verbose,
                no_judge=no_judge,
                background=background,
            )
        except (KeyboardInterrupt, SystemExit):
            raise typer.Exit(0)

        api_key        = w["api_key"]
        model          = w["model"]
        provider       = w["provider"]
        system_prompt  = w["system_prompt"]
        judge_model    = w["judge_model"]
        judge_provider = w["judge_provider"]
        judge_api_key  = w["judge_api_key"]
        max_calls      = w["max_calls"]
        max_tokens     = w["max_tokens"]
        categories     = ",".join(w["categories"]) if w["categories"] else categories
        tests_file     = Path(w["extra_tests_file"]) if w["extra_tests_file"] else tests_file
        output         = w["output"]
        verbose        = w["verbose"]
        no_judge       = w["no_judge"]
        background     = w["background"]

    resolved_prompt = _resolve_system_prompt(system_prompt, system_prompt_file)

    cat_list: Optional[list[str]] = (
        [c.strip() for c in categories.split(",")] if categories else None
    )

    config = TestRunConfig(
        api_key=api_key,
        model=model,
        provider=provider,
        system_prompt=resolved_prompt,
        judge_model=judge_model,
        judge_provider=judge_provider,
        judge_api_key=judge_api_key,
        max_calls=max_calls,
        max_tokens=max_tokens,
        categories=cat_list,
        extra_tests_file=str(tests_file) if tests_file else None,
        use_judge=not no_judge,
    )

    # ── Background mode ───────────────────────────────────────────────────────
    if background:
        job_id   = str(uuid.uuid4())[:8]
        job_dir  = JOBS_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        (job_dir / "config.json").write_text(config.model_dump_json())
        (job_dir / "status.json").write_text(json.dumps({
            "job_id":     job_id,
            "status":     "pending",
            "created_at": datetime.utcnow().isoformat(),
            "model":      model,
            "provider":   provider,
        }, indent=2))

        _spawn_background_worker(job_id, JOBS_DIR)

        console.print()
        console.print(Panel(
            f"  [bold cyan]Job ID:[/bold cyan]  {job_id}\n"
            f"  [dim]Model:[/dim]    {model} ({provider})\n\n"
            f"  [dim]pit status {job_id}[/dim]          — live progress\n"
            f"  [dim]pit status {job_id} --follow[/dim]  — auto-refresh\n"
            f"  [dim]pit jobs[/dim]                    — all jobs",
            title="[bold]Background job started[/bold]",
            border_style="cyan",
            padding=(0, 2),
        ))
        console.print()
        return

    # ── Foreground mode ───────────────────────────────────────────────────────
    if not needs_wizard:
        console.print()
        judge_note = (
            f"  [dim]Judge:[/dim] {judge_model or model} ({judge_provider or provider})"
            if not no_judge else "  [dim]Judge:[/dim] keyword-only"
        )
        console.print(Panel.fit(
            f"[bold cyan]PIT[/bold cyan] — Prompt Injection Tester\n"
            f"  [dim]Target:[/dim] {model} ({provider})\n{judge_note}",
            border_style="cyan", padding=(0, 2),
        ))
    console.print()

    table = Table("Test", "Category", "Sev", "Verdict", "Reasoning",
                  show_lines=True, expand=True)
    results = []
    final_calls = 0
    final_tokens = 0

    with console.status("[bold cyan]Running tests…[/bold cyan]") as status:
        for result, calls, tokens in run_tests(config):
            results.append(result)
            final_calls  = calls
            final_tokens = tokens

            v_style   = VERDICT_STYLE[result.verdict]
            s_style   = SEVERITY_STYLE[result.severity]
            icon      = VERDICT_ICON[result.verdict]
            short_r   = result.reasoning[:72] + "…" if len(result.reasoning) > 75 else result.reasoning

            table.add_row(
                f"[bold]{result.test_case.name}[/bold]",
                f"[dim]{result.test_case.category.value}[/dim]",
                f"[{s_style}]{result.severity.value.upper()}[/{s_style}]",
                f"[{v_style}]{icon} {result.verdict.value.upper()}[/{v_style}]",
                short_r,
            )
            status.update(
                f"[bold cyan]Running tests… ({len(results)} done, "
                f"{calls} calls, {tokens:,} tokens)[/bold cyan]"
            )

    console.print(table)
    console.print()

    summary = build_summary(results)
    total   = summary.total or 1

    def pct(n: int) -> str:
        return f"{int(n / total * 100):3d}%"

    summary_lines = (
        f"[bold]Run complete[/bold]  [dim]{summary.total} tests · "
        f"{final_calls} API calls · {final_tokens:,} tokens[/dim]\n\n"
        f"[green]✓ Safe        {summary.safe:3d}  {pct(summary.safe)}[/green]\n"
        f"[bold red]✗ Vulnerable  {summary.vulnerable:3d}  {pct(summary.vulnerable)}[/bold red]\n"
        f"[yellow]~ Partial     {summary.partial:3d}  {pct(summary.partial)}[/yellow]\n"
        f"[dim]? Unclear     {summary.unclear:3d}  {pct(summary.unclear)}[/dim]"
    )
    border = "red" if summary.vulnerable > 0 else "yellow" if summary.partial > 0 else "green"
    console.print(Panel(summary_lines, border_style=border, padding=(1, 2)))

    if verbose:
        non_safe = [r for r in results if r.verdict in (Verdict.VULNERABLE, Verdict.PARTIAL, Verdict.UNCLEAR)]
        if non_safe:
            console.print()
            console.print(Rule("[bold]Full responses — non-safe results[/bold]"))
            for r in non_safe:
                v_style = VERDICT_STYLE[r.verdict]
                console.print(f"\n[{v_style}]{VERDICT_ICON[r.verdict]} {r.test_case.name}[/{v_style}]  "
                               f"[dim]{r.test_case.category.value}[/dim]")
                console.print(f"[dim]Attack:[/dim]   {r.test_case.prompt}")
                console.print(f"[dim]Response:[/dim] {r.raw_response}")
                if r.flagged_keywords:
                    console.print(f"[dim]Keywords:[/dim] {', '.join(r.flagged_keywords)}")

    if output:
        test_run = TestRun(
            config=config, results=results,
            total_tokens=final_tokens, total_calls=final_calls,
            summary=summary,
        )
        save_json_report(test_run, str(output))
        console.print(f"\n[dim]Report saved → {output}[/dim]")

    console.print()
    if summary.vulnerable > 0:
        raise typer.Exit(2)


# ---------------------------------------------------------------------------
# generate command
# ---------------------------------------------------------------------------

@app.command()
def generate(
    api_key: Optional[str] = typer.Option(
        None, "--api-key", "-k", envvar="PIT_API_KEY",
        help="API key (required for AI generation).",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m",
        help="Model to use for generation.",
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p",
        help="Model provider: openai | anthropic.",
    ),
    system_prompt: Optional[str] = typer.Option(
        None, "--system-prompt", "-s",
        help="System prompt to analyze (inline string).",
    ),
    system_prompt_file: Optional[Path] = typer.Option(
        None, "--system-prompt-file",
        help="Path to a file containing the system prompt.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Path to save the generated YAML test cases.",
    ),
    count: int = typer.Option(
        15, "--count", "-n",
        help="Number of test cases to generate (AI mode).",
    ),
    manual: bool = typer.Option(
        False, "--manual",
        help="Create test cases manually via interactive prompts instead of AI.",
    ),
) -> None:
    """Generate custom test cases for a specific system prompt."""
    from core.models import Category, Severity, TestCase

    console.print()
    console.print(Panel.fit(
        "[bold cyan]PIT[/bold cyan] — Test Case Generator",
        border_style="cyan", padding=(0, 2),
    ))
    console.print()

    # ── Choose mode if not specified ──────────────────────────────────────────
    if not manual:
        mode = questionary.select(
            "Generation mode:",
            choices=[
                questionary.Choice("AI-powered  (LLM analyzes your system prompt and writes targeted attacks)", value="ai"),
                questionary.Choice("Manual      (create test cases one-by-one via prompts)",                    value="manual"),
            ],
            style=STYLE,
        ).ask()
        if mode is None:
            raise typer.Exit(0)
        manual = (mode == "manual")

    # ── Resolve system prompt ─────────────────────────────────────────────────
    resolved_prompt: Optional[str] = None
    if system_prompt:
        resolved_prompt = system_prompt
    elif system_prompt_file:
        resolved_prompt = system_prompt_file.read_text().strip()
    else:
        if not manual:
            # AI mode requires a system prompt
            src = questionary.select(
                "How would you like to provide the system prompt?",
                choices=[
                    questionary.Choice("Load from file", value="file"),
                    questionary.Choice("Paste inline",   value="inline"),
                ],
                style=STYLE,
            ).ask()
            if src == "file":
                p = questionary.path("Path to system prompt file:", style=STYLE).ask()
                if p:
                    resolved_prompt = Path(p).read_text().strip()
            else:
                console.print("[dim]Paste your system prompt. Enter END on its own line to finish.[/dim]")
                lines: list[str] = []
                while True:
                    line = input()
                    if line.strip().upper() == "END":
                        break
                    lines.append(line)
                resolved_prompt = "\n".join(lines).strip()

    # ── Output path ───────────────────────────────────────────────────────────
    if output is None:
        p = questionary.text(
            "Save generated test cases to:",
            default="generated_tests.yaml",
            style=STYLE,
        ).ask()
        output = Path(p) if p else Path("generated_tests.yaml")

    # ── AI generation ─────────────────────────────────────────────────────────
    if not manual:
        if not resolved_prompt:
            console.print("[red]System prompt is required for AI generation.[/red]")
            raise typer.Exit(1)

        # Resolve provider / model / api_key for generation
        if provider is None:
            provider = questionary.select("Provider:", choices=["openai", "anthropic"], style=STYLE).ask()
        if api_key is None:
            import os
            env_keys = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
            api_key = os.environ.get("PIT_API_KEY") or os.environ.get(env_keys.get(provider, ""))
            if not api_key:
                api_key = questionary.password(f"{provider.capitalize()} API key:", style=STYLE).ask()
        if model is None:
            from cli.wizard import PROVIDER_MODELS
            choices = PROVIDER_MODELS.get(provider, ["[ enter custom name ]"])
            sel = questionary.select("Model:", choices=choices, style=STYLE).ask()
            model = questionary.text("Model name:", style=STYLE).ask() if "enter custom" in (sel or "") else sel

        from core.generator import generate_attacks
        from core.providers.base import BaseProvider

        gen_provider = BaseProvider.create(provider, api_key, model)

        with console.status(f"[bold cyan]Generating {count} test cases…[/bold cyan]"):
            try:
                yaml_str, tokens = generate_attacks(gen_provider, resolved_prompt, count)
            except ValueError as e:
                console.print(f"[red]Generation failed:[/red] {e}")
                raise typer.Exit(1)

        # Preview generated cases
        data = yaml.safe_load(yaml_str)
        attacks = data.get("attacks", [])
        console.print()
        table = Table("ID", "Category", "Name", "Severity", show_lines=True)
        for a in attacks:
            s = a.get("severity", "medium")
            s_style = SEVERITY_STYLE.get(Severity(s) if s in Severity._value2member_map_ else Severity.MEDIUM, "")
            table.add_row(
                a.get("id", "?"),
                a.get("category", "?"),
                a.get("name", "?"),
                f"[{s_style}]{s.upper()}[/{s_style}]",
            )
        console.print(table)
        console.print(f"\n[dim]{len(attacks)} test cases generated  ·  {tokens:,} tokens used[/dim]\n")

        output.write_text(yaml_str)
        console.print(f"[green]Saved →[/green] {output}")
        console.print(f"[dim]Use with: pit run --tests-file {output} ...[/dim]\n")
        return

    # ── Manual creation ───────────────────────────────────────────────────────
    created: list[dict] = []
    cat_choices = [c.value for c in Category]
    sev_choices = [s.value for s in Severity]

    console.print("[dim]Create test cases one by one. Press Ctrl+C to stop and save.[/dim]\n")

    try:
        while True:
            idx = len(created) + 1
            console.print(Rule(f"[cyan]Test case #{idx}[/cyan]"))

            tc_id = questionary.text(
                "ID:", default=f"custom_{idx:03d}", style=STYLE,
            ).ask()
            if tc_id is None:
                break

            name = questionary.text("Name:", style=STYLE).ask()
            if not name:
                break

            category = questionary.select(
                "Category:", choices=cat_choices, style=STYLE,
            ).ask()
            if category is None:
                break

            prompt_text = questionary.text("Attack prompt:", style=STYLE).ask()
            if not prompt_text:
                break

            expected = questionary.text(
                "Expected behavior (what a safe response looks like):", style=STYLE,
            ).ask()
            if not expected:
                break

            severity = questionary.select(
                "Severity:", choices=sev_choices, style=STYLE,
            ).ask()
            if severity is None:
                break

            tags_str = questionary.text(
                "Tags (comma-separated, optional):", default="", style=STYLE,
            ).ask() or ""
            tags = [t.strip() for t in tags_str.split(",") if t.strip()]

            created.append({
                "id":               tc_id,
                "category":         category,
                "name":             name,
                "prompt":           prompt_text,
                "expected_behavior": expected,
                "severity":         severity,
                "tags":             tags,
            })

            console.print(f"[green]✓ Added:[/green] {name}\n")

            more = questionary.confirm("Add another test case?", default=True, style=STYLE).ask()
            if not more:
                break

    except (KeyboardInterrupt, EOFError):
        pass

    if not created:
        console.print("[dim]No test cases created.[/dim]\n")
        raise typer.Exit(0)

    result_yaml = yaml.dump({"attacks": created}, default_flow_style=False, allow_unicode=True)
    output.write_text(result_yaml)

    console.print(f"\n[green]Saved {len(created)} test case(s) →[/green] {output}")
    console.print(f"[dim]Use with: pit run --tests-file {output} ...[/dim]\n")


# ---------------------------------------------------------------------------
# jobs command
# ---------------------------------------------------------------------------

@app.command()
def jobs() -> None:
    """List all background jobs."""
    if not JOBS_DIR.exists():
        console.print("\n[dim]No jobs found. Start one with: pit run --background[/dim]\n")
        return

    job_dirs = sorted(JOBS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    if not job_dirs:
        console.print("\n[dim]No jobs found. Start one with: pit run --background[/dim]\n")
        return

    table = Table("Job ID", "Status", "Model", "Progress", "Started", "Ended",
                  show_lines=True, title="[bold]Background Jobs[/bold]")

    for job_dir in job_dirs:
        status_file = job_dir / "status.json"
        if not status_file.exists():
            continue
        s = json.loads(status_file.read_text())

        job_status = s.get("status", "?")
        status_map = {
            "running":  "[cyan]running[/cyan]",
            "complete": "[green]complete[/green]",
            "failed":   "[red]failed[/red]",
            "pending":  "[yellow]pending[/yellow]",
        }
        status_display = status_map.get(job_status, job_status)

        completed = s.get("completed", 0)
        total     = s.get("total", "?")
        progress  = f"{completed}/{total}" if total != "?" else f"{completed}/?"

        started = s.get("started_at") or s.get("created_at", "?")
        if started and started != "?":
            started = started[:16].replace("T", " ")

        ended = s.get("completed_at")
        if ended:
            ended = ended[:16].replace("T", " ")
        else:
            ended = "[dim]—[/dim]"

        table.add_row(
            s.get("job_id", job_dir.name),
            status_display,
            f"{s.get('model', '?')} ({s.get('provider', '?')})",
            progress,
            started,
            ended,
        )

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------

@app.command()
def status(
    job_id: str = typer.Argument(..., help="Job ID to inspect."),
    follow: bool = typer.Option(
        False, "--follow", "-f",
        help="Auto-refresh every 2 seconds until the job completes.",
    ),
) -> None:
    """Show the status and results of a background job."""
    import time

    job_dir = JOBS_DIR / job_id
    if not job_dir.exists():
        console.print(f"[red]Error:[/red] job '{job_id}' not found in {JOBS_DIR}/")
        raise typer.Exit(1)

    def _render() -> Table:
        s        = _read_status(job_id) or {}
        raw      = _read_results(job_id)
        progress = f"{s.get('completed', 0)}/{s.get('total', '?')}"
        job_status = s.get("status", "?")
        status_colors = {
            "running": "cyan", "complete": "green",
            "failed": "red", "pending": "yellow",
        }
        color = status_colors.get(job_status, "white")

        # Header panel
        calls  = s.get("total_calls", 0)
        tokens = s.get("total_tokens", 0)
        error  = s.get("error")
        info = (
            f"  [dim]Job:[/dim]      {job_id}\n"
            f"  [dim]Status:[/dim]   [{color}]{job_status}[/{color}]\n"
            f"  [dim]Model:[/dim]    {s.get('model', '?')} ({s.get('provider', '?')})\n"
            f"  [dim]Progress:[/dim] {progress}  ·  {calls} calls  ·  {tokens:,} tokens"
        )
        if error:
            info += f"\n  [red]Error:[/red] {error}"

        report_path = job_dir / "report.json"
        if report_path.exists():
            info += f"\n  [dim]Report:[/dim]   {report_path}"

        console.print()
        console.print(Panel(info, title=f"[bold]Job {job_id}[/bold]",
                            border_style=color, padding=(0, 2)))
        console.print()

        if raw:
            console.print(_render_results_table(raw))
            console.print()

        return job_status

    if not follow:
        _render()
        return

    # Follow mode — poll until complete or failed
    console.print("[dim]Following job (Ctrl+C to stop)…[/dim]")
    try:
        while True:
            job_status = _render()
            if job_status in ("complete", "failed"):
                break
            time.sleep(2)
            console.clear()
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped following.[/dim]\n")


# ---------------------------------------------------------------------------
# list-attacks command
# ---------------------------------------------------------------------------

@app.command(name="list-attacks")
def list_attacks(
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Filter by category.",
    ),
) -> None:
    """List all built-in attack test cases."""
    cats = [category] if category else None
    test_cases = load_builtin_attacks(cats)

    table = Table("ID", "Category", "Name", "Severity", "Tags",
                  title="[bold]Built-in Attack Test Cases[/bold]", show_lines=True)
    for tc in test_cases:
        s_style = SEVERITY_STYLE[tc.severity]
        table.add_row(
            tc.id,
            tc.category.value,
            tc.name,
            f"[{s_style}]{tc.severity.value.upper()}[/{s_style}]",
            ", ".join(tc.tags),
        )

    console.print()
    console.print(table)
    console.print(f"\n[dim]Total: {len(test_cases)} test cases[/dim]\n")


# ---------------------------------------------------------------------------
# review command
# ---------------------------------------------------------------------------

@app.command()
def review(
    report_file: Path = typer.Argument(..., help="Path to a JSON report file."),
) -> None:
    """Interactively review UNCLEAR and PARTIAL results from a saved report."""
    if not report_file.exists():
        console.print(f"[red]Error:[/red] file not found: {report_file}")
        raise typer.Exit(1)

    with open(report_file) as f:
        data = json.load(f)

    results = data.get("results", [])
    needs_review = [r for r in results if r["verdict"] in ("unclear", "partial")]

    if not needs_review:
        console.print("[green]No results flagged for manual review.[/green]")
        return

    console.print(f"\n[bold]{len(needs_review)} result(s) need manual review[/bold]\n")

    for i, r in enumerate(needs_review, 1):
        tc      = r["test_case"]
        verdict = r["verdict"]
        v_style = VERDICT_STYLE.get(Verdict(verdict), "white")

        console.print(Rule(f"[{v_style}]{i}/{len(needs_review)}: {tc['name']}[/{v_style}]"))
        console.print(f"[dim]Category:[/dim]  {tc['category']}")
        console.print(f"[dim]Severity:[/dim]  {r['severity'].upper()}")
        console.print(f"[dim]Verdict:[/dim]   [{v_style}]{verdict.upper()}[/{v_style}]")
        console.print(f"[dim]Reasoning:[/dim] {r['reasoning']}")
        console.print()
        console.print(f"[dim]Attack prompt:[/dim]\n{tc['prompt']}")
        console.print()
        console.print(f"[dim]Model response:[/dim]\n{r['raw_response']}")
        console.print()

        choice = typer.prompt("Your verdict? [s=safe, v=vulnerable, p=partial, skip]", default="skip")
        labels = {"v": ("[red]Marked: VULNERABLE[/red]"), "s": "[green]Marked: SAFE[/green]",
                  "p": "[yellow]Marked: PARTIAL[/yellow]"}
        console.print(labels.get(choice.lower(), "[dim]Skipped.[/dim]"))
        console.print()

    console.print("[dim]Review complete.[/dim]\n")


if __name__ == "__main__":
    app()
