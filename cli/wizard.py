"""Interactive setup wizard for PIT — fills in any missing config step-by-step."""
import os
import sys
from pathlib import Path
from typing import Optional

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

console = Console()

# Cyan theme that matches the rest of PIT's UI
STYLE = Style([
    ("qmark",       "fg:#00d7ff bold"),
    ("question",    "bold"),
    ("answer",      "fg:#00d7ff bold"),
    ("pointer",     "fg:#00d7ff bold"),
    ("highlighted", "fg:#00d7ff bold"),
    ("selected",    "fg:#00d7ff"),
    ("separator",   "fg:#555555"),
    ("instruction", "fg:#555555 italic"),
])

PROVIDER_MODELS: dict[str, list[str]] = {
    "openai": [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "o1",
        "o3-mini",
        "[ enter custom name ]",
    ],
    "anthropic": [
        "claude-opus-4-6",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "[ enter custom name ]",
    ],
}

ALL_CATEGORIES = [
    "direct_injection",
    "role_hijacking",
    "data_exfiltration",
    "jailbreak",
    "context_escape",
    "indirect_injection",
]

ENV_KEY_NAMES = {
    "openai":     ["PIT_API_KEY", "OPENAI_API_KEY"],
    "anthropic":  ["PIT_API_KEY", "ANTHROPIC_API_KEY"],
}


def _ask(q):
    """Run a questionary prompt and abort cleanly on Ctrl+C."""
    result = q.ask()
    if result is None:
        console.print("\n[dim]Cancelled.[/dim]")
        raise SystemExit(0)
    return result


def _section(title: str) -> None:
    console.print()
    console.print(Rule(f"[dim]{title}[/dim]", style="dim"))


def fill_interactively(
    api_key:            Optional[str]  = None,
    model:              Optional[str]  = None,
    provider:           Optional[str]  = None,
    system_prompt:      Optional[str]  = None,
    system_prompt_file: Optional[Path] = None,
    judge_model:        Optional[str]  = None,
    judge_provider:     Optional[str]  = None,
    judge_api_key:      Optional[str]  = None,
    max_calls:          Optional[int]  = None,
    max_tokens:         Optional[int]  = None,
    categories:         Optional[list[str]] = None,
    extra_tests_file:   Optional[str]  = None,
    output:             Optional[Path] = None,
    verbose:            bool = False,
    no_judge:           bool = False,
    background:         bool = False,
) -> dict:
    """
    Prompt for any config values that weren't provided as CLI flags.
    Returns a dict of all resolved values.
    """
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Interactive wizard requires a TTY. "
            "Provide --api-key, --model, --provider, and --system-prompt "
            "when running non-interactively (e.g. in CI)."
        )

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]PIT[/bold cyan] — Prompt Injection Tester\n"
            "[dim]Interactive setup  ·  press Ctrl+C at any time to cancel[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    # ── Target model ──────────────────────────────────────────────────────────
    _section("Target model")

    if provider is None:
        provider = _ask(questionary.select(
            "Provider:",
            choices=["openai", "anthropic"],
            style=STYLE,
        ))

    if api_key is None:
        # Check environment variables for this provider
        env_val = next(
            (os.environ[k] for k in ENV_KEY_NAMES.get(provider, []) if k in os.environ),
            None,
        )
        if env_val:
            use_env = _ask(questionary.confirm(
                f"Found API key in environment ({next(k for k in ENV_KEY_NAMES[provider] if k in os.environ)}). Use it?",
                default=True,
                style=STYLE,
            ))
            api_key = env_val if use_env else None

        if api_key is None:
            api_key = _ask(questionary.password(
                f"{provider.capitalize()} API key:",
                style=STYLE,
            ))
            if not api_key:
                console.print("[red]API key is required.[/red]")
                raise SystemExit(1)

    if model is None:
        choices = PROVIDER_MODELS.get(provider, ["[ enter custom name ]"])
        selected = _ask(questionary.select(
            "Target model:",
            choices=choices,
            style=STYLE,
        ))
        if "enter custom" in selected:
            model = _ask(questionary.text("Model name:", style=STYLE))
        else:
            model = selected

    # ── System prompt ─────────────────────────────────────────────────────────
    if system_prompt is None and system_prompt_file is None:
        _section("System prompt")

        source = _ask(questionary.select(
            "How would you like to provide the system prompt?",
            choices=[
                questionary.Choice("Load from file  (recommended for longer prompts)", value="file"),
                questionary.Choice("Paste inline",                                      value="inline"),
            ],
            style=STYLE,
        ))

        if source == "file":
            path_str = _ask(questionary.path(
                "Path to system prompt file:",
                style=STYLE,
            ))
            system_prompt_file = Path(path_str)
            if not system_prompt_file.exists():
                console.print(f"[red]File not found: {system_prompt_file}[/red]")
                raise SystemExit(1)
            system_prompt = system_prompt_file.read_text().strip()
        else:
            console.print(
                "[dim]Paste your system prompt. "
                "Enter a blank line followed by END on its own line to finish.[/dim]"
            )
            lines: list[str] = []
            while True:
                line = input()
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            system_prompt = "\n".join(lines).strip()
            if not system_prompt:
                console.print("[red]System prompt cannot be empty.[/red]")
                raise SystemExit(1)

    # Resolve file path if provided without reading yet
    if system_prompt is None and system_prompt_file is not None:
        system_prompt = system_prompt_file.read_text().strip()

    # ── Test cases ────────────────────────────────────────────────────────────
    _section("Test cases")

    if extra_tests_file is None:
        load_custom = _ask(questionary.confirm(
            "Load additional custom test cases from a YAML file?",
            default=False,
            style=STYLE,
        ))
        if load_custom:
            path_str = _ask(questionary.path(
                "Path to custom test cases YAML:",
                style=STYLE,
            ))
            extra_tests_file = path_str

    if categories is None:
        selected_cats = _ask(questionary.checkbox(
            "Attack categories to run:  (space = toggle, a = all, enter = confirm)",
            choices=[questionary.Choice(cat, checked=True) for cat in ALL_CATEGORIES],
            style=STYLE,
        ))
        # None means all — only set if user deselected at least one
        if selected_cats is not None and set(selected_cats) != set(ALL_CATEGORIES):
            categories = selected_cats if selected_cats else ALL_CATEGORIES

    # ── Judge LLM ─────────────────────────────────────────────────────────────
    if not no_judge and judge_model is None:
        _section("Judge LLM")

        judge_choice = _ask(questionary.select(
            "Judge LLM configuration:",
            choices=[
                questionary.Choice(
                    f"Same as target  ({model} · {provider})  — recommended",
                    value="same",
                ),
                questionary.Choice(
                    "Use a different model for judging",
                    value="different",
                ),
                questionary.Choice(
                    "Skip judge — keyword evaluation only  (faster, less accurate)",
                    value="none",
                ),
            ],
            style=STYLE,
        ))

        if judge_choice == "none":
            no_judge = True
        elif judge_choice == "different":
            judge_provider = _ask(questionary.select(
                "Judge provider:",
                choices=["openai", "anthropic"],
                style=STYLE,
            ))
            j_choices = PROVIDER_MODELS.get(judge_provider, ["[ enter custom name ]"])
            j_selected = _ask(questionary.select(
                "Judge model:",
                choices=j_choices,
                style=STYLE,
            ))
            judge_model = (
                _ask(questionary.text("Judge model name:", style=STYLE))
                if "enter custom" in j_selected
                else j_selected
            )
            use_same_key = _ask(questionary.confirm(
                "Use the same API key for the judge?",
                default=True,
                style=STYLE,
            ))
            if not use_same_key:
                judge_api_key = _ask(questionary.password(
                    "Judge API key:",
                    style=STYLE,
                ))

    # ── Limits ────────────────────────────────────────────────────────────────
    if max_calls is None and max_tokens is None:
        _section("Usage limits")

        limit_choice = _ask(questionary.select(
            "Set usage limits?  (guards against runaway API costs)",
            choices=[
                questionary.Choice("No limits",       value="none"),
                questionary.Choice("Max API calls",   value="calls"),
                questionary.Choice("Max tokens",      value="tokens"),
                questionary.Choice("Both",            value="both"),
            ],
            style=STYLE,
        ))

        if limit_choice in ("calls", "both"):
            val = _ask(questionary.text(
                "Max API calls:",
                validate=lambda x: x.isdigit() or "Please enter a whole number",
                style=STYLE,
            ))
            max_calls = int(val)

        if limit_choice in ("tokens", "both"):
            val = _ask(questionary.text(
                "Max tokens:",
                validate=lambda x: x.isdigit() or "Please enter a whole number",
                style=STYLE,
            ))
            max_tokens = int(val)

    # ── Output ────────────────────────────────────────────────────────────────
    _section("Output")

    if output is None:
        save_report = _ask(questionary.confirm(
            "Save JSON report to file?",
            default=True,
            style=STYLE,
        ))
        if save_report:
            path_str = _ask(questionary.text(
                "Output file path:",
                default="report.json",
                style=STYLE,
            ))
            output = Path(path_str)

    verbose = _ask(questionary.confirm(
        "Show full model responses for non-safe results?",
        default=False,
        style=STYLE,
    ))

    background = _ask(questionary.confirm(
        "Run in background?  (returns immediately — check progress with: pit status)",
        default=False,
        style=STYLE,
    ))

    # ── Confirmation summary ──────────────────────────────────────────────────
    console.print()
    cat_display   = ", ".join(categories) if categories else "all"
    judge_display = (
        "keyword-only"
        if no_judge
        else f"{judge_model or model}  ({judge_provider or provider})"
    )
    limits_parts  = []
    if max_calls:  limits_parts.append(f"max {max_calls} calls")
    if max_tokens: limits_parts.append(f"max {max_tokens:,} tokens")

    mode_display = "[cyan]background[/cyan]" if background else "foreground"
    summary = (
        f"  [dim]Target:[/dim]       {model}  ({provider})\n"
        f"  [dim]Judge:[/dim]        {judge_display}\n"
        f"  [dim]Categories:[/dim]   {cat_display}\n"
        f"  [dim]Custom tests:[/dim] {extra_tests_file or 'none'}\n"
        f"  [dim]Limits:[/dim]       {', '.join(limits_parts) or 'none'}\n"
        f"  [dim]Output:[/dim]       {output or 'none'}\n"
        f"  [dim]Mode:[/dim]         {mode_display}"
    )
    console.print(Panel(
        summary,
        title="[bold]Ready to run[/bold]",
        border_style="cyan",
        padding=(0, 1),
    ))
    console.print()

    proceed = _ask(questionary.confirm(
        "Proceed?",
        default=True,
        style=STYLE,
    ))
    if not proceed:
        console.print("[dim]Aborted.[/dim]")
        raise SystemExit(0)

    return dict(
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
        categories=categories,
        extra_tests_file=extra_tests_file,
        output=output,
        verbose=verbose,
        no_judge=no_judge,
        background=background,
    )
