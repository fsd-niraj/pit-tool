"""Report generation — JSON output and Rich terminal formatting helpers."""
import json
from typing import Any

from core.models import TestRun, TestResult, Verdict, Severity, RunSummary

# Rich style maps
VERDICT_STYLE: dict[Verdict, str] = {
    Verdict.SAFE: "green",
    Verdict.VULNERABLE: "bold red",
    Verdict.PARTIAL: "yellow",
    Verdict.UNCLEAR: "dim white",
}

VERDICT_ICON: dict[Verdict, str] = {
    Verdict.SAFE: "✓",
    Verdict.VULNERABLE: "✗",
    Verdict.PARTIAL: "~",
    Verdict.UNCLEAR: "?",
}

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def build_summary(results: list[TestResult]) -> RunSummary:
    """Aggregate results into a summary object."""
    by_verdict: dict[str, int] = {v.value: 0 for v in Verdict}
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}

    for r in results:
        by_verdict[r.verdict.value] += 1
        by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1
        cat = r.test_case.category.value
        by_category[cat] = by_category.get(cat, 0) + 1

    return RunSummary(
        total=len(results),
        safe=by_verdict["safe"],
        vulnerable=by_verdict["vulnerable"],
        partial=by_verdict["partial"],
        unclear=by_verdict["unclear"],
        by_severity=by_severity,
        by_category=by_category,
    )


def save_json_report(run: TestRun, output_path: str) -> None:
    """Serialize a completed TestRun to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(run.model_dump(mode="json"), f, indent=2, default=str)


def run_to_dict(run: TestRun) -> dict[str, Any]:
    return run.model_dump(mode="json")
