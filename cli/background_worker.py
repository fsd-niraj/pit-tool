"""
Background job worker.

Invoked by the main process as a detached subprocess:
    python -c "from cli.background_worker import execute_job; execute_job(job_id, jobs_base)"

Reads config from <jobs_base>/<job_id>/config.json, runs the test suite, and
writes streaming results + a final report to the same directory.
"""
import json
import os
from datetime import datetime
from pathlib import Path

from core.attacks.loader import load_builtin_attacks, load_custom_attacks
from core.models import TestResult, TestRun, TestRunConfig
from core.reporter import build_summary, save_json_report
from core.runner import run_tests


def execute_job(job_id: str, jobs_base: str = ".pit/jobs") -> None:
    """Run a background job to completion, writing results as they stream in."""
    jobs_dir = Path(jobs_base) / job_id
    config_file  = jobs_dir / "config.json"
    status_file  = jobs_dir / "status.json"
    results_file = jobs_dir / "results.jsonl"

    config = TestRunConfig.model_validate_json(config_file.read_text())

    # Pre-count total tests so we can show X/Y progress
    test_cases = load_builtin_attacks(config.categories)
    if config.extra_tests_file:
        test_cases.extend(load_custom_attacks(config.extra_tests_file))
    total = len(test_cases)

    def _write_status(patch: dict) -> None:
        current = json.loads(status_file.read_text()) if status_file.exists() else {}
        current.update(patch)
        status_file.write_text(json.dumps(current, indent=2))

    _write_status({
        "job_id":       job_id,
        "status":       "running",
        "pid":          os.getpid(),
        "model":        config.model,
        "provider":     config.provider,
        "started_at":   datetime.utcnow().isoformat(),
        "completed_at": None,
        "completed":    0,
        "total":        total,
        "total_calls":  0,
        "total_tokens": 0,
        "error":        None,
    })

    try:
        with open(results_file, "w") as rf:
            for result, calls, tokens in run_tests(config):
                rf.write(result.model_dump_json() + "\n")
                rf.flush()
                _write_status({
                    "completed":    json.loads(status_file.read_text())["completed"] + 1,
                    "total_calls":  calls,
                    "total_tokens": tokens,
                })

        final = json.loads(status_file.read_text())
        _write_status({
            "status":       "complete",
            "completed_at": datetime.utcnow().isoformat(),
        })

        # Build final report
        results: list[TestResult] = []
        with open(results_file) as rf:
            for line in rf:
                line = line.strip()
                if line:
                    results.append(TestResult.model_validate_json(line))

        run = TestRun(
            config=config,
            results=results,
            total_tokens=final["total_tokens"],
            total_calls=final["total_calls"],
            summary=build_summary(results),
        )
        save_json_report(run, str(jobs_dir / "report.json"))

    except Exception as e:
        _write_status({
            "status":       "failed",
            "error":        str(e),
            "completed_at": datetime.utcnow().isoformat(),
        })
        raise
