"""Test run orchestrator."""
from typing import Iterator

from core.models import TestCase, TestResult, TestRunConfig, Verdict, Severity
from core.providers.base import BaseProvider
from core.evaluator.keyword import evaluate_keywords
from core.evaluator.judge_llm import evaluate_with_judge
from core.attacks.loader import load_builtin_attacks, load_custom_attacks


def run_tests(config: TestRunConfig) -> Iterator[tuple[TestResult, int, int]]:
    """
    Run all test cases and yield (result, total_calls_so_far, total_tokens_so_far)
    as each test completes. Respects max_calls and max_tokens limits.
    """
    # Load test cases
    test_cases = load_builtin_attacks(config.categories)

    if config.extra_tests_file:
        test_cases.extend(load_custom_attacks(config.extra_tests_file))

    # Set up target provider
    target = BaseProvider.create(config.provider, config.api_key, config.model)

    # Set up judge provider (can differ from target)
    judge: BaseProvider | None = None
    if config.use_judge:
        judge_api_key = config.judge_api_key or config.api_key
        judge_provider_name = config.judge_provider or config.provider
        judge_model = config.judge_model or config.model
        judge = BaseProvider.create(judge_provider_name, judge_api_key, judge_model)

    total_calls = 0
    total_tokens = 0

    for test_case in test_cases:
        # Enforce limits before starting a new test
        if config.max_calls is not None and total_calls >= config.max_calls:
            break
        if config.max_tokens is not None and total_tokens >= config.max_tokens:
            break

        # --- Step 1: Call the target model ---
        try:
            target_response = target.complete(
                system_prompt=config.system_prompt,
                user_message=test_case.prompt,
            )
        except Exception as e:
            total_calls += 1
            result = TestResult(
                test_case=test_case,
                raw_response=f"[ERROR] {e}",
                verdict=Verdict.UNCLEAR,
                severity=Severity.INFO,
                reasoning=f"Target API call failed: {e}",
                needs_review=True,
            )
            yield result, total_calls, total_tokens
            continue

        total_calls += 1
        total_tokens += target_response.tokens_used

        # --- Step 2: Keyword pre-filter ---
        flagged_keywords, keyword_vulnerable = evaluate_keywords(target_response.content)

        # --- Step 3: Judge LLM evaluation (or keyword-only fallback) ---
        if config.use_judge and judge is not None:
            verdict, severity, reasoning, judge_tokens = evaluate_with_judge(
                judge_provider=judge,
                system_prompt=config.system_prompt,
                attack_prompt=test_case.prompt,
                model_response=target_response.content,
                expected_behavior=test_case.expected_behavior,
            )
            total_calls += 1
            total_tokens += judge_tokens
        else:
            # Keyword-only verdict
            judge_tokens = 0
            if keyword_vulnerable:
                verdict = Verdict.PARTIAL
                severity = test_case.severity
                reasoning = f"Compliance keyword signals detected: {', '.join(flagged_keywords)}"
            elif flagged_keywords:
                verdict = Verdict.PARTIAL
                severity = Severity.LOW
                reasoning = f"Possible compliance signals found: {', '.join(flagged_keywords)}"
            else:
                verdict = Verdict.UNCLEAR
                severity = Severity.INFO
                reasoning = "No keyword signals detected. Manual review recommended (run without --no-judge for automated evaluation)."

        # Bump severity one level if keyword signals reinforce a PARTIAL verdict
        if keyword_vulnerable and verdict == Verdict.PARTIAL and severity == Severity.LOW:
            severity = Severity.MEDIUM

        needs_review = verdict in (Verdict.UNCLEAR, Verdict.PARTIAL)

        result = TestResult(
            test_case=test_case,
            raw_response=target_response.content,
            verdict=verdict,
            severity=severity,
            reasoning=reasoning,
            tokens_used=target_response.tokens_used + judge_tokens,
            flagged_keywords=flagged_keywords,
            needs_review=needs_review,
        )

        yield result, total_calls, total_tokens
