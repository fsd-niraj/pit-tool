"""Load and manage test cases from YAML files."""
import yaml
from pathlib import Path

from core.models import TestCase, Category, Severity

ATTACKS_DIR = Path(__file__).parent

BUILTIN_FILES: dict[Category, str] = {
    Category.DIRECT_INJECTION: "direct_injection.yaml",
    Category.ROLE_HIJACKING: "role_hijacking.yaml",
    Category.DATA_EXFILTRATION: "data_exfiltration.yaml",
    Category.JAILBREAK: "jailbreak.yaml",
    Category.CONTEXT_ESCAPE: "context_escape.yaml",
    Category.INDIRECT_INJECTION: "indirect_injection.yaml",
}


def _parse_attack(raw: dict, category: Category) -> TestCase:
    return TestCase(
        id=raw["id"],
        category=Category(raw.get("category", category.value)),
        name=raw["name"],
        prompt=raw["prompt"],
        expected_behavior=raw["expected_behavior"],
        severity=Severity(raw.get("severity", "medium")),
        tags=raw.get("tags", []),
    )


def load_builtin_attacks(categories: list[str] | None = None) -> list[TestCase]:
    """Load built-in attack test cases, optionally filtered by category."""
    test_cases: list[TestCase] = []

    for category, filename in BUILTIN_FILES.items():
        if categories and category.value not in categories:
            continue

        filepath = ATTACKS_DIR / filename
        if not filepath.exists():
            continue

        with open(filepath) as f:
            data = yaml.safe_load(f)

        for raw in data.get("attacks", []):
            test_cases.append(_parse_attack(raw, category))

    return test_cases


def load_custom_attacks(filepath: str) -> list[TestCase]:
    """Load custom attack test cases from a user-provided YAML file."""
    with open(filepath) as f:
        data = yaml.safe_load(f)

    test_cases: list[TestCase] = []
    for raw in data.get("attacks", []):
        # custom files must specify category; default to context_escape
        category = Category(raw.get("category", "context_escape"))
        test_cases.append(_parse_attack(raw, category))

    return test_cases
