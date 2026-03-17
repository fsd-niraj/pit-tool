"""Core data models for PIT."""
from enum import Enum
from datetime import datetime
from typing import Optional
import uuid

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    PARTIAL = "partial"
    UNCLEAR = "unclear"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    DIRECT_INJECTION = "direct_injection"
    ROLE_HIJACKING = "role_hijacking"
    DATA_EXFILTRATION = "data_exfiltration"
    JAILBREAK = "jailbreak"
    CONTEXT_ESCAPE = "context_escape"
    INDIRECT_INJECTION = "indirect_injection"


class TestCase(BaseModel):
    id: str
    category: Category
    name: str
    prompt: str
    expected_behavior: str
    severity: Severity
    tags: list[str] = []


class TestResult(BaseModel):
    test_case: TestCase
    raw_response: str
    verdict: Verdict
    severity: Severity
    reasoning: str
    tokens_used: int = 0
    flagged_keywords: list[str] = []
    needs_review: bool = False


class RunSummary(BaseModel):
    total: int
    safe: int
    vulnerable: int
    partial: int
    unclear: int
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}


class TestRunConfig(BaseModel):
    api_key: str
    model: str
    provider: str
    system_prompt: str
    judge_model: Optional[str] = None
    judge_provider: Optional[str] = None
    judge_api_key: Optional[str] = None
    max_calls: Optional[int] = None
    max_tokens: Optional[int] = None
    categories: Optional[list[str]] = None
    extra_tests_file: Optional[str] = None
    use_judge: bool = True


class TestRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    config: TestRunConfig
    results: list[TestResult] = []
    total_tokens: int = 0
    total_calls: int = 0
    summary: Optional[RunSummary] = None
