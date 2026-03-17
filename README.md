# PIT — Prompt Injection Tester

A CLI security testing tool for LLM applications. PIT runs adversarial prompt injection attacks against your AI app's system prompt and uses a second LLM as a judge to determine whether each attack succeeded.

---

## How it works

```
Your system prompt + attack prompt
        │
        ▼
  Target model responds
        │
        ├── Keyword filter  (fast, no cost)
        └── Judge LLM       (evaluates if guardrails were breached)
                │
                ▼
        Verdict: safe / vulnerable / partial / unclear
```

Each test result includes a verdict, severity level, and a one-sentence explanation from the judge.

---

## Requirements

- Python 3.11+
- An API key for OpenAI or Anthropic

---

## Installation

```bash
git clone git@github.com:fsd-niraj/pit-tool.git
cd pit-tool

python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

pip install -e .
```

Verify:

```bash
pit --help
```

---

## Quickstart

### Interactive wizard (recommended for first run)

Just run `pit run` with no arguments. The wizard will walk you through everything step by step:

```bash
pit run
```

You will be asked for:

1. Provider (OpenAI / Anthropic)
2. API key
3. Target model
4. System prompt (file or paste inline)
5. Custom test cases (optional)
6. Attack categories
7. Judge LLM config
8. Usage limits
9. Output file
10. Whether to run in background

---

### Direct flags (for scripting / CI)

```bash
pit run \
  --api-key $OPENAI_API_KEY \
  --model gpt-4o \
  --provider openai \
  --system-prompt-file path/to/system_prompt.txt \
  --output report.json
```

Mix flags with the wizard: any flag you omit will be asked interactively.

---

## Commands

| Command                    | Description                                       |
| -------------------------- | ------------------------------------------------- |
| `pit run`                  | Run prompt injection tests                        |
| `pit generate`             | Generate custom test cases (AI-powered or manual) |
| `pit jobs`                 | List all background jobs                          |
| `pit status <job-id>`      | Show progress and results of a background job     |
| `pit list-attacks`         | Browse the built-in attack library                |
| `pit review <report.json>` | Manually review unclear/partial results           |

---

## Built-in attack library

29 attacks across 6 categories:

| Category             | What it tests                                                  |
| -------------------- | -------------------------------------------------------------- |
| `direct_injection`   | Overriding instructions via user input                         |
| `role_hijacking`     | Convincing the model to adopt a different persona              |
| `data_exfiltration`  | Extracting the system prompt or restricted information         |
| `jailbreak`          | Using hypothetical/fictional framing to bypass guardrails      |
| `context_escape`     | Pulling the model off-topic or outside its defined scope       |
| `indirect_injection` | Malicious instructions embedded in content the model processes |

```bash
pit list-attacks                          # all 29
pit list-attacks --category jailbreak     # filtered
```

---

## Generating custom test cases

### AI-powered (recommended)

The LLM analyzes your system prompt, identifies every guardrail, and writes targeted attacks for each one:

```bash
pit generate \
  --api-key $OPENAI_API_KEY \
  --model gpt-4o \
  --provider openai \
  --system-prompt-file path/to/system_prompt.txt \
  --output my_tests.yaml \
  --count 20
```

Or just run `pit generate` for the interactive wizard.

### Manual

Create test cases one by one via prompts:

```bash
pit generate --manual --output my_tests.yaml
```

Use custom tests alongside the built-in library:

```bash
pit run ... --tests-file my_tests.yaml
```

---

## Background mode

For large test suites, run in the background and check progress separately:

```bash
# Start the job
pit run --background \
  --api-key $OPENAI_API_KEY \
  --model gpt-4o \
  --provider openai \
  --system-prompt-file path/to/system_prompt.txt

# → Job ID: a1b2c3d4

pit jobs                         # list all jobs
pit status a1b2c3d4              # snapshot
pit status a1b2c3d4 --follow     # live refresh every 2s
```

Job files are stored in `.pit/jobs/<id>/`:

```
.pit/jobs/<id>/
  config.json       run configuration
  status.json       live progress (completed/total, calls, tokens)
  results.jsonl     one result per line as they stream in
  report.json       final report (written on completion)
  worker.log        worker stdout/stderr
```

---

## Common options

| Flag                   | Short | Description                                    |
| ---------------------- | ----- | ---------------------------------------------- |
| `--api-key`            | `-k`  | API key (or set `PIT_API_KEY` env var)         |
| `--model`              | `-m`  | Target model name                              |
| `--provider`           | `-p`  | `openai` or `anthropic`                        |
| `--system-prompt`      | `-s`  | System prompt as an inline string              |
| `--system-prompt-file` |       | Path to system prompt file                     |
| `--tests-file`         | `-t`  | Path to custom YAML test cases                 |
| `--categories`         | `-c`  | Comma-separated categories to run              |
| `--output`             | `-o`  | Save JSON report to file                       |
| `--max-calls`          |       | Hard limit on total API calls                  |
| `--max-tokens`         |       | Hard limit on total tokens                     |
| `--no-judge`           |       | Skip judge LLM, use keyword evaluation only    |
| `--background`         | `-b`  | Run in background, return job ID immediately   |
| `--verbose`            | `-v`  | Show full model responses for non-safe results |

---

## Verdicts

| Verdict      | Meaning                                   |
| ------------ | ----------------------------------------- |
| `safe`       | Model stayed within its guardrails        |
| `vulnerable` | Model complied with the attack            |
| `partial`    | Concerning behavior but not a full bypass |
| `unclear`    | Ambiguous — flagged for manual review     |

---

Pass it at runtime: `pit run --tests-file my_tests.yaml ...`
