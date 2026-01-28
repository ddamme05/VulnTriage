# VulnTriage

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Reachability-focused vulnerability triage for Python projects.**

VulnTriage turns a long scanner report into a smaller, auditable set of findings by
checking for **static usage evidence** in your codebase. It does not change scanner
results; it classifies them into **actionable**, **needs_review**, or **dismissed**
with evidence and reasons you can inspect.

> **Python-only for now.** VulnTriage uses tree-sitter for AST parsing; other language
> grammars (Go, JavaScript, Java, etc.) are not yet integrated.

## Why this exists

Scanner output is noisy. VulnTriage focuses on **evidence-backed reachability**,
so teams can prioritize fixes that are actually relevant to their code.

## Standout features

- **Evidence-based classification**: imports + call sites drive status
- **Fail-closed by default**: uncertainty → `needs_review`, never auto-dismissed
- **Offline-first**: no network calls unless you explicitly refresh or enable AI
- **Threat intel enrichment**: EPSS/KEV for risk-aware ordering (cache + refresh)
- **Strict mode**: prevents dismissals if any files are skipped
- **VEX exports**: CycloneDX VEX 1.5 and OpenVEX 0.2.0
- **Optional function-level matching**: CVE → function map (opt-in)
- **Optional AI advisory**: analysis only, never changes classification
- **Deterministic output**: stable JSON for CI/diffing

## Quickstart

### 1) Generate a Trivy report

```bash
trivy fs . --format json --output trivy.json
```

### 2) Run VulnTriage

```bash
uv run vulntriage scan --trivy-json trivy.json --src .
```

### 3) Risk-based sorting (optional)

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --prioritize-risk
```

## Usage cookbook

### Minimal scan

```bash
uv run vulntriage scan --trivy-json trivy.json --src .
```

### JSON output (CI-friendly)

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --json > results.json
```

### Fail-closed strict mode

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --strict
```

### Offline-first workflow (security posture)

1) **Online refresh (one-time):**

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --refresh
```

2) **Offline runs (no network):**

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --offline
```

Offline guard:
- `--offline` (CLI flag)
- `VULNTRIAGE_OFFLINE=1` (environment variable)

Both prevent refresh/network calls and fail fast if a refresh is attempted.

### Custom EPSS/KEV files

```bash
uv run vulntriage scan --trivy-json trivy.json --src . \
  --epss-file /path/to/epss.csv \
  --kev-file /path/to/kev.json
```

### CycloneDX VEX export

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --output-vex out.vex.json
```

### OpenVEX export

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --output-openvex out.openvex.json
```

### CVE function matching (opt-in)

```bash
uv run vulntriage scan --trivy-json trivy.json --src . \
  --cve-function-map path/to/map.json
```

Bundled seed map (opt-in, community-contributed):
`src/vulntriage/data/cve_functions.json`

### AI advisory (optional)

```bash
export OPENAI_API_KEY="sk-..."
uv run vulntriage scan --trivy-json trivy.json --src . --ai --ai-limit 25
```

Controls:
- `--ai-limit N` caps cost per run
- `--ai-context-lines N` controls snippet size
- `--ai-cache PATH` enables caching
- `--ai-redact/--no-ai-redact` toggles secret redaction

## Example output

```
VulnTriage - Reachability Analysis
  Trivy report: trivy.json
  Source path:  .

Found 30 vulnerabilities:
  Actionable:   6
  Needs Review: 21
  Dismissed:    3

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
│ Status       │ Severity   │ CVE                │ Package       │ Evidence  │
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ ACTIONABLE   │ HIGH       │ CVE-2019-10906     │ jinja2@2.10   │ 1 call(s) │
│ REVIEW       │ HIGH       │ CVE-2024-23334     │ aiohttp@3.5.3 │ -         │
│ DISMISSED    │ CRITICAL   │ CVE-2020-14343     │ pyyaml@3.13   │ -         │
└──────────────┴────────────┴────────────────────┴───────────────┴───────────┘
```

## What it does not do

| Claim | Reality |
|-------|---------|
| Full exploitability analysis | Static usage evidence only (not runtime reachability) |
| Runtime telemetry | No instrumentation, tracing, or profiling |
| Replace security review | It reduces noise; humans decide risk |
| SAST/DAST | It triages existing scanner output |

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- [Trivy](https://trivy.dev/) vulnerability scanner

## Development

```bash
uv run pytest
uv run ruff check src/ tests/
uv run mypy src/ --strict
```

## Acknowledgments

VulnTriage consumes [Trivy](https://github.com/aquasecurity/trivy) JSON output.
Trivy is an open-source vulnerability scanner by [Aqua Security](https://www.aquasec.com/) (Apache-2.0 license).

## License

MIT
