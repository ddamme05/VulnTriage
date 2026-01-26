# VulnTriage

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Reachability-focused vulnerability triage for Python projects.**

VulnTriage bridges the gap between "vulnerable package" and "exploitable code" by
checking for static usage evidence in your codebase. It turns a long scanner report
into a smaller, auditable set of actionable findings.

## What it does

- Parses your Trivy JSON report and deduplicates findings
- Scans your source code for imports and call sites (Tree-sitter)
- Classifies each CVE as `actionable`, `needs_review`, or `dismissed`
- Enriches with EPSS/KEV for risk-based sorting (offline-first)
- Optional CycloneDX VEX export
- Optional AI advisory analysis (does not change classification)

## What it does not do

| Claim | Reality |
|-------|---------|
| Full exploitability analysis | We detect static usage, not runtime reachability |
| Runtime telemetry | No execution traces, instrumentation, or profiling |
| 100% accurate package mapping | Namespace packages and edge cases exist |
| Replacement for security review | We filter noise; humans make final decisions |
| SAST/DAST tool | We triage scanner output, not scan for new vulns |

## Quickstart

### 1) Generate a Trivy report

```bash
trivy fs . --format json --output trivy.json
```

### 2) Run VulnTriage

```bash
uv run vulntriage scan --trivy-json trivy.json --src .
```

### 3) Optional: risk-based sorting

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --prioritize-risk
```

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

## Core features

- **Tree-sitter parsing**: Fast, fault-tolerant import and call site detection
- **Package name resolution**: Handles PyPI to import mapping (e.g., `Pillow` -> `PIL`)
- **Alias resolution**: Tracks `import X as Y` and `from X import Y` patterns
- **Wildcard/dynamic import detection**: Flags `from X import *` and `importlib.import_module()`
- **Fail-closed safety**: Uncertain findings default to `needs_review`, never auto-dismissed
- **Deterministic output**: Stable JSON for CI and diffing

## Enrichment and prioritization

- **EPSS/KEV enrichment** (offline-first)
  - Bundled fallback data
  - Cache + `--refresh` to update
  - Custom data paths with `--epss-file` and `--kev-file`
- **Risk sorting**: `--prioritize-risk`
  - KEV first, then EPSS (if present), then severity

## VEX export

Produce CycloneDX VEX 1.5 output:

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --output-vex out.vex.json
```

## Function-level matching (optional)

Use a CVE -> function map to require a vulnerable function call before marking `actionable`.

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --cve-function-map path/to/map.json
```

Safety-first behavior:
- If a map exists and a matching call is found -> `actionable`
- If a map exists but no match -> `needs_review` (never auto-dismissed)
- If no map exists -> current behavior unchanged

## AI advisory (optional)

AI analysis is advisory only. It never changes classification.

```bash
export OPENAI_API_KEY="sk-..."
uv run vulntriage scan --trivy-json trivy.json --src . --ai --ai-limit 25
```

Controls:
- `--ai-limit N` caps cost per run
- `--ai-context-lines N` controls snippet size
- `--ai-cache PATH` enables caching
- `--ai-redact/--no-ai-redact` toggles secret redaction

## CLI overview

```bash
uv run vulntriage --help
uv run vulntriage scan --help
uv run vulntriage scan --json
uv run vulntriage scan --strict
```

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
