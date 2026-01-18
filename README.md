# VulnTriage

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Democratizing reachability analysis for vulnerability triage.**

VulnTriage bridges the gap between "Vulnerable Package" and "Exploitable Code," turning a list of 500 scanner alerts into a focused list of actionable tasks.

## Overview

Security scanners like Trivy generate too many CVEs to manually triage. Most are false positives because vulnerable code paths are never executed. VulnTriage filters noise by detecting whether vulnerable packages show **static usage evidence** in your codebase.

> **Static usage evidence:** An import of the vulnerable module **plus** at least one usage signal (call, attribute access, instantiation) in included files.

## Features

- **Tree-sitter Parsing**: Fast, fault-tolerant import and call site detection
- **Package Name Resolution**: Handles PyPI → import name mapping (e.g., `Pillow` → `PIL`)
- **Alias Resolution**: Tracks `import X as Y` and `from X import Y` patterns
- **Wildcard/Dynamic Import Detection**: Flags `from X import *` and `importlib.import_module()`
- **Fail-Closed Safety**: Uncertain findings default to `needs_review`, never auto-dismissed
- **Deterministic Output**: Reproducible JSON for CI integration
- **VEX Export Ready**: Designed for CycloneDX/OpenVEX integration (V2)

## What VulnTriage is NOT

| Claim | Reality |
|-------|---------|
| ❌ Full exploitability analysis | We detect static usage, not runtime reachability |
| ❌ Runtime telemetry | No execution traces, instrumentation, or profiling |
| ❌ 100% accurate package mapping | Namespace packages and edge cases exist |
| ❌ Replacement for security review | We filter noise; humans make final decisions |
| ❌ SAST/DAST tool | We triage scanner output, not scan for vulns |

## Installation

This project uses [uv](https://github.com/astral-sh/uv) for package management:

```bash
git clone https://github.com/ddamme05/VulnTriage.git
cd VulnTriage
uv sync
```

## Usage

### Generate Trivy Report

```bash
trivy fs . --format json --output trivy.json
```

### Run Triage

```bash
uv run vulntriage scan --trivy-json trivy.json --src .
```

### Output

```
VulnTriage - Reachability Analysis
  Trivy report: trivy.json
  Source path:  .

Found 30 vulnerabilities:
  🔴 Actionable:   6
  🟡 Needs Review: 21
  🟢 Dismissed:    3

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
│ Status       │ Severity   │ CVE                │ Package       │ Evidence  │
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ ACTIONABLE   │ HIGH       │ CVE-2019-10906     │ jinja2@2.10   │ 1 call(s) │
│ REVIEW       │ HIGH       │ CVE-2024-23334     │ aiohttp@3.5.3 │ -         │
│ DISMISSED    │ CRITICAL   │ CVE-2020-14343     │ pyyaml@3.13   │ -         │
└──────────────┴────────────┴────────────────────┴───────────────┴───────────┘
```

### CLI Commands

```bash
uv run vulntriage --help        # Show all commands
uv run vulntriage version       # Show version
uv run vulntriage scan --help   # Scan options
uv run vulntriage scan --json   # JSON output
```

## Architecture

| Component | Tech | Role |
|-----------|------|------|
| Scanner | Trivy | Finds CVEs in dependencies |
| Parser | Tree-sitter | Finds imports and call sites |
| Engine | Python + Pydantic | Orchestrates analysis |
| UI | Typer + Rich | CLI experience |

## Classification

VulnTriage outputs three statuses:

| Status | Meaning |
|--------|---------|
| `actionable` | Clear static usage evidence found (imports + calls) |
| `needs_review` | Evidence exists but ambiguous/incomplete |
| `dismissed` | No import evidence in scanned files |

**Key invariant:** `dismissed` requires positive evidence of absence. Prioritization signals (CVSS, EPSS, KEV) affect ordering only, never the dismissal bar.

## Safety Attestations

- **Fail-closed by design**: Parse failures, timeouts, and ambiguous mappings → `needs_review`
- **Wildcard/dynamic imports**: Force `needs_review` to prevent false dismissals
- **Coordinates-only evidence**: Store file/line refs, snippets read from disk
- **Excluded paths are invisible**: Filtered before parsing, never contribute to dismissal
- **Deterministic**: Same input → same output (sorted, reproducible)

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- [Trivy](https://trivy.dev/) vulnerability scanner

## Development

### Running Tests

```bash
uv run pytest                    # All tests
uv run pytest tests/test_integration.py -v  # Integration tests
```

### Linting

```bash
uv run ruff check src/ tests/
uv run mypy src/
```

## Acknowledgments

VulnTriage consumes [Trivy](https://github.com/aquasecurity/trivy)'s JSON output. Trivy is an open-source vulnerability scanner by [Aqua Security](https://www.aquasec.com/) (Apache-2.0 license).

## License

MIT
