# VulnTriage

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
<!-- [![Tests](https://github.com/ddamme05/VulnTriage/actions/workflows/test.yml/badge.svg)](https://github.com/ddamme05/VulnTriage/actions/workflows/test.yml) -->
<!-- [![PyPI version](https://badge.fury.io/py/vulntriage.svg)](https://badge.fury.io/py/vulntriage) -->

**Democratizing reachability analysis for vulnerability triage.**

VulnTriage bridges the gap between "Vulnerable Package" and "Exploitable Code," turning a list of 500 scanner alerts into a focused list of actionable tasks.

## Overview

Security scanners like Trivy generate too many CVEs to manually triage. Most are false positives because vulnerable code paths are never executed. VulnTriage filters noise by detecting whether vulnerable packages show **static usage evidence** in your codebase.

> **Static usage evidence:** An import of the vulnerable module **plus** at least one usage signal (call, attribute access, instantiation) in included files.

## Features

- **Tree-sitter Parsing**: Fast, fault-tolerant import and usage detection
- **Package Name Resolution**: Handles PyPI → import name mapping (e.g., `Pillow` → `PIL`)
- **LLM-Assisted Analysis**: GPT-4o provides confidence scoring and reasoning (advisory only)
- **Prioritization**: Ranks findings by CVSS severity and usage evidence strength
- **Fail-Closed Safety**: Uncertain findings default to `needs_review`, never auto-dismissed
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
export OPENAI_API_KEY="sk-..."
uv run vulntriage scan --trivy-json trivy.json --src .
```

### CLI Commands

```bash
uv run vulntriage --help        # Show all commands
uv run vulntriage version       # Show version
uv run vulntriage scan --help   # Scan options
```

## Architecture

| Component | Tech | Role |
|-----------|------|------|
| Scanner | Trivy | Finds CVEs in dependencies |
| Parser | Tree-sitter | Finds imports and call sites |
| Engine | Python + Pydantic | Orchestrates analysis |
| Analyst | GPT-4o | Confidence scoring (advisory) |
| UI | Typer + Rich | CLI experience |

## Classification

VulnTriage outputs three statuses:

| Status | Meaning |
|--------|---------|
| `actionable` | Clear static usage evidence found |
| `needs_review` | Evidence exists but ambiguous/incomplete |
| `dismissed` | No import evidence in scanned files |

**Key invariant:** `dismissed` requires positive evidence of absence. Prioritization signals (CVSS, EPSS, KEV) affect ordering only, never the dismissal bar.

## Safety Attestations

- **Fail-closed by design**: Parse failures, timeouts, and ambiguous mappings → `needs_review`
- **No silent fallbacks**: Token-scan fallback emits structured warnings
- **Coordinates-only evidence**: LLM outputs file/line refs, snippets read from disk
- **LLM is advisory**: Classification is rule-based; LLM provides reasoning only
- **Excluded paths are invisible**: Filtered before parsing, never contribute to dismissal

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- [Trivy](https://trivy.dev/) vulnerability scanner
- OpenAI API key (for LLM analysis)

## Development

### Running Tests

```bash
uv run pytest
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
