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

- **Zero-config workflow**: auto-discovers inputs, supports `pyproject.toml` / `.vulntriage.toml`
- **Evidence-based classification**: imports + call sites drive status
- **Fail-closed by default**: uncertainty → `needs_review`, never auto-dismissed
- **Offline-first**: no network calls unless you explicitly refresh or enable AI
- **Threat intel enrichment**: EPSS/KEV for risk-aware ordering (cache + refresh)
- **Strict mode**: prevents dismissals if any files are skipped
- **Direct vs transitive detection**: lockfile-based proximity for safer triage
- **VEX exports**: CycloneDX VEX 1.5 and OpenVEX 0.2.0
- **Optional function-level matching**: CVE → function map (opt-in)
- **Optional AI advisory**: analysis only, never changes classification
- **Deterministic output**: stable JSON for CI/diffing

## Quickstart

### 1) Generate a Trivy report

```bash
trivy fs --scanners vuln --format json --output trivy.json .
```

### 2) Run VulnTriage

```bash
uv run vulntriage scan --trivy-json trivy.json --src .
```

Or, if you have a config file (see below), just:

```bash
uv run vulntriage scan
```

## Configuration

VulnTriage supports project-level configuration so you don't have to pass the
same flags every time. Drop a config file in your repo and `vulntriage scan`
picks it up automatically.

### Config file formats

**Option A — `pyproject.toml`** (recommended for Python projects):

```toml
[tool.vulntriage]
trivy_json = "trivy.json"
src = "."
lockfile = "uv.lock"
include_dev = true
proximity = true
enrich = true
```

**Option B — `.vulntriage.toml`** (standalone, any project):

```toml
[scan]
trivy-json = "trivy.json"
src = "."
include-dev = true
json = true
```

Both formats support all CLI flags. Key names are normalized (dashes and
underscores are interchangeable, `json` maps to `--json`).

### Resolution order

Every option follows a 4-tier precedence (highest wins):

| Priority | Source | Example |
|----------|--------|---------|
| 1 | CLI flag | `--trivy-json report.json` |
| 2 | Environment variable | `TRIVY_JSON=report.json` |
| 3 | Config file | `trivy_json = "report.json"` |
| 4 | Auto-discovery / default | Finds `trivy.json` in repo root |

Environment variables:
- `TRIVY_JSON` — Trivy report path
- `VULNTRIAGE_LOCKFILE` — lockfile override
- `VULNTRIAGE_OFFLINE` — disable network access

### Dry run

Use `--dry-run` to see where every resolved value came from without running the scan:

```bash
uv run vulntriage scan --dry-run
```

```
VulnTriage - Dry Run
  Trivy JSON: /path/to/trivy.json (config:.vulntriage.toml)
  Source:     /path/to/src (config:.vulntriage.toml)
  Lockfile:   /path/to/uv.lock (auto)
  Proximity:  enabled (default)
  JSON:       off (default)
```

The `(config:...)`, `(auto)`, `(cli)`, and `(default)` labels show exactly
where each value was resolved from.

### Config file discovery

VulnTriage walks **up** the directory tree from your working directory to find
the config, so it works from any subdirectory. If both `pyproject.toml` and
`.vulntriage.toml` exist and have conflicting keys, `pyproject.toml` wins and
a warning is printed.

## Usage cookbook

### JSON output (CI-friendly)

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --json > results.json
```

Force table output when piping:

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --no-json
```

### Fail-closed strict mode

```bash
uv run vulntriage scan --trivy-json trivy.json --src . --strict
```

### Dependency proximity (direct vs transitive)

By default, VulnTriage attempts to detect dependency proximity from lockfiles.
You can override or disable it:

```bash
# Explicit lockfile
uv run vulntriage scan --trivy-json trivy.json --src . --lockfile poetry.lock

# Disable proximity detection
uv run vulntriage scan --trivy-json trivy.json --src . --no-proximity

# Include dev/optional dependency groups in proximity
uv run vulntriage scan --trivy-json trivy.json --src . --include-dev
```

### Proximity verification (this repo)

Run a repo-only check that prints a lockfile graph summary (direct vs transitive)
and a vulnerability proximity summary (if any CVEs are found):

```bash
./scripts/verify_proximity_repo.sh
```

If Trivy finds 0 vulnerabilities, the proximity summary will be empty; the
lockfile graph summary still validates direct vs transitive mapping.

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

### Custom ignore rules (for consumers)

Create a `.vulntriageignore` file at repo root to add or override ignore patterns.
It uses **gitignore-style** syntax (via `pathspec`) and is applied after the defaults.

Example:

```
# Ignore generated code
generated/

# Re-include tests (override default excludes)
!tests/
!test_*.py
```

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
