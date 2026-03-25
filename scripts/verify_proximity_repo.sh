#!/usr/bin/env bash
# Proximity Verification Script (Repo)
# Runs Trivy on this repo (excluding test-repos) and summarizes proximity output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TRIVY_JSON="$SCRIPT_DIR/verify_proximity_repo_trivy.json"
RESULTS_JSON="$SCRIPT_DIR/verify_proximity_repo_output.json"
SUMMARY_FILE="$SCRIPT_DIR/verify_proximity_repo_output.txt"

echo "=== VulnTriage Repo Proximity Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

if ! command -v trivy >/dev/null 2>&1; then
    echo "ERROR: trivy is not installed"
    echo "Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    exit 1
fi
# SECURITY: Block compromised Trivy >= v0.69.4 (TeamPCP supply chain attack, 2026-03-19)
# Safe versions: v0.69.3 and earlier. v0.69.4+ are compromised or unverified.
# See: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
TRIVY_VER=$(trivy --version 2>/dev/null | grep -oP 'Version: \K[0-9.]+' || true)
if [[ -n "$TRIVY_VER" ]] && printf '%s\n' "0.69.4" "$TRIVY_VER" | sort -V | head -n1 | grep -q "0.69.4"; then
    echo "❌ ERROR: Trivy version v${TRIVY_VER} is compromised or unverified. Aborting."
    echo "Install v0.69.3 or earlier: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23"
    exit 1
fi

if [ ! -f "uv.lock" ]; then
    echo "ERROR: uv.lock not found in repo root"
    exit 1
fi

SCAN_CMD=()
if command -v uv >/dev/null 2>&1; then
    SCAN_CMD=(uv run vulntriage scan)
elif command -v vulntriage >/dev/null 2>&1; then
    SCAN_CMD=(vulntriage scan)
else
    SCAN_CMD=(python3 -m vulntriage scan)
fi

PY_CMD=(python3)
if command -v uv >/dev/null 2>&1; then
    PY_CMD=(uv run python)
fi

echo "--- Lockfile graph summary (uv.lock) ---"
"${PY_CMD[@]}" - <<'PY' | tee "$SUMMARY_FILE"
from pathlib import Path

from vulntriage.dependency_graph import build_dependency_graph

graph = build_dependency_graph(Path("."), lockfile=Path("uv.lock"), include_dev=False)
if graph is None:
    print("No dependency graph built from uv.lock.")
    raise SystemExit(1)

direct = len(graph.direct)
total = len(graph.all_packages)
transitive = max(total - direct, 0)

print(f"Direct packages: {direct}")
print(f"Transitive packages: {transitive}")
print(f"Total packages: {total}")

if graph.direct:
    sample = ", ".join(sorted(graph.direct)[:10])
    print(f"Direct sample: {sample}")

transitive_pkgs = sorted(graph.all_packages - graph.direct)[:10]
if transitive_pkgs:
    print(f"Transitive sample: {', '.join(transitive_pkgs)}")
PY

echo "" | tee -a "$SUMMARY_FILE"

echo "--- Running Trivy scan (excluding test-repos) ---"
trivy fs --scanners vuln --format json --output "$TRIVY_JSON" --skip-dirs test-repos .

echo "--- Running VulnTriage ---"
"${SCAN_CMD[@]}" \
  --trivy-json "$TRIVY_JSON" \
  --src . \
  --lockfile uv.lock \
  --no-enrich \
  --json \
  > "$RESULTS_JSON"

echo "--- Proximity summary ---"
"${PY_CMD[@]}" - <<'PY' | tee -a "$SUMMARY_FILE"
import json
from collections import Counter
from pathlib import Path

results_path = Path("scripts/verify_proximity_repo_output.json")
data = json.loads(results_path.read_text(encoding="utf-8"))

print(f"Total vulnerabilities: {len(data)}")
if not data:
    print("No vulnerabilities found. Proximity summary is empty.")
    raise SystemExit(0)

counts = {"direct": 0, "transitive": 0, "none": 0}
null_pkgs = Counter()

for r in data:
    prox = r.get("proximity")
    if prox is None:
        counts["none"] += 1
        null_pkgs[r.get("pkg_name", "unknown")] += 1
    else:
        counts[prox] += 1

print("Proximity counts:")
print(f"  direct:     {counts['direct']}")
print(f"  transitive: {counts['transitive']}")
print(f"  none:       {counts['none']}")

print("")
print("Legend:")
print("  direct     = package is a direct dependency (pyproject.toml)")
print("  transitive = package appears only in the lockfile graph")
print("  none       = package not found in lockfile graph (name mismatch or non-Python)")

if null_pkgs:
    print("")
    print("Top null packages:")
    for name, count in null_pkgs.most_common(10):
        print(f"  {count:>3}  {name}")
PY

echo ""
echo "JSON saved to: $RESULTS_JSON"
echo "Summary saved to: $SUMMARY_FILE"
