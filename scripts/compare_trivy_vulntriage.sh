#!/usr/bin/env bash
# Trivy vs VulnTriage Comparison Script
# Compares raw Trivy vulnerability count against VulnTriage triage results.
#
# Prerequisites:
# - trivy installed
# - test-repos/pygoat cloned

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/compare_output.txt"

exec > >(tee "$OUTPUT_FILE") 2>&1

echo "=== Trivy vs VulnTriage Comparison ==="
echo "Date: $(date -Iseconds)"
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

if [ ! -d "test-repos/pygoat" ]; then
    echo "--- Cloning PyGoat ---"
    mkdir -p test-repos
    git clone --depth 1 https://github.com/adeyosemanputra/pygoat.git test-repos/pygoat 2>&1 | grep -v "^remote:" || true
fi

TRIVY_JSON="test-repos/pygoat-trivy.json"
SRC_DIR="test-repos/pygoat"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "--- Running Trivy scan ---"
if ! command -v trivy &> /dev/null; then
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
trivy fs --scanners vuln --format json --quiet "$SRC_DIR" 2>/dev/null > "$TRIVY_JSON"

echo "--- Running VulnTriage ---"
uv run vulntriage scan \
  --trivy-json "$TRIVY_JSON" \
  --src "$SRC_DIR" \
  --json \
  > "$TEMP_DIR/vulntriage.json" 2>/dev/null

echo ""
echo "=== Results ==="
echo ""

export TRIVY_JSON TEMP_DIR

uv run python - <<'PY'
import json
import os
from pathlib import Path

trivy_path = Path(os.environ["TRIVY_JSON"])
vt_path = Path(os.environ["TEMP_DIR"]) / "vulntriage.json"

# Parse Trivy
trivy_data = json.loads(trivy_path.read_text(encoding="utf-8"))
trivy_vulns = []
for result in trivy_data.get("Results", []):
    trivy_vulns.extend(result.get("Vulnerabilities", []))

trivy_by_sev = {}
for v in trivy_vulns:
    sev = v.get("Severity", "UNKNOWN")
    trivy_by_sev[sev] = trivy_by_sev.get(sev, 0) + 1

# Parse VulnTriage
vt_data = json.loads(vt_path.read_text(encoding="utf-8"))
vt_by_status = {"actionable": 0, "needs_review": 0, "dismissed": 0}
vt_by_sev = {}
for r in vt_data:
    vt_by_status[r["status"]] = vt_by_status.get(r["status"], 0) + 1
    sev = r.get("severity", "UNKNOWN")
    vt_by_sev[sev] = vt_by_sev.get(sev, 0) + 1

total_trivy = len(trivy_vulns)
total_vt = len(vt_data)
actionable = vt_by_status["actionable"]
needs_review = vt_by_status["needs_review"]
dismissed = vt_by_status["dismissed"]

print("TRIVY (raw)")
print(f"  Total vulnerabilities: {total_trivy}")
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
    if trivy_by_sev.get(sev, 0) > 0:
        print(f"    {sev}: {trivy_by_sev[sev]}")
print()

print("VULNTRIAGE (triaged)")
print(f"  Total vulnerabilities: {total_vt}")
print(f"    Actionable:   {actionable}")
print(f"    Needs Review: {needs_review}")
print(f"    Dismissed:    {dismissed}")
print()

print("TRIAGE VALUE")
if total_trivy > 0:
    reduction = ((dismissed) / total_trivy) * 100
    focus = ((actionable + needs_review) / total_trivy) * 100
    print(f"  Dismissed (noise reduction): {dismissed}/{total_trivy} ({reduction:.1f}%)")
    print(f"  Requires attention:          {actionable + needs_review}/{total_trivy} ({focus:.1f}%)")
else:
    print("  No vulnerabilities to compare")

print()
print("EVIDENCE HEALTH CHECK")
actionable_with_evidence = sum(1 for r in vt_data if r["status"] == "actionable" and r.get("evidence"))
actionable_without_evidence = sum(1 for r in vt_data if r["status"] == "actionable" and not r.get("evidence"))
dismissed_with_evidence = sum(1 for r in vt_data if r["status"] == "dismissed" and r.get("evidence"))
print(f"  Actionable with evidence:    {actionable_with_evidence}")
print(f"  Actionable without evidence: {actionable_without_evidence}")
print(f"  Dismissed with evidence:     {dismissed_with_evidence}")


def _sample(rows, n=5):
    return rows[:n]


def _print_sample(label, rows):
    print()
    print(label)
    for r in rows:
        evidence = r.get("evidence") or []
        if evidence:
            first = evidence[0]
            ev = f"{first.get('file_path')}:{first.get('line_start')} {first.get('symbol_name')}"
        else:
            ev = "no-evidence"
        reason = r.get("reason", "").replace("\n", " ")
        if len(reason) > 120:
            reason = reason[:117] + "..."
        version = r.get("installed_version", "unknown")
        print(f"  {r['status']:12} {r.get('severity','UNKNOWN'):9} {r['vuln_id']:22} {r['pkg_name']:16} {version:10} {ev}")
        print(f"    reason: {reason}")


actionable_rows = [r for r in vt_data if r["status"] == "actionable"]
needs_review_rows = [r for r in vt_data if r["status"] == "needs_review"]
dismissed_rows = [r for r in vt_data if r["status"] == "dismissed"]

_print_sample("SAMPLE: Actionable (top 5)", _sample(actionable_rows))
_print_sample("SAMPLE: Needs Review (top 5)", _sample(needs_review_rows))
_print_sample("SAMPLE: Dismissed (top 5)", _sample(dismissed_rows))
PY

echo ""
echo "=== Comparison Complete ==="
echo "Output saved to: $OUTPUT_FILE"
