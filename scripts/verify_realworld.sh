#!/usr/bin/env bash
# Real-World Verification Script
# Uses PyGoat vulnerable Python repo to verify VulnTriage determinism and sorting.
#
# Prerequisites:
# - trivy installed
# - test-repos/pygoat cloned (run: git clone https://github.com/adeyosemanputra/pygoat test-repos/pygoat)
# - test-repos/pygoat-trivy.json generated (run: trivy fs --scanners vuln --format json --quiet test-repos/pygoat > test-repos/pygoat-trivy.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== VulnTriage Real-World Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

# Check prerequisites
if [ ! -d "test-repos/pygoat" ]; then
    echo "--- Cloning PyGoat (Vulnerable Python Web Application) ---"
    mkdir -p test-repos
    git clone --depth 1 https://github.com/adeyosemanputra/pygoat.git test-repos/pygoat 2>&1 | grep -v "^remote:" || true
fi

if [ ! -f "test-repos/pygoat-trivy.json" ]; then
    echo "--- Running Trivy scan on PyGoat ---"
    if ! command -v trivy &> /dev/null; then
        echo "❌ ERROR: trivy is not installed"
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
    trivy fs --scanners vuln --format json --quiet test-repos/pygoat 2>/dev/null > test-repos/pygoat-trivy.json
fi

VULN_COUNT=$(python3 -c "
import json
with open('test-repos/pygoat-trivy.json') as f:
    data = json.load(f)
count = sum(len(r.get('Vulnerabilities') or []) for r in data.get('Results', []))
print(count)
")

echo "PyGoat has $VULN_COUNT vulnerabilities"
echo ""

echo "=== Trivy Report Sample (first 10 vulnerabilities) ==="
python3 -c "
import json
with open('test-repos/pygoat-trivy.json') as f:
    data = json.load(f)
count = 0
for r in data.get('Results', []):
    vulns = r.get('Vulnerabilities') or []
    for v in vulns:
        if count >= 10:
            break
        print(f\"{v['VulnerabilityID']:22} {v['PkgName']:18} {v['Severity']:10} {v.get('InstalledVersion', 'N/A')}\")
        count += 1
    if count >= 10:
        break
"

if [ "$VULN_COUNT" -eq 0 ]; then
    echo "❌ ERROR: No vulnerabilities found - regenerate Trivy report"
    exit 1
fi

TRIVY_JSON="test-repos/pygoat-trivy.json"
SRC_DIR="test-repos/pygoat"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo ""
echo "=== Running VulnTriage (3 runs for determinism) ==="

echo ""
echo "--- Run 1 ---"
uv run vulntriage scan --trivy-json "$TRIVY_JSON" --src "$SRC_DIR" --json > "$TEMP_DIR/run1.json" 2> "$TEMP_DIR/run1.log"
python3 -c "
import json
with open('$TEMP_DIR/run1.json') as f:
    results = json.load(f)
print(f'  Results: {len(results)} vulnerabilities')
for r in results[:5]:
    evidence = len(r.get('evidence', []))
    epss = f\"{r.get('epss_score', 0) or 0:.1%}\" if r.get('epss_score') is not None else '-'
    kev = '🔥' if r.get('is_kev') else '  '
    print(f\"  {kev} {r['status']:12} {r['severity']:10} {r['vuln_id']:22} {r['pkg_name']:15} evidence={evidence}\")
print('  ...')
"

echo ""
echo "--- Run 2 ---"
uv run vulntriage scan --trivy-json "$TRIVY_JSON" --src "$SRC_DIR" --json > "$TEMP_DIR/run2.json" 2> "$TEMP_DIR/run2.log"
python3 -c "
import json
with open('$TEMP_DIR/run2.json') as f:
    results = json.load(f)
print(f'  Results: {len(results)} vulnerabilities')
for r in results[:5]:
    evidence = len(r.get('evidence', []))
    print(f\"     {r['status']:12} {r['severity']:10} {r['vuln_id']:22} {r['pkg_name']:15} evidence={evidence}\")
print('  ...')
"

echo ""
echo "--- Run 3 ---"
uv run vulntriage scan --trivy-json "$TRIVY_JSON" --src "$SRC_DIR" --json > "$TEMP_DIR/run3.json" 2> "$TEMP_DIR/run3.log"
python3 -c "
import json
with open('$TEMP_DIR/run3.json') as f:
    results = json.load(f)
print(f'  Results: {len(results)} vulnerabilities')
for r in results[:5]:
    evidence = len(r.get('evidence', []))
    print(f\"     {r['status']:12} {r['severity']:10} {r['vuln_id']:22} {r['pkg_name']:15} evidence={evidence}\")
print('  ...')
"

echo ""
echo "=== Comparing Outputs ==="

DIFF_1_2=$(diff "$TEMP_DIR/run1.json" "$TEMP_DIR/run2.json" || true)
DIFF_2_3=$(diff "$TEMP_DIR/run2.json" "$TEMP_DIR/run3.json" || true)

if [ -z "$DIFF_1_2" ] && [ -z "$DIFF_2_3" ]; then
    echo "✅ PASSED: All 3 runs produced identical output"
else
    echo "❌ FAILED: Outputs differ between runs"
    echo ""
    echo "Diff run1 vs run2:"
    echo "$DIFF_1_2"
    echo ""
    echo "--- Stderr logs ---"
    cat "$TEMP_DIR/run1.log" "$TEMP_DIR/run2.log" "$TEMP_DIR/run3.log"
    exit 1
fi

echo ""
echo "=== Testing Risk-Based Sorting (--prioritize-risk) ==="

echo ""
echo "--- Default sort ---"
uv run vulntriage scan --trivy-json "$TRIVY_JSON" --src "$SRC_DIR" --json 2>/dev/null > "$TEMP_DIR/default.json"
python3 -c "
import json
with open('$TEMP_DIR/default.json') as f:
    results = json.load(f)
for r in results[:5]:
    kev = '🔥' if r.get('is_kev') else '  '
    epss = f\"{r.get('epss_score', 0) or 0:.1%}\" if r.get('epss_score') is not None else '-'
    print(f\"  {kev} {r['severity']:10} EPSS:{epss:>6}  {r['vuln_id']:22} {r['status']}\")
"

echo ""
echo "--- Risk sort ---"
uv run vulntriage scan --trivy-json "$TRIVY_JSON" --src "$SRC_DIR" --prioritize-risk --json 2>/dev/null > "$TEMP_DIR/risk.json"
python3 -c "
import json
with open('$TEMP_DIR/risk.json') as f:
    results = json.load(f)
for r in results[:5]:
    kev = '🔥' if r.get('is_kev') else '  '
    epss = f\"{r.get('epss_score', 0) or 0:.1%}\" if r.get('epss_score') is not None else '-'
    print(f\"  {kev} {r['severity']:10} EPSS:{epss:>6}  {r['vuln_id']:22} {r['status']}\")
"

echo ""
echo "=== Summary ==="
RESULT_COUNT=$(python3 -c "import json; print(len(json.load(open('$TEMP_DIR/run1.json'))))")
ACTIONABLE=$(python3 -c "import json; print(sum(1 for r in json.load(open('$TEMP_DIR/run1.json')) if r['status']=='actionable'))")
NEEDS_REVIEW=$(python3 -c "import json; print(sum(1 for r in json.load(open('$TEMP_DIR/run1.json')) if r['status']=='needs_review'))")
DISMISSED=$(python3 -c "import json; print(sum(1 for r in json.load(open('$TEMP_DIR/run1.json')) if r['status']=='dismissed'))")

echo "Total vulnerabilities: $RESULT_COUNT"
echo "  🔴 Actionable:   $ACTIONABLE"
echo "  🟡 Needs Review: $NEEDS_REVIEW"
echo "  🟢 Dismissed:    $DISMISSED"

# Show any warnings
if [ -s "$TEMP_DIR/run1.log" ]; then
    echo ""
    echo "--- Warnings/Errors ---"
    cat "$TEMP_DIR/run1.log"
fi

echo ""
echo "=== All Tests Passed ==="
