#!/usr/bin/env bash
# Sorting Verification Script
# Verifies that VulnTriage sorts results correctly with different flags.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== VulnTriage Sorting Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Create test fixtures with mixed severities and KEV/EPSS data
cat > "$TEMP_DIR/trivy.json" << 'EOF'
{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "requirements.txt",
      "Type": "pip",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-99999", "PkgName": "unknown-pkg", "InstalledVersion": "1.0.0", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j", "InstalledVersion": "2.14.0", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2023-00001", "PkgName": "requests", "InstalledVersion": "2.28.0", "Severity": "LOW"},
        {"VulnerabilityID": "CVE-2023-44487", "PkgName": "http2", "InstalledVersion": "1.0.0", "Severity": "MEDIUM"}
      ]
    }
  ]
}
EOF

mkdir -p "$TEMP_DIR/src"
echo "x = 1" > "$TEMP_DIR/src/app.py"

cd "$PROJECT_ROOT"

echo "--- Test 1: Default Sorting (by severity) ---"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --json 2> "$TEMP_DIR/default.log" > "$TEMP_DIR/default_sort.json"

echo "Expected order: CRITICAL -> HIGH -> MEDIUM -> LOW"
echo "Actual order:"
uv run python -c "
import json
with open('$TEMP_DIR/default_sort.json') as f:
    results = json.load(f)
for r in results:
    print(f\"  {r['severity']:10} {r['vuln_id']}\")
"

# Verify CRITICAL comes first
FIRST_SEVERITY=$(uv run python -c "
import json
with open('$TEMP_DIR/default_sort.json') as f:
    results = json.load(f)
print(results[0]['severity'] if results else 'NONE')
")

if [ "$FIRST_SEVERITY" = "CRITICAL" ]; then
    echo "✅ Default sort: CRITICAL first"
else
    echo "❌ Default sort failed: Expected CRITICAL first, got $FIRST_SEVERITY"
    exit 1
fi

echo ""
echo "--- Test 2: Risk-based Sorting (KEV -> EPSS -> severity) ---"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --prioritize-risk --json 2> "$TEMP_DIR/risk.log" > "$TEMP_DIR/risk_sort.json"

echo "Expected: KEV items first (CVE-2021-44228, CVE-2023-44487), then by EPSS"
echo "Actual order:"
uv run python -c "
import json
with open('$TEMP_DIR/risk_sort.json') as f:
    results = json.load(f)
for r in results:
    kev = '🔥' if r.get('is_kev') else '  '
    epss = f\"{r.get('epss_score', 0) or 0:.1%}\" if r.get('epss_score') is not None else '-'
    print(f\"  {kev} EPSS:{epss:>6} {r['severity']:10} {r['vuln_id']}\")
"

# Verify KEV item comes first
FIRST_KEV=$(uv run python -c "
import json
with open('$TEMP_DIR/risk_sort.json') as f:
    results = json.load(f)
print('true' if results and results[0].get('is_kev') else 'false')
")

if [ "$FIRST_KEV" = "true" ]; then
    echo "✅ Risk sort: KEV item first"
else
    echo "❌ Risk sort failed: Expected KEV item first"
    exit 1
fi

echo ""
echo "--- Test 3: Sorting Determinism (multiple runs with same flags) ---"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --prioritize-risk --json 2> "$TEMP_DIR/risk2.log" > "$TEMP_DIR/risk_sort_2.json"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --prioritize-risk --json 2> "$TEMP_DIR/risk3.log" > "$TEMP_DIR/risk_sort_3.json"

DIFF=$(diff "$TEMP_DIR/risk_sort.json" "$TEMP_DIR/risk_sort_2.json" || true)
if [ -z "$DIFF" ]; then
    echo "✅ Risk sort determinism: identical across runs"
else
    echo "❌ Risk sort determinism failed"
    echo "--- Stderr logs ---"
    cat "$TEMP_DIR/risk.log" "$TEMP_DIR/risk2.log" "$TEMP_DIR/risk3.log"
    exit 1
fi

echo ""
echo "=== All Sorting Tests Passed ==="

# Show any warnings if present
if [ -s "$TEMP_DIR/default.log" ]; then
    echo ""
    echo "--- Warnings/Errors (stderr) ---"
    cat "$TEMP_DIR/default.log"
fi
