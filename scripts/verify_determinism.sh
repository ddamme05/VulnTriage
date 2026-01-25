#!/usr/bin/env bash
# Determinism Verification Script
# Runs VulnTriage multiple times and compares outputs to ensure identical results.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== VulnTriage Determinism Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Create test fixtures
cat > "$TEMP_DIR/trivy.json" << 'EOF'
{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "requirements.txt",
      "Type": "pip",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-00003", "PkgName": "urllib3", "InstalledVersion": "1.26.0", "Severity": "MEDIUM"},
        {"VulnerabilityID": "CVE-2023-00001", "PkgName": "requests", "InstalledVersion": "2.28.0", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2023-00002", "PkgName": "flask", "InstalledVersion": "2.0.0", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j", "InstalledVersion": "2.14.0", "Severity": "CRITICAL"}
      ]
    }
  ]
}
EOF

mkdir -p "$TEMP_DIR/src"
cat > "$TEMP_DIR/src/app.py" << 'EOF'
import requests
import flask
from flask import Flask

app = Flask(__name__)
requests.get("https://example.com")
EOF

echo "--- Run 1 ---"
cd "$PROJECT_ROOT"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --json > "$TEMP_DIR/run1.json" 2> "$TEMP_DIR/run1.log"

echo "--- Run 2 ---"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --json > "$TEMP_DIR/run2.json" 2> "$TEMP_DIR/run2.log"

echo "--- Run 3 ---"
uv run vulntriage scan --trivy-json "$TEMP_DIR/trivy.json" --src "$TEMP_DIR/src" --json > "$TEMP_DIR/run3.json" 2> "$TEMP_DIR/run3.log"

echo ""
echo "=== Comparing Outputs ==="

# Compare all runs
DIFF_1_2=$(diff "$TEMP_DIR/run1.json" "$TEMP_DIR/run2.json" || true)
DIFF_2_3=$(diff "$TEMP_DIR/run2.json" "$TEMP_DIR/run3.json" || true)
DIFF_1_3=$(diff "$TEMP_DIR/run1.json" "$TEMP_DIR/run3.json" || true)

if [ -z "$DIFF_1_2" ] && [ -z "$DIFF_2_3" ] && [ -z "$DIFF_1_3" ]; then
    echo "✅ PASSED: All 3 runs produced identical output"
    echo ""
    echo "Output sample (first run):"
    cat "$TEMP_DIR/run1.json"
    
    # Show any warnings/errors if present
    if [ -s "$TEMP_DIR/run1.log" ]; then
        echo ""
        echo "--- Warnings/Errors (stderr) ---"
        cat "$TEMP_DIR/run1.log"
    fi
else
    echo "❌ FAILED: Outputs differ between runs"
    echo ""
    echo "Diff run1 vs run2:"
    echo "$DIFF_1_2"
    echo ""
    echo "Diff run2 vs run3:"
    echo "$DIFF_2_3"
    echo ""
    echo "--- Stderr logs ---"
    echo "Run 1:" && cat "$TEMP_DIR/run1.log"
    echo "Run 2:" && cat "$TEMP_DIR/run2.log"
    echo "Run 3:" && cat "$TEMP_DIR/run3.log"
    exit 1
fi
