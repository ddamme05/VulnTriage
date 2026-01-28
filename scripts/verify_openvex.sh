#!/usr/bin/env bash
# OpenVEX Verification Script
# Runs VulnTriage with --output-openvex and validates the OpenVEX output.
#
# Prerequisites:
# - trivy installed
# - test-repos/pygoat cloned (run: git clone https://github.com/adeyosemanputra/pygoat test-repos/pygoat)
# - test-repos/pygoat-trivy.json generated (run: trivy fs --scanners vuln --format json --quiet test-repos/pygoat > test-repos/pygoat-trivy.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/verify_openvex_output.txt"
OUTPUT_JSON="$SCRIPT_DIR/verify_openvex_output.json"
WRITE_OUTPUT=0

if ! touch "$OUTPUT_FILE" 2>/dev/null; then
    WRITE_OUTPUT=0
else
    exec > >(tee "$OUTPUT_FILE") 2>&1
    WRITE_OUTPUT=1
fi

echo "=== VulnTriage OpenVEX Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

if [ ! -d "test-repos/pygoat" ]; then
    echo "--- Cloning PyGoat ---"
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
    trivy fs --scanners vuln --format json --quiet test-repos/pygoat 2>/dev/null > test-repos/pygoat-trivy.json
fi

TRIVY_JSON="test-repos/pygoat-trivy.json"
SRC_DIR="test-repos/pygoat"
TEMP_DIR=$(mktemp -d 2>/dev/null || true)
if [ -z "$TEMP_DIR" ]; then
    echo "❌ ERROR: Unable to create temp directory."
    echo "Set TMPDIR to a writable path and retry (e.g., export TMPDIR=/path)."
    exit 1
fi
trap "rm -rf $TEMP_DIR" EXIT

OPENVEX_OUT="$TEMP_DIR/pygoat.openvex.json"
VT_CMD=(uv run vulntriage)
if [ -x "$PROJECT_ROOT/.venv/bin/vulntriage" ]; then
    VT_CMD=("$PROJECT_ROOT/.venv/bin/vulntriage")
fi

echo "--- Running VulnTriage with OpenVEX export ---"
"${VT_CMD[@]}" scan \
  --trivy-json "$TRIVY_JSON" \
  --src "$SRC_DIR" \
  --output-openvex "$OPENVEX_OUT" \
  --json \
  > "$TEMP_DIR/results.json" 2> "$TEMP_DIR/run.log"

if [ ! -s "$OPENVEX_OUT" ]; then
    echo "❌ ERROR: OpenVEX output file not created"
    exit 1
fi

echo "--- Validating OpenVEX structure ---"
python3 - "$OPENVEX_OUT" <<'PY'
import json
import sys
from pathlib import Path

openvex_path = Path(sys.argv[1])
try:
    data = json.loads(openvex_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as e:
    print(f"❌ Invalid JSON: {e}")
    sys.exit(1)

assert data.get("@context", "").startswith("https://openvex.dev/"), "Invalid @context"
assert data.get("version") == 1, "Invalid version"
assert "statements" in data, "Missing statements"

statements = data.get("statements") or []
print(f"Statements: {len(statements)}")
if not statements:
    print("⚠️  Warning: OpenVEX document is valid but empty (no statements).")
    sys.exit(1)

for i, stmt in enumerate(statements[:5]):
    vuln = stmt.get("vulnerability", {})
    products = stmt.get("products", [])
    if "name" not in vuln:
        print(f"❌ Statement {i} missing vulnerability name")
        sys.exit(1)
    if not products or "@id" not in products[0]:
        print(f"❌ Statement {i} missing product @id")
        sys.exit(1)
    if any(c.isupper() for c in products[0]["@id"]):
        print(f"❌ Product @id must be lowercase: {products[0]['@id']}")
        sys.exit(1)
PY

if cp "$OPENVEX_OUT" "$OUTPUT_JSON" 2>/dev/null; then
    WRITE_OUTPUT=1
fi

echo ""
echo "=== OpenVEX Verification Passed ==="
if [ "$WRITE_OUTPUT" -eq 1 ]; then
    echo "Output saved to: $OUTPUT_FILE"
    echo "JSON saved to: $OUTPUT_JSON"
else
    echo "⚠️  Output files not written (no write permission)."
fi
