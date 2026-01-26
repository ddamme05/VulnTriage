#!/usr/bin/env bash
# VEX Verification Script
# Runs VulnTriage with --output-vex and validates the CycloneDX VEX output.
#
# Prerequisites:
# - trivy installed
# - test-repos/pygoat cloned (run: git clone https://github.com/adeyosemanputra/pygoat test-repos/pygoat)
# - test-repos/pygoat-trivy.json generated (run: trivy fs --scanners vuln --format json --quiet test-repos/pygoat > test-repos/pygoat-trivy.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/verify_vex_output.txt"

exec > >(tee "$OUTPUT_FILE") 2>&1

echo "=== VulnTriage VEX Verification ==="
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
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

VEX_OUT="$SCRIPT_DIR/verify_vex_output.json"
export VEX_OUT

PY_CMD=(python3)
if command -v uv &> /dev/null; then
    PY_CMD=(uv run python)
fi

echo "--- Running VulnTriage with VEX export ---"
echo "VEX output: $VEX_OUT"
uv run vulntriage scan \
  --trivy-json "$TRIVY_JSON" \
  --src "$SRC_DIR" \
  --output-vex "$VEX_OUT" \
  --json \
  > "$TEMP_DIR/results.json" 2> "$TEMP_DIR/run.log"

if [ ! -s "$VEX_OUT" ]; then
    echo "❌ ERROR: VEX output file not created"
    exit 1
fi

echo "--- Validating VEX structure ---"
"${PY_CMD[@]}" - <<'PY'
import json
import os
from pathlib import Path

vex_path = Path(os.environ["VEX_OUT"])
data = json.loads(vex_path.read_text(encoding="utf-8"))

assert data["bomFormat"] == "CycloneDX"
assert data["specVersion"] == "1.5"
assert "components" in data
assert "vulnerabilities" in data

component_refs = {c.get("bom-ref") for c in data["components"]}
affect_refs = set()
for v in data["vulnerabilities"]:
    for a in v.get("affects", []):
        affect_refs.add(a.get("ref"))

missing = affect_refs - component_refs
assert not missing, f"Missing component refs for affects: {missing}"

print(f"Components: {len(data['components'])}")
print(f"Vulnerabilities: {len(data['vulnerabilities'])}")
PY

echo "--- Validating against CycloneDX schema ---"
"${PY_CMD[@]}" - <<'PY'
import os
from pathlib import Path

try:
    from cyclonedx.validation.json import JsonValidator
    from cyclonedx.schema import SchemaVersion
except Exception as e:
    print(
        f"⚠️  Skipping schema validation (missing cyclonedx deps: {e}). "
        "Run `uv sync` to install dev dependencies."
    )
    raise SystemExit(0)

vex_path = Path(os.environ["VEX_OUT"])
validator = JsonValidator(SchemaVersion.V1_5)
validation_error = validator.validate_str(vex_path.read_text(encoding="utf-8"))
if validation_error is not None:
    raise SystemExit(f"VEX schema validation failed: {validation_error}")
print("Schema validation: OK")
PY

echo ""
echo "=== VEX Verification Passed ==="
