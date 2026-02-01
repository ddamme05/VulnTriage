#!/usr/bin/env bash
# Config Resolution Verification Script
# Validates config/ENV/CLI precedence and dry-run output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/verify_config_resolution_output.txt"

RICH_DISABLE=1
export RICH_DISABLE
COLUMNS=200
export COLUMNS

WRITE_OUTPUT=0
if ! touch "$OUTPUT_FILE" 2>/dev/null; then
    WRITE_OUTPUT=0
else
    exec > >(tee "$OUTPUT_FILE") 2>&1
    WRITE_OUTPUT=1
fi

echo "=== VulnTriage Config Resolution Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

TEMP_DIR=$(mktemp -d -p "$PROJECT_ROOT" .vt-config-XXXXXX 2>/dev/null || mktemp -d 2>/dev/null || true)
if [ -z "$TEMP_DIR" ]; then
    echo "ERROR: Unable to create temp directory."
    exit 1
fi

cleanup() {
    if [ -f "$PROJECT_ROOT/.vulntriage.toml.bak" ]; then
        mv "$PROJECT_ROOT/.vulntriage.toml.bak" "$PROJECT_ROOT/.vulntriage.toml"
    else
        rm -f "$PROJECT_ROOT/.vulntriage.toml"
    fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if [ -f "$PROJECT_ROOT/.vulntriage.toml" ]; then
    mv "$PROJECT_ROOT/.vulntriage.toml" "$PROJECT_ROOT/.vulntriage.toml.bak"
fi

mkdir -p "$TEMP_DIR/src"
cat > "$TEMP_DIR/trivy.json" <<'JSON'
{
  "SchemaVersion": 2,
  "Results": []
}
JSON
touch "$TEMP_DIR/uv.lock"
touch "$TEMP_DIR/override.lock"
echo "print('hello')" > "$TEMP_DIR/src/app.py"

cat > "$PROJECT_ROOT/.vulntriage.toml" <<EOF
[scan]
trivy-json = "$TEMP_DIR/trivy.json"
src = "$TEMP_DIR/src"
lockfile = "$TEMP_DIR/uv.lock"
proximity = true
json = false
EOF

VT_CMD=(uv run vulntriage)
if [ -x "$PROJECT_ROOT/.venv/bin/vulntriage" ]; then
    VT_CMD=("$PROJECT_ROOT/.venv/bin/vulntriage")
fi

echo "--- Dry run with dotfile config ---"
OUTPUT=$("${VT_CMD[@]}" scan --dry-run --no-json 2>&1 || true)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "config:.vulntriage.toml" || {
    echo "ERROR: trivy_json not resolved from dotfile config"
    exit 1
}
LOCK_BLOCK=$(printf "%s\n" "$OUTPUT" | awk '/Lockfile:/ {print; getline; print; exit}')
echo "$LOCK_BLOCK" | grep -q "config:.vulntriage.toml" || {
    echo "ERROR: lockfile not resolved from dotfile config"
    exit 1
}

echo ""
echo "--- Dry run with env override (VULNTRIAGE_LOCKFILE) ---"
export VULNTRIAGE_LOCKFILE="$TEMP_DIR/override.lock"
OUTPUT=$("${VT_CMD[@]}" scan --dry-run --no-json 2>&1 || true)
echo "$OUTPUT"
LOCK_BLOCK=$(printf "%s\n" "$OUTPUT" | awk '/Lockfile:/ {print; getline; print; exit}')
echo "$LOCK_BLOCK" | grep -q "env:VULNTRIAGE_LOCKFILE" || {
    echo "ERROR: lockfile not resolved from env override"
    exit 1
}
unset VULNTRIAGE_LOCKFILE

echo ""
echo "=== Config Resolution Verification Passed ==="
if [ "$WRITE_OUTPUT" -eq 1 ]; then
    echo "Output saved to: $OUTPUT_FILE"
fi
