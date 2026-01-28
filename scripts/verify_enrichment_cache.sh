#!/usr/bin/env bash
# Enrichment Cache Verification Script
# Demonstrates offline-first EPSS/KEV caching behavior.
#
# Uses local test fixtures (no Trivy dependency).
# Requires network access only for --refresh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/verify_enrichment_cache_output.txt"
WRITE_OUTPUT=0

if ! touch "$OUTPUT_FILE" 2>/dev/null; then
    WRITE_OUTPUT=0
else
    exec > >(tee "$OUTPUT_FILE") 2>&1
    WRITE_OUTPUT=1
fi

echo "=== VulnTriage Enrichment Cache Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

TRIVY_JSON="tests/fixtures/trivy_pygoat.json"
SRC_DIR="tests/fixtures/pygoat_src"

if [ ! -f "$TRIVY_JSON" ] || [ ! -d "$SRC_DIR" ]; then
    echo "❌ ERROR: Missing fixtures at tests/fixtures"
    exit 1
fi

TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -p "$PROJECT_ROOT/.tmp" 2>/dev/null || true)
if [ -z "$TEMP_DIR" ]; then
    echo "❌ ERROR: Unable to create temp directory."
    echo "Set TMPDIR to a writable path and retry (e.g., export TMPDIR=/path)."
    exit 1
fi
trap "rm -rf $TEMP_DIR" EXIT

CACHE_DIR=$(python3 - <<'PY'
from pathlib import Path
print(Path.home() / ".cache" / "vulntriage")
PY
)

VT_CMD=(uv run vulntriage)
if [ -x "$PROJECT_ROOT/.venv/bin/vulntriage" ]; then
    VT_CMD=("$PROJECT_ROOT/.venv/bin/vulntriage")
fi

LOG_REFRESH="$TEMP_DIR/refresh.log"
LOG_NOREFRESH="$TEMP_DIR/norefresh.log"

echo "--- Refreshing EPSS/KEV into cache (requires network) ---"
"${VT_CMD[@]}" scan \
  --trivy-json "$TRIVY_JSON" \
  --src "$SRC_DIR" \
  --refresh \
  --json \
  > "$TEMP_DIR/refresh.json" 2> "$LOG_REFRESH" || true

if grep -q "Failed to refresh EPSS data" "$LOG_REFRESH"; then
    echo "⚠️  EPSS refresh failed. See log for details."
fi
if grep -q "Failed to refresh KEV data" "$LOG_REFRESH"; then
    echo "⚠️  KEV refresh failed. See log for details."
fi

if [ ! -d "$CACHE_DIR" ]; then
    echo "❌ Cache directory not available: $CACHE_DIR"
    echo "Reason (log):"
    cat "$LOG_REFRESH"
    exit 1
fi

if [ ! -f "$CACHE_DIR/epss.csv" ] || [ ! -f "$CACHE_DIR/kev.json" ]; then
    echo "❌ Cache files missing in $CACHE_DIR"
    echo "Reason (log):"
    cat "$LOG_REFRESH"
    echo ""
    echo "Common causes:"
    echo "- No network / captive portal returned HTML instead of data"
    echo "- Corporate proxy blocked downloads"
    echo ""
    echo "Fix:"
    echo "1) Ensure network access to EPSS/KEV endpoints, then rerun"
    echo "2) Or manually place files into the cache:"
    echo "   ~/.cache/vulntriage/epss.csv"
    echo "   ~/.cache/vulntriage/kev.json"
    exit 1
fi

echo "--- Reading cached data ---"
python3 - <<'PY'
import csv
import json
from pathlib import Path

cache = Path.home() / ".cache" / "vulntriage"
meta = cache / "metadata.json"
if meta.exists():
    data = json.loads(meta.read_text(encoding="utf-8"))
    print(f"Metadata: {data}")
else:
    print("Metadata: missing")

epss_path = cache / "epss.csv"
kev_path = cache / "kev.json"

with epss_path.open(encoding="utf-8") as f:
    reader = csv.DictReader(
        line for line in f if line.strip() and not line.lstrip().startswith("#")
    )
    rows = [next(reader) for _ in range(3)]
    print(f"EPSS sample rows: {rows}")

kev = json.loads(kev_path.read_text(encoding="utf-8"))
print(f"KEV entries: {len(kev.get('vulnerabilities', []))}")
PY

echo "--- Using cache without refresh (offline mode) ---"
OFFLINE_CMD=("${VT_CMD[@]}" scan --offline --trivy-json "$TRIVY_JSON" --src "$SRC_DIR" --json)

if command -v unshare >/dev/null 2>&1; then
    if unshare -n true >/dev/null 2>&1; then
        echo "  Network namespace isolation: enabled (unshare -n)"
        unshare -n env VULNTRIAGE_OFFLINE=1 "${OFFLINE_CMD[@]}" \
          > "$TEMP_DIR/norefresh.json" 2> "$LOG_NOREFRESH" || true
    else
        echo "  Network namespace isolation: unavailable (permission denied)"
        env VULNTRIAGE_OFFLINE=1 "${OFFLINE_CMD[@]}" \
          > "$TEMP_DIR/norefresh.json" 2> "$LOG_NOREFRESH" || true
    fi
else
    echo "  Network namespace isolation: unshare not installed"
    env VULNTRIAGE_OFFLINE=1 "${OFFLINE_CMD[@]}" \
      > "$TEMP_DIR/norefresh.json" 2> "$LOG_NOREFRESH" || true
fi

echo "--- Cache usage check ---"
python3 - "$TEMP_DIR/norefresh.json" <<'PY'
import json
import sys
from pathlib import Path

results = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
# Any EPSS/KEV data present indicates enrichment used cached data
has_epss = any(r.get("epss_score") is not None for r in results)
has_kev = any(r.get("is_kev") for r in results)
print(f"EPSS present: {has_epss}")
print(f"KEV present: {has_kev}")
PY

echo ""
echo "=== Enrichment Cache Verification Passed ==="
if [ "$WRITE_OUTPUT" -eq 1 ]; then
    echo "Output saved to: $OUTPUT_FILE"
else
    echo "⚠️  Output file not written (no write permission)."
fi
