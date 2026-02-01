#!/usr/bin/env bash
set -euo pipefail

# Verify function matching with the sample CVE function map

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="$SCRIPT_DIR/verify_function_matching_output.txt"

cd "$PROJECT_ROOT"

echo "=== Function Matching Verification ===" | tee "$OUTPUT_FILE"
echo "Date: $(date -Iseconds)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Use real PyGoat from test-repos
TRIVY_JSON="test-repos/pygoat-trivy.json"
SRC_DIR="test-repos/pygoat"
FN_MAP="${FN_MAP:-src/vulntriage/data/cve_functions.json}"

PY_CMD=(python3)
if command -v uv &> /dev/null; then
    PY_CMD=(uv run python)
fi

if [[ ! -f "$TRIVY_JSON" ]]; then
    echo "ERROR: $TRIVY_JSON not found" | tee -a "$OUTPUT_FILE"
    exit 1
fi

if [[ ! -f "$FN_MAP" ]]; then
    echo "ERROR: $FN_MAP not found" | tee -a "$OUTPUT_FILE"
    exit 1
fi

echo "--- Run WITHOUT function map ---" | tee -a "$OUTPUT_FILE"
uv run vulntriage scan -t "$TRIVY_JSON" -s "$SRC_DIR" --no-enrich --no-json 2>&1 | head -30 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

echo "--- Run WITH function map ---" | tee -a "$OUTPUT_FILE"
uv run vulntriage scan -t "$TRIVY_JSON" -s "$SRC_DIR" --no-enrich --cve-function-map "$FN_MAP" --no-json 2>&1 | head -30 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Count results with/without function map
echo "--- Status comparison ---" | tee -a "$OUTPUT_FILE"
echo "Without function map:" | tee -a "$OUTPUT_FILE"
uv run vulntriage scan -t "$TRIVY_JSON" -s "$SRC_DIR" --no-enrich --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
counts = {}
for r in data:
    s = r['status']
    counts[s] = counts.get(s, 0) + 1
for k, v in sorted(counts.items()):
    print(f'  {k}: {v}')
" | tee -a "$OUTPUT_FILE"

echo "With function map:" | tee -a "$OUTPUT_FILE"
uv run vulntriage scan -t "$TRIVY_JSON" -s "$SRC_DIR" --no-enrich --cve-function-map "$FN_MAP" --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
counts = {}
for r in data:
    s = r['status']
    counts[s] = counts.get(s, 0) + 1
for k, v in sorted(counts.items()):
    print(f'  {k}: {v}')
" | tee -a "$OUTPUT_FILE"

echo "" | tee -a "$OUTPUT_FILE"
echo "--- Function map evidence check ---" | tee -a "$OUTPUT_FILE"
SRC_DIR="$SRC_DIR" FN_MAP="$FN_MAP" "${PY_CMD[@]}" - <<'PY' | tee -a "$OUTPUT_FILE"
import os
from collections import defaultdict
from pathlib import Path

from vulntriage.analyzer import find_call_sites
from vulntriage.cve_function_map import load_cve_function_map, matches_vulnerable_function
from vulntriage.scanner import scan_directory

src_dir = Path(os.environ["SRC_DIR"])
map_path = Path(os.environ["FN_MAP"])

fn_map = load_cve_function_map(map_path)
if not fn_map:
    print("No function map entries loaded.")
    raise SystemExit(0)

scan_result = scan_directory(src_dir, include_tests=False)
call_sites = []
for parsed in scan_result.parsed_files:
    call_sites.extend(
        find_call_sites(parsed.path, parsed.tree.root_node, parsed.symbol_table, None)
    )

total_functions = sum(len(fns) for fns in fn_map.values())
matched = {}
missing = defaultdict(list)

for cve, functions in fn_map.items():
    for fn in functions:
        found = None
        for call in call_sites:
            if matches_vulnerable_function(call.callee, {fn}):
                found = call
                break
        if found:
            matched[fn] = found
        else:
            missing[cve].append(fn)

print(f"Functions in map: {total_functions}")
print(f"Functions matched in code: {len(matched)}")
print(f"Functions missing in code: {sum(len(v) for v in missing.values())}")

for cve, fns in sorted(fn_map.items()):
    missing_count = len(missing.get(cve, []))
    print(f"  {cve}: {len(fns) - missing_count}/{len(fns)} matched")

if missing:
    print()
    print("Missing function entries (first 10):")
    count = 0
    for cve, fns in sorted(missing.items()):
        for fn in fns:
            print(f"  {cve}: {fn}")
            count += 1
            if count >= 10:
                raise SystemExit(0)
PY

echo "" | tee -a "$OUTPUT_FILE"
echo "=== Verification complete ===" | tee -a "$OUTPUT_FILE"
echo "Output saved to: $OUTPUT_FILE"
