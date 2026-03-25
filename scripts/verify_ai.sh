#!/usr/bin/env bash
# AI Advisory Verification Script
# Runs VulnTriage with --ai and validates AI analysis output.
#
# Prerequisites:
# - OPENAI_API_KEY set
# - trivy installed
# - test-repos/pygoat cloned (run: git clone https://github.com/adeyosemanputra/pygoat test-repos/pygoat)
# - test-repos/pygoat-trivy.json generated (run: trivy fs --scanners vuln --format json --quiet test-repos/pygoat > test-repos/pygoat-trivy.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$SCRIPT_DIR/verify_ai_output.txt"
OUTPUT_JSON="$SCRIPT_DIR/verify_ai_output.json"
WRITE_OUTPUT=0

if [ -f "$PROJECT_ROOT/.env" ]; then
    # shellcheck disable=SC1091
    source "$PROJECT_ROOT/.env"
fi

echo "=== VulnTriage AI Advisory Verification ==="
echo "Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "❌ ERROR: OPENAI_API_KEY is not set"
    echo "Set it and rerun: export OPENAI_API_KEY='sk-...'"
    exit 1
fi
export OPENAI_API_KEY

# Check prerequisites
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

TRIVY_JSON="test-repos/pygoat-trivy.json"
SRC_DIR="test-repos/pygoat"
TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -p "$PROJECT_ROOT/test-repos" 2>/dev/null || true)
if [ -z "$TEMP_DIR" ]; then
    echo "❌ ERROR: Unable to create temp directory."
    echo "Set TMPDIR to a writable path and retry (e.g., export TMPDIR=/path)."
    exit 1
fi
trap "rm -rf $TEMP_DIR" EXIT

AI_OUT="$TEMP_DIR/ai_results.json"
AI_LOG="$TEMP_DIR/ai_run.log"
AI_CACHE="$TEMP_DIR/ai_cache.json"
export AI_OUT

VT_CMD=(uv run vulntriage)
if [ -x "$PROJECT_ROOT/.venv/bin/vulntriage" ]; then
    VT_CMD=("$PROJECT_ROOT/.venv/bin/vulntriage")
fi

echo "--- Running VulnTriage with AI advisory ---"
"${VT_CMD[@]}" scan \
  --trivy-json "$TRIVY_JSON" \
  --src "$SRC_DIR" \
  --json \
  --ai \
  --ai-limit 3 \
  --ai-context-lines 50 \
  --ai-redact \
  --ai-cache "$AI_CACHE" \
  > "$AI_OUT" 2> "$AI_LOG"

if [ ! -s "$AI_OUT" ]; then
    echo "❌ ERROR: AI output JSON not created"
    cat "$AI_LOG" || true
    exit 1
fi

echo "--- Validating AI output ---"
if ! python3 - <<'PY'
import json
import os
from pathlib import Path

data = json.loads(Path(os.environ["AI_OUT"]).read_text(encoding="utf-8"))
assert isinstance(data, list), "Output is not a list"
ai_results = [r for r in data if r.get("ai_analysis")]
evidence_results = [r for r in data if r.get("evidence")]
actionable_with_evidence = [r for r in data if r.get("status") == "actionable" and r.get("evidence")]

print(f"Total results: {len(data)}")
print(f"AI-annotated results: {len(ai_results)}")
print(f"Results with evidence: {len(evidence_results)}")
print(f"Actionable with evidence: {len(actionable_with_evidence)}")

if len(ai_results) == 0:
    raise SystemExit(2)
assert len(ai_results) <= 3, "AI limit exceeded"

print("--- Sample AI results (up to 3) ---")
for r in ai_results[:3]:
    ai = r["ai_analysis"]
    print(
        f"{r['vuln_id']:22} {r['pkg_name']:12} "
        f"exploitable={ai['is_exploitable']} "
        f"confidence={ai['confidence']:.2f}"
    )
PY
then
    echo "❌ ERROR: No AI analysis results found"
    if [ -s "$AI_LOG" ]; then
        echo "--- AI run log ---"
        cat "$AI_LOG"
    else
        echo "--- AI run log empty ---"
    fi
    exit 1
fi

if cp "$AI_OUT" "$OUTPUT_JSON" 2>/dev/null; then
    WRITE_OUTPUT=1
fi

echo ""
echo "=== AI Advisory Verification Passed ==="
if [ "$WRITE_OUTPUT" -eq 1 ]; then
    echo "JSON saved to: $OUTPUT_JSON"
else
    echo "⚠️  Output files not written (no write permission)."
fi
