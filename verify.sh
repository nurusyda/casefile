#!/usr/bin/env bash
# =============================================================================
# verify.sh — Reproducibility Harness for CaseFile Grounding Verification
# =============================================================================
#
# What this proves:
#   - Every committed fixture reproduces its expected grounding numbers
#     (total_claims, grounded, contradicted, hallucination_rate) from
#     sanitized audit logs and findings — no raw evidence required.
#   - All three cases (SRL-2018, SRL-2018-DC, SRL-2018-FILE) reproduce
#     full Tier 2 (CSV-backed exact_value verification) because minimal
#     CSV fixtures are committed alongside the sanitized audit trail.
#
# Run:
#   bash verify.sh
#
# Requires: python3, jq
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

FIXTURES_DIR="$REPO_ROOT/fixtures/reproducibility"

if [ ! -d "$FIXTURES_DIR" ]; then
    echo "ERROR: fixtures/reproducibility/ not found. Run: python3 scripts/build_repro_fixtures.py"
    exit 1
fi

# Check prerequisites
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install with: sudo apt-get install jq"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required."
    exit 1
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== CaseFile Reproducibility Verification ==="
echo ""

PASS_COUNT=0
FAIL_COUNT=0
declare -a TABLE_ROWS
declare -a FAILED_CASES

for case_fixture_dir in "$FIXTURES_DIR"/*/; do
    case_name=$(basename "$case_fixture_dir")

    # ── Copy fixture into temp workdir ──────────────────────────────────────
    cp -r "$case_fixture_dir" "$WORKDIR/$case_name"
    CASE_ABS="$WORKDIR/$case_name"

    # ── Expand {{CASE_DIR}} tokens in audit log and findings ────────────────
    if [ -f "$CASE_ABS/audit/mcp.jsonl" ]; then
        sed -i "s#{{CASE_DIR}}#$CASE_ABS#g" "$CASE_ABS/audit/mcp.jsonl"
    fi
    if [ -f "$CASE_ABS/findings.json" ]; then
        sed -i "s#{{CASE_DIR}}#$CASE_ABS#g" "$CASE_ABS/findings.json"
    fi

    # ── Run grounding verification ──────────────────────────────────────────
    export CASE_DIR="$CASE_ABS"
    export CASEFILE_CASE_ROOT="$CASE_ABS"
    export AUDIT_LOG="$CASE_ABS/audit/mcp.jsonl"
    export FINDINGS_FILE="$CASE_ABS/findings.json"
    export CLAIM_REPORT="$CASE_ABS/analysis/claim_accuracy_report.json"

    mkdir -p "$CASE_ABS/analysis"

    VERIFY_EXIT=0
    python3 scripts/grounding_verify.py > "$CASE_ABS/analysis/verify.log" 2>&1 || VERIFY_EXIT=$?

    # ── Read produced report ────────────────────────────────────────────────
    CLAIM_REPORT_FILE="$CASE_ABS/analysis/claim_accuracy_report.json"
    if [ -f "$CLAIM_REPORT_FILE" ]; then
        actual_total=$(jq -r '.total_claims' "$CLAIM_REPORT_FILE")
        actual_grounded=$(jq -r '.grounded' "$CLAIM_REPORT_FILE")
        actual_ungrounded=$(jq -r '.ungrounded' "$CLAIM_REPORT_FILE")
        actual_contradicted=$(jq -r '.contradicted' "$CLAIM_REPORT_FILE")
        actual_halluc=$(jq -r '.hallucination_rate' "$CLAIM_REPORT_FILE")
        actual_tier2=$(jq -r '.tier2_verified' "$CLAIM_REPORT_FILE")
    else
        echo "  [ERROR] No claim accuracy report produced for $case_name"
        actual_total="ERR"
        actual_grounded="ERR"
        actual_ungrounded="ERR"
        actual_contradicted="ERR"
        actual_halluc="ERR"
        actual_tier2="ERR"
    fi

    # ── Read expected values ────────────────────────────────────────────────
    expected_total=$(jq -r '.total_claims' "$CASE_ABS/expected.json")
    expected_grounded=$(jq -r '.grounded' "$CASE_ABS/expected.json")
    expected_ungrounded=$(jq -r '.ungrounded' "$CASE_ABS/expected.json")
    expected_contradicted=$(jq -r '.contradicted' "$CASE_ABS/expected.json")
    expected_halluc=$(jq -r '.hallucination_rate' "$CASE_ABS/expected.json")
    expected_tier2=$(jq -r '.tier2_verified' "$CASE_ABS/expected.json")

    # ── Compare ─────────────────────────────────────────────────────────────
    result="PASS"
    mismatches=""

    if [ "$actual_total" != "$expected_total" ]; then
        result="FAIL"
        mismatches="$mismatches total_claims($actual_total!=$expected_total)"
    fi
    if [ "$actual_grounded" != "$expected_grounded" ]; then
        result="FAIL"
        mismatches="$mismatches grounded($actual_grounded!=$expected_grounded)"
    fi
    if [ "$actual_contradicted" != "$expected_contradicted" ]; then
        result="FAIL"
        mismatches="$mismatches contradicted($actual_contradicted!=$expected_contradicted)"
    fi

    # Hallucination rate: compare as float strings
    if [ "$actual_halluc" != "$expected_halluc" ]; then
        result="FAIL"
        mismatches="$mismatches halluc%($actual_halluc!=$expected_halluc)"
    fi

    # Tier 2: enforced for all cases (all have committed CSVs)
    tier2_display="$actual_tier2"
    tier2_note=""
    if [ "$actual_tier2" != "$expected_tier2" ]; then
        result="FAIL"
        mismatches="$mismatches tier2($actual_tier2!=$expected_tier2)"
    fi

    if [ "$result" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_CASES+=("$case_name$mismatches")
    fi

    # Format: CASE | claims | grounded | contradicted | halluc% | tier2 | RESULT
    printf -v row "%-18s | %6s | %8s | %12s | %7s | %5s | %s" \
        "$case_name" "$actual_total" "$actual_grounded" "$actual_contradicted" \
        "$actual_halluc" "$tier2_display" "$result"
    TABLE_ROWS+=("$row")

    # Print per-case detail
    echo "  $case_name: claims=$actual_total grounded=$actual_grounded" \
         "contradicted=$actual_contradicted halluc%=$actual_halluc" \
         "tier2=$tier2_display → $result$tier2_note"
done

# ── Print fixed-width table ──────────────────────────────────────────────────
echo ""
echo "CASE               | claims | grounded | contradicted | halluc% | tier2 | RESULT"
echo "--------------------+--------+----------+--------------+---------+-------+-------"
for row in "${TABLE_ROWS[@]}"; do
    echo "$row"
done

# ── Aggregate line ──────────────────────────────────────────────────────────
# Re-read all produced reports for aggregate
agg_total=0 agg_grounded=0 agg_contradicted=0
for case_fixture_dir in "$FIXTURES_DIR"/*/; do
    case_name=$(basename "$case_fixture_dir")
    CASE_ABS="$WORKDIR/$case_name"
    REPORT="$CASE_ABS/analysis/claim_accuracy_report.json"
    if [ -f "$REPORT" ]; then
        agg_total=$((agg_total + $(jq '.total_claims' "$REPORT")))
        agg_grounded=$((agg_grounded + $(jq '.grounded' "$REPORT")))
        agg_contradicted=$((agg_contradicted + $(jq '.contradicted' "$REPORT")))
    fi
done

if [ "$agg_total" -gt 0 ]; then
    agg_halluc=$(python3 -c "print(round($agg_contradicted / $agg_total, 4))")
else
    agg_halluc="0.0"
fi

printf -v agg_row "%-18s | %6d | %8d | %12d | %7s | %5s | %s" \
    "AGGREGATE" "$agg_total" "$agg_grounded" "$agg_contradicted" \
    "$agg_halluc" "-" ""
echo "--------------------+--------+----------+--------------+---------+-------+-------"
echo "$agg_row"
echo ""

# ── Final verdict ───────────────────────────────────────────────────────────
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "✓ All $PASS_COUNT case(s) PASSED reproducibility check."
    echo ""
    echo "  All three cases reproduce full Tier 1 + Tier 2 attestation."
    exit 0
else
    echo "✗ $FAIL_COUNT case(s) FAILED reproducibility check:"
    for fc in "${FAILED_CASES[@]}"; do
        echo "    - $fc"
    done
    exit 1
fi
