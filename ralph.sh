#!/usr/bin/env bash
# ralph.sh — Ralph Wiggum Self-Correction Loop
# Runs Claude Code in a loop, checking prd.json acceptance criteria each iteration.
# Named after the character who keeps trying until something works.
#
# Usage:
#   bash ralph.sh [case_dir]
#
# Requirements:
#   - claude (Claude Code CLI) in PATH
#   - prd.json in working directory
#   - MCP server running (or started by this script)
#
# The loop runs until:
#   1. Claude outputs <promise>TASK_COMPLETE</promise>, OR
#   2. All tasks in prd.json have PASSED status, OR
#   3. max_iterations is reached (default: 25)

set -euo pipefail

# ─── CONFIG ────────────────────────────────────────────────────────────────────
CASE_DIR="${1:-.}"
PRD_FILE="${CASE_DIR}/prd.json"
PROGRESS_FILE="${CASE_DIR}/analysis/progress.txt"
LOG_FILE="${CASE_DIR}/analysis/ralph.log"
MAX_ITER=$(python3 -c "import json; print(json.load(open('${PRD_FILE}'))['max_iterations'])" 2>/dev/null || echo 25)
COMPLETION_SIGNAL="TASK_COMPLETE"
RALPH_JSONL="${CASE_DIR}/audit/ralph.jsonl"

# ─── SETUP ─────────────────────────────────────────────────────────────────────
mkdir -p "${CASE_DIR}/analysis" "${CASE_DIR}/reports" "${CASE_DIR}/audit"

log() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[${ts}] $*" | tee -a "${LOG_FILE}"
}

log "=== RALPH WIGGUM LOOP START ==="
log "Case dir: ${CASE_DIR}"
log "Max iterations: ${MAX_ITER}"
log "PRD file: ${PRD_FILE}"

# ─── ITERATION LOOP ────────────────────────────────────────────────────────────
iteration=0
last_output=""

while [ "${iteration}" -lt "${MAX_ITER}" ]; do
    iteration=$((iteration + 1))
    log "--- Iteration ${iteration}/${MAX_ITER} ---"

    # Build the prompt for this iteration
    if [ "${iteration}" -eq 1 ]; then
        PROMPT="Read CLAUDE.md and prd.json. Begin the CRIMSON OSPREY investigation. Work through the OODA loop. Call MCP tools. Document all findings with CONFIRMED/INFERRED/HYPOTHESIS labels. Output the <promise>TASK_COMPLETE</promise> block when done."
    else
        # Feed progress back to Claude with specific failures
        # shellcheck disable=SC2016  # Python heredoc single-quoted literals are intentional
        FAILED_TASKS=$(python3 - <<'PYEOF'
import json, sys, os

prd = json.load(open(os.environ.get('PRD_FILE', 'prd.json')))
progress_file = os.environ.get('PROGRESS_FILE', 'analysis/progress.txt')

failed = []
for task in prd['tasks']:
    failed.append(f"- {task['id']} ({task['name']}): {task['failure_action']}")

print('\n'.join(failed) if failed else 'All tasks passed.')
PYEOF
        )
        PROMPT="Iteration ${iteration}. Previous run incomplete. Review ./analysis/progress.txt for what was found. The following tasks need attention:\n\n${FAILED_TASKS}\n\nContinue the investigation. Fix the gaps. Re-output <promise>TASK_COMPLETE</promise> when all criteria are met."
    fi

    # Run Claude Code (non-interactive, pipe prompt)
    log "Running Claude Code..."
    CLAUDE_OUTPUT=$(echo "${PROMPT}" | claude -p 2>&1) || true
    last_output="${CLAUDE_OUTPUT}"

    # Log output summary
    log "Claude output length: ${#CLAUDE_OUTPUT} chars"

    # Append to progress file
    {
        echo "=== Iteration ${iteration} — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
        echo "${CLAUDE_OUTPUT}" | tail -50
        echo ""
    } >> "${PROGRESS_FILE}"

    # Check for completion signal
    if echo "${CLAUDE_OUTPUT}" | grep -q "${COMPLETION_SIGNAL}"; then
        log "COMPLETION SIGNAL DETECTED — Task complete."

        # Extract promise block
        PROMISE=$(echo "${CLAUDE_OUTPUT}" | sed -n '/<promise>/,/<\/promise>/p')
        log "Promise block: ${PROMISE}"

        # Score against prd.json checkpoints
        log "=== FINAL SCORE ==="
        python3 - <<PYEOF
import json, os, re

prd = json.load(open('${PRD_FILE}'))
output = """${CLAUDE_OUTPUT}"""

confirmed = re.search(r'confirmed_findings:\s*\[?(\d+)\]?', output)
inferred  = re.search(r'inferred_findings:\s*\[?(\d+)\]?',  output)
hypo      = re.search(r'hypothesis:\s*\[?(\d+)\]?',         output)
self_corr = re.search(r'self_corrections:\s*\[?(\d+)\]?',   output)

print(f"  CONFIRMED findings : {confirmed.group(1) if confirmed else '?'}")
print(f"  INFERRED findings  : {inferred.group(1)  if inferred  else '?'}")
print(f"  HYPOTHESES         : {hypo.group(1)      if hypo      else '?'}")
print(f"  Self-corrections   : {self_corr.group(1) if self_corr else '?'}")
print(f"  Iterations used    : ${iteration}")
print()
print("Checkpoint scoring:")
for cp in prd['scoring']['checkpoints']:
    print(f"  {cp['id']}: {cp['question']}")
PYEOF

        log "=== RALPH LOOP COMPLETE after ${iteration} iterations ==="
        exit 0
    fi

    log "No completion signal. Continuing..."

    # Write self-correction record to audit/ralph.jsonl
    RALPH_JSONL="${RALPH_JSONL}" CASE_DIR="${CASE_DIR}" ITERATION="${iteration}" MAX_ITER="${MAX_ITER}" python3 - <<'PYEOF2'
import json, datetime, os
record = {
    "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
    "iteration": int(os.environ["ITERATION"]),
    "max_iterations": int(os.environ["MAX_ITER"]),
    "event": "self_correction",
    "action": "retry",
    "case_dir": os.environ["CASE_DIR"]
}
with open(os.environ["RALPH_JSONL"], "a", encoding="utf-8") as f:
    f.write(json.dumps(record) + "\n")
PYEOF2

    # RAM check between iterations
    FREE_RAM=$(free -h | awk '/^Mem:/ {print $4}')
    log "Available RAM: ${FREE_RAM}"

    # Brief pause between iterations (avoid hammering the API)
    sleep 5
done

# ─── MAX ITERATIONS REACHED ────────────────────────────────────────────────────
log "ERROR: Max iterations (${MAX_ITER}) reached without completion signal."
log "Last output tail:"
echo "${last_output}" | tail -20 | tee -a "${LOG_FILE}"
log "Check ${PROGRESS_FILE} for accumulated findings."
log "Check ${CASE_DIR}/audit/mcp.jsonl for tool call history."
exit 1
