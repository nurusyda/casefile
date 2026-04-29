#!/usr/bin/env bash
# ralph.sh — Ralph Wiggum Self-Correction Loop
# Runs Claude Code in a loop, checking prd.json acceptance criteria each iteration.
# Named after the character who keeps trying until something works.
#
# Usage:
#   bash ralph.sh [case_dir]
#
# Fixes applied (April 29 2026):
#   - Removed --no-interactive flag (not supported in current Claude Code)
#   - Added rate limit detection — pause instead of burning all 25 iterations
#   - Added pre-flight check for .claude/settings.json (MCP tool permissions)
#
# Requirements:
#   - claude (Claude Code CLI) in PATH and logged in
#   - prd.json in working directory
#   - MCP server running (casefile venv active)
#
# The loop runs until:
#   1. Claude outputs <promise>TASK_COMPLETE</promise>, OR
#   2. max_iterations is reached (default: 25)

set -euo pipefail

# ─── CONFIG ────────────────────────────────────────────────────────────────────
CASE_DIR="${1:-.}"
PRD_FILE="${CASE_DIR}/prd.json"
PROGRESS_FILE="${CASE_DIR}/analysis/progress.txt"
LOG_FILE="${CASE_DIR}/analysis/ralph.log"
MAX_ITER=$(python3 -c "import json; print(json.load(open('${PRD_FILE}'))['max_iterations'])" 2>/dev/null || echo 25)
COMPLETION_SIGNAL="TASK_COMPLETE"
RATE_LIMIT_PAUSE=120  # seconds to wait when rate limited

# ─── SETUP ─────────────────────────────────────────────────────────────────────
mkdir -p "${CASE_DIR}/analysis" "${CASE_DIR}/reports" "${CASE_DIR}/audit"

log() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[${ts}] $*" | tee -a "${LOG_FILE}"
}

# ─── PRE-FLIGHT: MCP PERMISSIONS ───────────────────────────────────────────────
# Claude Code requires .claude/settings.json to allow MCP tool calls.
# Without this, Claude will ask for permission every iteration and never proceed.
SETTINGS_FILE="${CASE_DIR}/.claude/settings.json"
if [[ ! -f "${SETTINGS_FILE}" ]]; then
    log "Creating .claude/settings.json — allowlisting casefile MCP tools..."
    mkdir -p "${CASE_DIR}/.claude"
    cat > "${SETTINGS_FILE}" << 'SETTINGS'
{
  "permissions": {
    "allow": [
      "mcp__casefile__parse_amcache",
      "mcp__casefile__parse_prefetch",
      "mcp__casefile__parse_event_logs",
      "mcp__casefile__parse_registry",
      "mcp__casefile__parse_mft"
    ]
  }
}
SETTINGS
    log "Created ${SETTINGS_FILE}"
else
    log "Found existing ${SETTINGS_FILE} — skipping creation"
fi

# ─── PRE-FLIGHT: CLAUDE CODE LOGIN CHECK ───────────────────────────────────────
log "Checking Claude Code login status..."
LOGIN_CHECK=$(claude --version 2>&1 || true)
if echo "${LOGIN_CHECK}" | grep -qi "not logged in\|please run /login\|login"; then
    log "ERROR: Claude Code is not logged in. Run: claude /login"
    exit 1
fi
log "Claude Code: ${LOGIN_CHECK}"

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
        PROMPT="Iteration ${iteration}. Previous run incomplete. Review ./analysis/progress.txt for what was found. The following tasks need attention:

${FAILED_TASKS}

Continue the investigation. Fix the gaps. Re-output <promise>TASK_COMPLETE</promise> when all criteria are met."
    fi

    # Run Claude Code (pipe prompt via stdin — no --no-interactive flag)
    log "Running Claude Code..."
    CLAUDE_OUTPUT=$(echo "${PROMPT}" | claude 2>&1) || true
    last_output="${CLAUDE_OUTPUT}"

    # Log output summary
    log "Claude output length: ${#CLAUDE_OUTPUT} chars"

    # ── Rate limit detection — pause instead of burning iterations ──────────────
    if echo "${CLAUDE_OUTPUT}" | grep -qi "hit your limit\|rate limit\|resets\|too many requests"; then
        log "RATE LIMIT DETECTED — pausing ${RATE_LIMIT_PAUSE}s before retry..."
        log "Output: $(echo "${CLAUDE_OUTPUT}" | head -3)"
        sleep "${RATE_LIMIT_PAUSE}"
        # Don't count this as a real iteration — decrement and retry
        iteration=$((iteration - 1))
        continue
    fi

    # ── Login check — exit immediately if not logged in ─────────────────────────
    if echo "${CLAUDE_OUTPUT}" | grep -qi "not logged in\|please run /login"; then
        log "ERROR: Claude Code logged out mid-run. Re-login and restart."
        exit 1
    fi

    # ── Unknown option / CLI error — exit with helpful message ──────────────────
    if echo "${CLAUDE_OUTPUT}" | grep -qi "unknown option\|invalid option\|error:"; then
        log "ERROR: Claude Code CLI error detected:"
        echo "${CLAUDE_OUTPUT}" | head -5 | tee -a "${LOG_FILE}"
        log "Fix the claude invocation in ralph.sh and restart."
        exit 1
    fi

    # Append to progress file
    {
        echo "=== Iteration ${iteration} — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
        echo "${CLAUDE_OUTPUT}" | tail -50
        echo ""
    } >> "${PROGRESS_FILE}"

    # ── Check for completion signal ──────────────────────────────────────────────
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
