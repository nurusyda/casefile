#!/usr/bin/env bash
# ralph.sh — Ralph Wiggum Self-Correction Loop
# Runs Claude Code in a loop, checking prd.json acceptance criteria each iteration.
# Named after the character who keeps trying until something works.
#
# Usage:
#   bash ralph.sh [case_dir]
#   CASEFILE_CASE_ROOT env var used if no arg given
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/ralph.log"
log() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "[${ts}] $*" | tee -a "${LOG_FILE}"
}

# ─── CONFIG ────────────────────────────────────────────────────────────────────
CASE_DIR="${1:-${CASEFILE_CASE_ROOT:-.}}"
CASEFILE_CASE_DIR="${CASEFILE_CASE_DIR:-${CASE_DIR}}"
CASEFILE_CASE_DIR="$(realpath "${CASEFILE_CASE_DIR}")"
[ -d "${CASEFILE_CASE_DIR}" ] || { log "ERROR: CASEFILE_CASE_DIR is not a directory: ${CASEFILE_CASE_DIR}"; exit 1; }
cd "${SCRIPT_DIR}" || { log "ERROR: Cannot cd to ${SCRIPT_DIR}"; exit 1; }

# ── Dependency check ──
command -v jq >/dev/null 2>&1 || { log "ERROR: jq is required but not installed. Run: sudo apt-get install jq"; exit 1; }

# ── Token tracking ──
CASE_NAME=$(basename "${CASE_DIR}")
SESSION_TOKENS_FILE="${SCRIPT_DIR}/results/${CASE_NAME}_session_tokens.json"
mkdir -p "${SCRIPT_DIR}/results"

# Initialize or load session tokens file
_init_session_tokens() {
    if [ ! -f "${SESSION_TOKENS_FILE}" ]; then
        jq -n --arg case "${CASE_NAME}" '{
          "case": $case,
          "captured_from": "claude_code_ralph_loop",
          "note": "Token usage captured via ralph.sh Claude Code loop.",
          "iterations": [],
          "totals": {}
        }' > "${SESSION_TOKENS_FILE}"
    fi
}

# Append a single iteration's token data to session_tokens.json
_capture_tokens() {
    local iter_num="$1"
    local correction_flag="${2:-}"
    local capture_args=("${CASE_NAME}" "${iter_num}")
    if [ -n "${correction_flag}" ]; then
        capture_args+=("--correction" "${correction_flag}")
    fi
    local token_entry
    token_entry=$(python3 "${SCRIPT_DIR}/scripts/capture_tokens.py" "${capture_args[@]}" 2>/dev/null) || true
    if [ -z "${token_entry}" ]; then
        log "Token capture: no transcript found for iteration ${iter_num}"
        return 0
    fi
    # Guard against error entries (e.g. {"error": "no_transcript_found"})
    if ! echo "$token_entry" | jq -e '.input_tokens != null' >/dev/null 2>&1; then
        log "Token capture produced error entry, skipping append"
        return 0
    fi
    # Append to iterations array and recompute totals atomically
    python3 "${SCRIPT_DIR}/scripts/append_session_tokens.py" \
        "$token_entry" "$SESSION_TOKENS_FILE"
    log "Token usage captured for iteration ${iter_num}"
}

# ── Generate .mcp.json with correct CASEFILE_CASE_DIR (jq avoids shell injection) ──
generate_mcp_json() {
    jq -n         --arg case_dir "${CASEFILE_CASE_DIR}"         --arg examiner "${CASEFILE_EXAMINER:-casefile}"         --arg script_dir "${SCRIPT_DIR}"         '{
            mcpServers: {
                casefile: {
                    type: "stdio",
                    command: "\($script_dir)/venv/bin/python3",
                    args: ["-m", "mcp_server.server"],
                    cwd: $script_dir,
                    env: {
                        CASEFILE_CASE_DIR: $case_dir,
                        CASEFILE_EXAMINER: $examiner,
                        PYTHONPATH: $script_dir
                    }
                }
            }
        }' > "${SCRIPT_DIR}/.mcp.json" \
    || { log "ERROR: Failed to write .mcp.json — check permissions on ${SCRIPT_DIR}"; exit 1; }
}
PRD_FILE="${CASE_DIR}/prd.json"
PROGRESS_FILE="${CASE_DIR}/analysis/progress.txt"
LOG_FILE="${CASE_DIR}/analysis/ralph.log"
MAX_ITER=$(python3 scripts/read_max_iter.py "$PRD_FILE" 2>/dev/null || echo 25)
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
_init_session_tokens

while [ "${iteration}" -lt "${MAX_ITER}" ]; do
    iteration=$((iteration + 1))
    log "--- Iteration ${iteration}/${MAX_ITER} ---"

    # Build the prompt for this iteration
    if [ "${iteration}" -eq 1 ]; then
        PROMPT=$(cat <<PROMPT_EOF
Read CLAUDE.md and prd.json. Read ${CASEFILE_CASE_DIR}/iocs.md if it exists — these are IOCs propagated from a prior host investigation, cross-reference all findings against them. Begin the investigation of the current case. Work through the OODA loop. Call MCP tools. Document all findings with CONFIRMED/INFERRED/HYPOTHESIS labels.

EVIDENCE GROUNDING REQUIREMENT (mandatory — not optional):
Every call to record_finding() MUST include evidence_quotes as a list of dicts.
Each dict MUST have exactly these keys:
  tool         : the canonical MCP tool name — MUST match the audit log exactly.
                 Use ONLY these names (not the logical wrapper names):
                   parse_prefetch   ->  pyscca
                   parse_memory     ->  Volatility3
                   parse_event_logs ->  EvtxECmd
                   parse_registry   ->  RECmd
                   parse_amcache    ->  AmcacheParser
                   parse_mft        ->  MFTECmd
                   correlate_evidence stays as: correlate_evidence
  claim        : short claim text grounded by this tool output
  invocation_id: the invocation_id from the audit log entry for that tool call
Optional keys:
  audit_field  : exact audit field path to validate (e.g. path, pid)
  audit_expected: expected value or comparison (e.g. ">0", "True")
  exact_value  : verbatim value from tool output for Tier-2 CSV verification

Example (correct):
  evidence_quotes=[
    {"tool": "parse_amcache", "claim": "subject_srv.exe present in Amcache", "invocation_id": "inv_abc123", "exact_value": "C:\\Windows\\Temp\\subject_srv.exe"},
    {"tool": "parse_memory", "claim": "subject_srv.exe running in memory (PID 1096)", "invocation_id": "inv_def456", "exact_value": "1096"}
  ]

If you do not have an exact value from a tool output, do NOT invent one. Label the finding INFERRED and explain the reasoning in interpretation.

Output the <promise>TASK_COMPLETE</promise> block when done.
PROMPT_EOF
        )
    else
        # Feed progress back to Claude with specific failures
        # shellcheck disable=SC2016  # Python heredoc single-quoted literals are intentional
        FAILED_TASKS=$(python3 scripts/extract_failed_tasks.py)
        PROMPT="Iteration ${iteration}. Previous run incomplete. Review ./analysis/progress.txt for what was found. The following tasks need attention:\n\n${FAILED_TASKS}\n\nContinue the investigation. Fix the gaps. Re-output <promise>TASK_COMPLETE</promise> when all criteria are met."
    fi

    # Run Claude Code (non-interactive, pipe prompt)
    # Regenerate .mcp.json with current CASEFILE_CASE_DIR so MCP server inherits it
    generate_mcp_json
    log "Running Claude Code..."
    CLAUDE_OUTPUT=$(printf '%s' "${PROMPT}" | claude -p --mcp-config "${SCRIPT_DIR}/.mcp.json" 2>&1) || true
    if [ "${#CLAUDE_OUTPUT}" -lt 100 ]; then
        log "Output too short (${#CLAUDE_OUTPUT} chars) — likely rate limit. Exiting."
        exit 1
    fi
    last_output="${CLAUDE_OUTPUT}"

    # Capture token usage for this iteration
    _capture_tokens "${iteration}"

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

UNIVERSAL_CHECKPOINTS = [
    {"id": "CP1", "tactic": "TA0001",
     "question": "Initial access vector identified and attributed to artifact?"},
    {"id": "CP2", "tactic": "TA0003",
     "question": "Persistence mechanism identified (service/task/registry run key)?"},
    {"id": "CP3", "tactic": "TA0004/TA0006",
     "question": "Privilege escalation or credential access identified?"},
    {"id": "CP4", "tactic": "TA0008",
     "question": "Lateral movement path traced with source and destination hosts?"},
    {"id": "CP5", "tactic": "TA0005",
     "question": "Defense evasion or anti-forensics activity detected?"},
    {"id": "CP6", "tactic": "TA0011/TA0010",
     "question": "Command & control or exfiltration activity identified?"},
    {"id": "CP7", "tactic": "meta",
     "question": "Timeline complete with CONFIRMED/INFERRED labels on every finding?"},
    {"id": "CP8", "tactic": "meta",
     "question": "All findings traceable to invocation_id in audit/mcp.jsonl?"},
]

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
checkpoints = prd.get('scoring', {}).get('checkpoints', UNIVERSAL_CHECKPOINTS)
for cp in checkpoints:
    tactic = f" [{cp.get('tactic', '')}]" if cp.get('tactic') else ""
    print(f"  {cp['id']}{tactic}: {cp['question']}")
PYEOF

        log "=== RALPH LOOP COMPLETE after ${iteration} iterations ==="

        # ── PHASE 2: GROUNDING VERIFICATION ─────────────────────────────────
        log "Running post-completion grounding verification..."
        set +e
        CASE_DIR="${CASE_DIR}" \
        AUDIT_LOG="${CASEFILE_CASE_DIR}/audit/mcp.jsonl" \
        FINDINGS_FILE="${CASEFILE_CASE_DIR}/findings.json" \
        CLAIM_REPORT="${CASE_DIR}/analysis/claim_accuracy_report.json" \
        PYTHONPATH="${SCRIPT_DIR}" \
        python3 scripts/grounding_verify.py
        GROUNDING_EXIT=$?
        set -e
        log "Grounding verify exit: ${GROUNDING_EXIT}"

        if [ "${GROUNDING_EXIT}" -eq 1 ]; then
            log "ERROR: grounding_verify.py failed to import grounding module (exit 1). Halting."
            exit 1
        fi

        if [ "${GROUNDING_EXIT}" -eq 2 ]; then
            log "GROUNDING FAILURE: CONTRADICTED claims detected."
            log "Feeding correction prompt back to Claude (max 3 correction iterations)..."

            CORRECTION_ITER=0
            while [ "${CORRECTION_ITER}" -lt 3 ] && [ "${GROUNDING_EXIT}" -eq 2 ]; do
                CORRECTION_ITER=$((CORRECTION_ITER + 1))
                log "Correction iteration ${CORRECTION_ITER}/3..."

                if ! CORRECTION_PROMPT=$(CASE_DIR="${CASE_DIR}" AUDIT_LOG="${CASEFILE_CASE_DIR}/audit/mcp.jsonl" FINDINGS_FILE="${CASEFILE_CASE_DIR}/findings.json" PYTHONPATH="${SCRIPT_DIR}" python3 scripts/grounding_correction_prompt.py); then
                    log "ERROR: grounding_correction_prompt.py failed"
                    exit 1
                fi
                # Regenerate .mcp.json with current CASEFILE_CASE_DIR for correction run
                generate_mcp_json
                CLAUDE_OUTPUT=$(printf '%s' "${CORRECTION_PROMPT}" | claude -p --mcp-config "${SCRIPT_DIR}/.mcp.json" 2>&1) || true
                log "Correction ${CORRECTION_ITER} output length: ${#CLAUDE_OUTPUT} chars"

                # Capture token usage for this correction iteration
                _capture_tokens "${iteration}" "${CORRECTION_ITER}"

                set +e
                CASE_DIR="${CASE_DIR}" \
                AUDIT_LOG="${CASEFILE_CASE_DIR}/audit/mcp.jsonl" \
                FINDINGS_FILE="${CASEFILE_CASE_DIR}/findings.json" \
                CLAIM_REPORT="${CASE_DIR}/analysis/claim_accuracy_report.json" \
                PYTHONPATH="${SCRIPT_DIR}" \
                python3 scripts/grounding_recheck.py
                GROUNDING_EXIT=$?
                set -e
                log "Grounding re-check exit: ${GROUNDING_EXIT}"
            done

            if [ "${GROUNDING_EXIT}" -eq 1 ]; then
                log "ERROR: grounding_recheck.py import failure (exit 1). Halting."
                exit 1
            elif [ "${GROUNDING_EXIT}" -eq 2 ]; then
                log "WARNING: CONTRADICTED claims remain after 3 correction iterations."
                log "Human review required. Proceeding with current findings."
            else
                log "Grounding correction successful after ${CORRECTION_ITER} iteration(s). ✓"
            fi
        fi

        log "=== GROUNDING VERIFICATION COMPLETE ==="
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
