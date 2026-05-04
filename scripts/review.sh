#!/bin/bash
# scripts/review.sh — Local pre-push code review gate
# Final Version: Secured, Logic-Corrected, and Audit-Compliant

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
AUDIT_FILE="${REPO_ROOT}/audit/review.jsonl"
DEEPSEEK_MODEL="deepseek-v4-pro"
DEEPSEEK_ENDPOINT="https://api.deepseek.com/chat/completions"

declare -a FILES=()

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
    echo "ERROR: DEEPSEEK_API_KEY not set." >&2
    exit 1
fi

SYSTEM_PROMPT="You are a DFIR code review expert. Respond ONLY with a JSON object: {\"severity\": \"CRITICAL|MAJOR|NITPICK|CLEAN\", \"findings\": \"text\"}"

# ============================================================================
# Core Functions
# ============================================================================

call_deepseek_api() {
    local file_path="$1"
    local file_content
    file_content=$(head -c 10240 -- "$file_path")

    local file_size=$(wc -c < "$file_path")
    if [[ "$file_size" -gt 10240 ]]; then
        echo "  ⚠️  File exceeds 10KB ($file_size bytes) — reviewing first 10KB only" >&2
    fi

    local user_prompt
    user_prompt=$(jq -n --arg path "$file_path" --arg content "$file_content" \
        '"Review file: " + $path + "\n\nContent:\n" + $content + "\n\nApply CaseFile 7-Law rules."')

    local body
    body=$(jq -n --arg model "$DEEPSEEK_MODEL" --arg sys "$SYSTEM_PROMPT" --arg user "$user_prompt" \
        '{model: $model, response_format: {type: "json_object"}, messages: [{role: "system", content: $sys}, {role: "user", content: $user}]}')

    curl -s -X POST "$DEEPSEEK_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
        -d "$body" | jq -r '.choices[0].message.content // empty'
}

collect_files() {
    FILES=()
    if [[ $# -gt 0 ]]; then
        FILES+=("$@")
    else
        while IFS= read -r f; do
            [[ -f "$f" ]] && FILES+=("$f")
        done < <(git diff --name-only main..HEAD 2>/dev/null || git diff --name-only HEAD)
    fi
}

main() {
    collect_files "$@"

    if [[ ${#FILES[@]} -eq 0 ]]; then
        echo "No files to review."
        exit 0
    fi

    # Ensure audit directory exists (Forensic Law 6)
    mkdir -p "$(dirname "$AUDIT_FILE")"

    for file in "${FILES[@]}"; do
        # Robust binary check: only review text files
        if ! file -b --mime-type "$file" | grep -q "^text/"; then
            echo "Skipping binary file: $file"
            continue
        fi

        echo "Reviewing: $file"
        local response
        response=$(call_deepseek_api "$file")
        
        local severity
        severity=$(echo "$response" | jq -r '.severity // "UNKNOWN"')
        local findings
        findings=$(echo "$response" | jq -r '.findings // "N/A"')

        # --- AUDIT LOGGING (Satisfies Law 6) ---
        jq -n --arg ts "$(date -u +%FT%TZ)" --arg f "$file" --arg sev "$severity" --arg find "$findings" \
            '{timestamp: $ts, file: $f, severity: $sev, findings: $find}' >> "$AUDIT_FILE"

        echo "  Verdict: $severity"

        if [[ "$severity" == "CRITICAL" || "$severity" == "MAJOR" ]]; then
            echo "  ❌ BLOCKING: $file"
            exit 1
        fi
    done
    echo "✅ All files passed local review and were logged to audit/."
}

main "$@"
