#!/usr/bin/env python3
"""
scripts/grounding_correction_prompt.py
========================================
Reads analysis/claim_accuracy_report.json and prints a specific correction
prompt listing every CONTRADICTED claim with its exact note.

Called by ralph.sh correction loop. Output is piped to `claude -p`.

Environment variables:
  CASE_DIR — path to the case directory
"""
import json
import os
import sys
from pathlib import Path

case_dir = os.environ.get("CASE_DIR", ".")
report_path = Path(case_dir) / "analysis" / "claim_accuracy_report.json"

if not report_path.exists():
    print(
        "CORRECTION REQUIRED: Some findings could not be verified against tool outputs. "
        "Re-run the relevant MCP tools and update findings with exact values from tool output. "
        "Do NOT add new claims without running a tool first. "
        "Re-output <promise>TASK_COMPLETE</promise> when all claims are grounded."
    )
    sys.exit(0)

try:
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
except (OSError, ValueError) as exc:
    print(
        f"CORRECTION REQUIRED: Could not read claim accuracy report ({exc}). "
        "Call get_findings() via MCP to inspect current findings. "
        "For each finding with CONTRADICTED or UNGROUNDED evidence_quotes, "
        "call record_finding() via MCP with corrected exact values from the audit log. "
        "Re-output <promise>TASK_COMPLETE</promise> when all claims are grounded."
    )
    sys.exit(0)

lines = [
    "GROUNDING CORRECTION REQUIRED:",
    f"Hallucination rate: {report.get('hallucination_rate', '?')}",
    f"Contradicted claims: {report.get('contradicted', '?')}",
    "",
    "The following claims are CONTRADICTED (tool output does not support them):",
]

# Collect CONTRADICTED and UNGROUNDED independently — both must always
# be shown. Previously UNGROUNDED were suppressed when CONTRADICTED existed,
# causing the self-correction loop to miss incomplete corrections.
contradicted_lines = []
ungrounded_lines = []
for fdata in report.get("findings", []):
    fid = fdata.get("finding_id", "<unknown>")
    for claim in fdata.get("claims", []):
        status = claim.get("status")
        if status == "CONTRADICTED":
            contradicted_lines.append(
                f"  Finding {fid}: claim '{claim.get('claim_text', '')[:120]}'"
                f"\n    Reason: {claim.get('note', '')}"
            )
        elif status == "UNGROUNDED":
            ungrounded_lines.append(
                f"  Finding {fid} UNGROUNDED: '{claim.get('claim_text', '')[:120]}'"
            )

if contradicted_lines:
    lines.append("CONTRADICTED claims (tool output does not support them):")
    lines.extend(contradicted_lines)
else:
    lines.append("  (No CONTRADICTED claims found.)")

if ungrounded_lines:
    lines.append("UNGROUNDED claims (no tool output found for these):")
    lines.extend(ungrounded_lines)
else:
    lines.append("  (No UNGROUNDED claims found.)")
lines += [
    "",
    "For each CONTRADICTED or UNGROUNDED claim:",
    "  1. Call get_findings() via MCP to retrieve the current finding.",
    "  2. Inspect the audit/mcp.jsonl entries for the relevant tool calls.",
    "     The invocation_id is in each audit entry — use it to find the exact",
    "     tool output that was actually produced.",
    "  3. Call record_finding() via MCP with corrected evidence_quotes.",
    "     Each evidence_quote MUST use exact_value that is ONE verbatim field",
    "     value from the parser CSV output — a single cell value, not a composite",
    "     summary string. For EvtxECmd: use PayloadData1/PayloadData2/TimeCreated.",
    "     For AmcacheParser: use Name/SHA1/FullPath field values verbatim.",
    "     CORRECT: \"exact_value\": \"Name: LARIAT\"",
    "     WRONG:   \"exact_value\": \"EID=7045 ServiceName=LARIAT executable=...\"",
    "     Do NOT construct composite strings. Copy ONE CSV cell value exactly.",
    "  4. If the audit log does not contain a value that supports the claim,",
    "     remove the claim entirely and re-label the finding as INFERRED",
    "     with explicit reasoning in the interpretation field.",
    "  5. Do NOT add new claims without a corresponding audit log entry.",
    "",
    "When all claims are corrected, re-output <promise>TASK_COMPLETE</promise>.",
]

print("\n".join(lines))
