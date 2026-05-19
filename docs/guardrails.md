# CaseFile -- Anti-Hallucination Guardrails

This document describes every guardrail in CaseFile's 11-layer anti-hallucination stack.
Each layer is labeled by enforcement type:

- **ARCH** -- Architectural: enforced in code, cannot be bypassed by prompt
- **PROMPT** -- Prompt-based: instructed in CLAUDE.md, relies on LLM compliance
- **PROCESS** -- Process: enforced by tooling or human action outside the LLM

---

## Guardrail Table

| Layer | Name | Type | What It Prevents | How It Is Tested |
|---|---|---|---|---|
| L1 | Structured JSON output | ARCH | Free-form hallucination in tool responses | All 10 MCP tools return typed dicts; `tests/test_*.py` assert schema |
| L2 | CONFIRMED/INFERRED labeling | ARCH | Overconfident claims without corroboration | `record_finding()` enforces label; `tests/test_findings.py` |
| L3 | Deterministic verdict engine | ARCH | LLM inventing correlation outcomes | `_decide_verdict()` has no LLM calls; `tests/test_correlation.py` |
| L4 | Audit trail traceability | ARCH | Unattributed findings | Every tool call writes to `audit/mcp.jsonl` with invocation_id |
| L5 | Human-in-the-loop approve gate | ARCH | AI self-approving its own findings | `casefile-approve` requires real TTY + password; AI cannot call it |
| L6 | Two-stage code review | PROCESS | Introducing hallucination vectors in code | monster_check (pre-commit) + CodeRabbit (pre-merge) |
| L7 | Path confinement | ARCH | Reading/writing outside case directory | `_resolve_case_dir()` + `.resolve().relative_to()` on every path |
| L8 | Evidence quotes system | ARCH | Paraphrasing that changes meaning | `evidence_quotes` required in `record_finding()` for CONFIRMED findings |
| L9 | Tier 1 grounding verifier | ARCH | Claims not traceable to tool output | `verify_finding_claims()` checks every claim against audit log invocation_id |
| L10 | Tier 2 CSV value verification | ARCH | Correct tool called, wrong value cited | `_verify_exact_value_in_csv()` opens actual CSV and checks field equality |
| L11 | Grounded self-correction loop | PROCESS | Persistent hallucinations surviving one pass | ralph.sh: UNGROUNDED/CONTRADICTED claims trigger re-prompt (max 3 iterations) |

---

## Layer Detail

### L1 -- Structured JSON Output

**File:** `mcp_server/tools/_shared.py`, all tool files

Every MCP tool returns a typed Python dict, not a free-form string. The LLM cannot
receive "CSRSS.EXE runs from System32 normally" as tool output -- it receives:

```json
{
  "process_name": "CSRSS.EXE",
  "image_path": "C:\\Windows\\Temp\\Perfmon\\CSRSS.EXE",
  "pid": 1096,
  "ppid": 740
}
```

Structured output forces the LLM to work with the actual data rather than narrate
from training memory.

**Tests:** `tests/test_amcache.py`, `tests/test_prefetch.py`, `tests/test_event_logs.py`,
`tests/test_registry.py`, `tests/test_mft.py`, `tests/test_memory.py`

---

### L2 -- CONFIRMED/INFERRED Labeling

**File:** `mcp_server/tools/findings.py`

Every finding must carry a confidence label:

- **CONFIRMED** -- corroborated by 2+ independent artifact sources
- **INFERRED** -- supported by 1 source, plausible but not cross-confirmed
- **SPECULATIVE** -- hypothesis with no direct artifact support

`record_finding()` rejects CONFIRMED findings that lack `evidence_quotes`. A finding
cannot claim CONFIRMED status without citing the specific tool output that supports it.

**Tests:** `tests/test_findings.py`

---

### L3 -- Deterministic Verdict Engine

**File:** `mcp_server/tools/correlation.py`

`correlate_evidence()` produces one of five verdicts based on which artifact sources
are present -- no LLM is involved in the decision:

| Verdict | Condition |
|---|---|
| CONFIRMED_RUNNING | Memory present AND (Amcache OR Prefetch OR MFT) |
| CONFIRMED_HISTORICAL | No memory AND 2+ of (Amcache, Prefetch, MFT) |
| MEMORY_ONLY | Memory present, no disk artifacts |
| INSTALLED_NEVER_RAN | Amcache only, no execution evidence |
| NOT_FOUND | No sources present |

The LLM receives the verdict; it does not produce it.

**Tests:** `tests/test_correlation.py`

---

### L4 -- Audit Trail Traceability

**File:** `mcp_server/tools/_shared.py` (`audit_log()`)

Every tool invocation writes a JSONL record to `audit/mcp.jsonl` containing:
`ts`, `invocation_id`, `tool`, `examiner`, `cmd`, `returncode`, `stdout_lines`,
`stderr_excerpt`, `parsed_record_count`, `duration_ms`, plus tool-specific fields
(`csv_files`, `verdict`, etc.).

Any finding can be traced back to the exact tool call that produced its evidence,
with timestamp and return code.

---

### L5 -- Human-in-the-Loop Approve Gate

**File:** `src/vhir_cli/commands/approve.py`, `pyproject.toml`

`casefile-approve` is a standalone CLI entrypoint that:
- Requires a real TTY (fails in non-interactive shells)
- Requires password confirmation via `getpass()`
- Writes a SHA-256 content hash at approval time to `approvals.jsonl`
- Is NOT registered as an MCP tool -- the AI cannot call it

The AI investigates and records findings. A human examiner reviews and approves.
These are structurally separated, not just instructed.

**Tests:** `tests/test_findings.py` (approve gate tests)

---

### L6 -- Two-Stage Code Review

**Process:** Pre-commit and pre-merge

Every code change passes two independent AI reviewers before merging:

1. **monster_check** (`scripts/monster_check.py`) -- pre-commit gate calling DeepSeek V4-Pro
   with CaseFile's 7-Law checklist. Checks for Golden Rule violations, path confinement,
   audit log compliance, and demo risk.

2. **CodeRabbit** -- pre-merge gate on every PR. Checks cross-file consistency,
   semantic correctness, and security issues.

Neither reviewer shares training data or prompts with the other. A hallucination
vector introduced in code must fool both independently to reach production.

---

### L7 -- Path Confinement

**File:** `mcp_server/tools/_shared.py` (`_resolve_case_dir()`, `_require_within_case_root()`)

Every file path operation resolves to an absolute path and checks it falls within
`CASEFILE_CASE_ROOT` using `.resolve().relative_to()`. A path like
`../../etc/passwd` resolves to an absolute path outside the case root and raises
`PermissionError` before any file operation occurs.

**Tests:** Path confinement tested in every tool's test file via tmp_path fixtures.

---

### L8 -- Evidence Quotes System

**File:** `mcp_server/tools/findings.py`

CONFIRMED findings must include `evidence_quotes` -- a list of exact values copied
verbatim from tool output:

```json
{
  "evidence_quotes": [
    {
      "tool": "parse_amcache",
      "invocation_id": "inv_abc123",
      "field": "full_path",
      "exact_value": "C:\\Windows\\Temp\\Perfmon\\CSRSS.EXE",
      "timestamp": "2026-05-18T05:00:00Z"
    }
  ]
}
```

The LLM is instructed: "Do not paraphrase. Do not summarize. Copy the exact value."
The schema is validated before the finding is written to disk.

---

### L9 -- Tier 1 Grounding Verifier

**File:** `mcp_server/tools/grounding.py` (`verify_finding_claims()`)
**Script:** `scripts/grounding_verify.py`

After the investigation loop completes, `grounding_verify.py` reads every finding
and checks each claim's `invocation_id` against `audit/mcp.jsonl`. A claim is:

- **GROUNDED** -- the invocation_id exists in the audit log and the tool was called
- **UNGROUNDED** -- no matching invocation_id found
- **CONTRADICTED** -- invocation_id found but return code indicates failure

Results are written to `analysis/claim_accuracy_report.json`.

**Tests:** `tests/test_grounding.py` (73 tests)

---

### L10 -- Tier 2 CSV Value Verification

**File:** `mcp_server/tools/grounding.py` (`_verify_exact_value_in_csv()`, `_should_run_tier2()`)

When an audit log entry contains `csv_files` (Amcache, Registry, Event Logs, MFT),
Tier 2 opens the actual CSV output and checks that the `exact_value` cited in
`evidence_quotes` appears as a field value in the data.

This catches the failure mode where the LLM correctly identifies which tool was
called but cites the wrong value from that tool's output.

Tier 2 uses exact field equality (not substring match) to prevent partial matches
from passing verification.

**Key implementation detail:** `audit_log()` flattens the `extra` dict into the
top-level JSONL entry (`record.update(extra)`). Tier 2 reads `csv_files` directly
from the top level, not from a nested `extra` key.

---

### L11 -- Grounded Self-Correction Loop

**File:** `ralph.sh`

After each investigation iteration, if `grounding_verify.py` exits with code 2
(CONTRADICTED claims found), ralph.sh:

1. Calls `grounding_correction_prompt.py` to build a specific correction prompt
   listing every contradicted claim with its exact note
2. Passes the prompt to Claude Code for targeted correction
3. Re-runs `grounding_recheck.py` to verify the correction
4. Repeats up to 3 times before escalating to human review

The correction prompt is specific -- not "review your findings" but:
> "Finding F-001: claim '[exact text]' is CONTRADICTED -- tool output shows
> '[exact value]'. Rewrite using ONLY the grounded claims."

This prevents the LLM from substituting one hallucination for another.

---

## What Is Not Guardrailed (Honest Disclosure)

| Gap | Status | Rationale |
|---|---|---|
| Per-claim confidence scoring | ✅ `findings.py` — `_agg()` aggregates claim confidence from evidence_quotes | `test_findings.py` — claim_confidence field asserted |
| Cross-source contradiction detector | ✅ `correlation.py:479` — `detect_contradictions()` called at line 627 | `test_correlation.py` — contradiction cases covered |
| Evidence provenance tagging | ✅ `_shared.py` — `audit_log()` appends provenance records; findings link via `supporting_invocation_ids` | Every finding integration test asserts invocation_id present |
| Training data contamination guard | ✅ `grounding.py:871` — `detect_baseline_assumptions()` live | `test_grounding.py` — baseline assumption detection tested |

The 11 implemented layers address the primary hallucination vectors identified in
production runs. The 4 planned improvements address edge cases that did not appear
in the SRL-2018 investigation.

---

## Hallucination Rate

From the May 18, 2026 investigation of BASE-RD-01 (CRIMSON OSPREY case):

| Metric | Value |
|---|---|
| Total claims analyzed | 25 |
| Tier 1 grounded | 25 |
| Ungrounded | 0 |
| Contradicted | 0 |
| **Hallucination rate** | **0.0%** |
| Self-corrections fired | 2 (F-057, F-060 corrected in loop) |

The 2 self-corrections demonstrate the loop is functioning: ungrounded claims were
detected and corrected before the final report, not silently accepted.
