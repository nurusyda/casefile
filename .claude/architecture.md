# CaseFile — Thought Process & Flow

# CaseFile: The Thought Process

Let me walk through this project the way I'd explain it to a new teammate who just joined the forensics team.

## 1. The Core Problem

**What problem does CaseFile actually solve?**

The fundamental problem is: LLMs hallucinate forensic findings. When you ask Claude Code to analyze evidence, it will confidently tell you things that aren't true — citing tool output that doesn't exist, inventing process names, making up correlation logic.

But there's a second, subtler problem: even if the AI gets things right, *how do you know*? The human examiner can't re-run every tool call. You need something between the AI's brain and the final report that says "actually verify this claim against real data."

CaseFile is an **anti-hallucination architecture** wrapped around an autonomous forensic agent. The parsers and tools are table stakes. The real innovation is the grounding infrastructure — a deterministic verification layer that catches AI lies before they reach the human.

## 2. Key Design Decisions and Their Rationale

### Decision 1: MCP Server as Strict Middleware (Not a Chatbot)

**What:** All forensic tools are wrapped as typed Python functions behind an MCP server (`mcp_server/server.py`). Claude Code never runs raw shell commands.

**Why:** Look at `mcp_server/server.py` line 7-8:
```python
# All tool output is parsed server-side before returning to LLM
# LLM never receives raw shell output
```

This is the first line of defense. If Claude never sees raw shell output, it can't hallucinate about what a tool said. The server parses CSV output, extracts structured data, and returns clean JSON. The AI only ever works with structured data — which is verifiable.

The import list shows every tool that exists. Tools are registered as MCP functions via `mcp.tool()`. This creates a strict API surface: Claude can only call these 17 functions. No `subprocess.run()`, no `os.system()`.

### Decision 2: Deterministic Correlation Engine (No LLM)

**What:** `correlate_evidence()` in `mcp_server/tools/correlation.py` uses a pure decision tree. No AI involvement in cross-source analysis.

**Why:** Look at the verdict logic — it's a simple decision tree (`_decide_verdict()`):

```python
if in_memory and has_execution: -> CONFIRMED_RUNNING
if in_memory and not has_execution and not on_disk: -> MEMORY_ONLY  
if not in_memory and has_execution: -> CONFIRMED_HISTORICAL
if not in_memory and not has_execution and on_disk: -> INSTALLED_NEVER_RAN
else: -> NOT_FOUND
```

This is intentionally dumb. No LLM, no probability, no fuzzy matching. The reason is critical: if the correlation logic itself hallucinates, there's no way to catch it — correlation is supposed to be the ground truth. By making it a pure function (no I/O, no state, no randomness), the verdict is deterministic and replicable.

The `VERDICTS` frozenset and `_VERDICT_CONFIDENCE` mapping enforce a closed set of possible outcomes. No creative labeling.

### Decision 3: Two-Tier Grounding (Anti-Hallucination Stack)

**What:** `mcp_server/tools/grounding.py` implements Tier 1 (invocation attestation) and Tier 2 (CSV value verification). This is NOT prompt engineering — it's code.

**Why:** The file header says it all:

> Phase 1 (this file) implements: validate_evidence_quotes(), verify_finding_claims(), get_attested_sources(), assert_sources_attested(), detect_baseline_assumptions(), build_claim_accuracy_report()
>
> Design principles (must not violate):
> - No LLM in the verification path. Every function here is deterministic.
> - Read-only access to audit/mcp.jsonl. Never write or mutate it.

The grounding layer reads the immutable audit log (`audit/mcp.jsonl`) and checks whether each evidence claim in a finding corresponds to a real tool invocation. If Claude says "I called `parse_amcache` and found `subject_srv.exe`", the grounding layer checks: was `parse_amcache` actually called? What invocation ID was logged? Did the output actually contain that executable name?

The `_TOOL_NAME_ALIASES` dict is a subtle but important detail — Claude calls tools by logical names (`parse_prefetch`) but the audit log records the canonical tool class name (`pyscca`). Without this alias map, every single Prefetch finding would be flagged as "CONTRADICTED" because the names don't match. This was discovered in a run and fixed in commit `e40af44`.

### Decision 4: The ralph.sh Self-Correction Loop

**What:** `ralph.sh` doesn't just run Claude once. It runs Claude in a loop, checks for a completion signal (`TASK_COMPLETE`), then runs grounding verification. If verification fails, it sends a correction prompt and re-runs.

**Why:** The story in the README tells you why:
> On our May 18 run: 6 findings, 19 contradicted claims, hallucination rate 1.0. After 1 correction iteration: 0.0.

The architecture acknowledges that Claude *will* hallucinate. The question is not "how do we prevent all hallucination" — that's impossible. The question is "how do we catch and correct it before the report reaches the human?"

The loop in `ralph.sh`:

```bash
while [ "${iteration}" -lt "${MAX_ITER}" ]; do
    # Run Claude with investigation prompt
    # Check for TASK_COMPLETE signal
    # Run grounding verification
    # If contradicted: build correction prompt, re-run
done
```

The iteration count is read dynamically from `prd.json` via `scripts/read_max_iter.py`. If the output is suspiciously short (< 100 chars), it exits immediately (rate limit guard added in commit `7435925`).

### Decision 5: Atomic Writes and Audit Trail

**What:** Every finding write goes through `_write_json()` with a `.tmp` file + rename. Every tool invocation is logged to `audit/mcp.jsonl`. The audit log is **append-only** — never mutated.

**Why:** Forensic integrity. If the process crashes mid-write, you don't get a corrupted findings file. If someone — or something — tries to alter the audit trail, the append-only design means the original records are still there (well, unless they delete the file, but that would be obvious).

In `findings.py`:
```python
def _write_json(path: Path, data: list) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    shutil.move(str(tmp), str(path))
```

This is a standard technique but crucial in a forensic context where every byte matters.

## 3. Major Components and Why They Exist

### MCP Server (`mcp_server/server.py`)
**Why it exists:** Provides a structured API surface that Claude Code must use. This is the outermost shell of the anti-hallucination onion — Claude cannot run arbitrary commands; it can only call these 17 functions. This is not a convenience layer; it's a cage.

### Tools Directory (`mcp_server/tools/*.py`)
Each tool file wraps a real SIFT forensic parser:
- `prefetch.py` → calls `pyscca`
- `memory.py` → calls `Volatility3`
- `event_logs.py` → calls `EvtxECmd`
- `amcache.py` → calls `AmcacheParser`
- `registry.py` → calls `RECmd`
- `mft.py` → calls `MFTECmd`
- `shellbags.py` → calls `SBECmd.dll`

**Why each tool exists separately:** Each tool has different parsing logic, different output formats, and different failure modes. By wrapping them as individual MCP tools, we get typed parameters, structured return values, and per-tool error handling. More importantly, each tool call is individually logged in the audit trail, making per-claim verification possible.

### Correlation Tool (`mcp_server/tools/correlation.py`)
**Why it exists:** Cross-source correlation is the #1 thing human examiners do manually — check Amcache + Prefetch + MFT + Memory to determine if a process was actually running vs. just installed. Making this deterministic removes the LLM's ability to hallucinate correlations. The path confinement helper (`_enforce_case_root`, `_resolve_case_dir`) prevents the correlation engine from reading outside the case directory.

### Grounding Infrastructure (`mcp_server/tools/grounding.py`)
**Why it exists:** This is the heart of the project. Everything else supports this. The grounding layer reads the audit log and verifies claims. Period. The functions `verify_finding_claims()` and `build_claim_accuracy_report()` are what separates CaseFile from "LLM + some parsers."

The `GroundingError` vs. `GroundingSchemaError` distinction matters: schema errors (malformed quotes) always raise so the finding cannot be recorded with bad data. Policy violations (CONFIRMED without quotes) are warnings for now — they recognized that not all code has been updated to supply quotes yet (Phases 1 vs. 2).

### ralph.sh
**Why it exists:** The self-correction loop is the safety net. Even with all the guardrails, the AI can still produce incorrect claims. The loop catches this, sends a targeted correction prompt, and re-verifies. The README documents a case where this caught 19 contradicted claims in one run and corrected them in one iteration.

### monster_check.py
**Why it exists:** This is a pre-commit review script that runs code through py_compile and sends diffs to DeepSeek for review. It exists because they discovered that hallucination vectors can be introduced in *code changes* — not just in AI output. It's a meta-guardrail: checking that the code that implements the guardrails is itself correct.

### export_findings.py
**Why it exists:** To make findings ingestible by SIEMs. ECS v8 and OCSF v1.3 formats. This is a practical decision: if you can't ship findings to a SIEM, it's just a report generator.

## 4. The Full Flow

Here's what happens from "user runs the tool" to "result comes out":

### Step 1: User runs `bash ralph.sh ~/cases/CASE001`

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASE_DIR="${1:-${CASEFILE_CASE_ROOT:-.}}"
CASEFILE_CASE_DIR="${CASEFILE_CASE_DIR:-${CASE_DIR}}"
```

`ralph.sh` determines the case directory, creates the `analysis/`, `reports/`, and `audit/` subdirectories, and generates `.mcp.json` with the correct environment variables injected via `jq` (not string interpolation — this avoids shell injection).

### Step 2: Claude Code starts investigation (Iteration 1)

`ralph.sh` sends the investigation prompt to Claude:
> "Read CLAUDE.md and prd.json. Begin the investigation of the current case. Work through the OODA loop. Call MCP tools. Document all findings with CONFIRMED/INFERRED/HYPOTHESIS labels."

Critically, the prompt also instructs Claude on the **evidence_quotes requirement** — every `record_finding()` call must include:
```json
{
  "tool": "parse_amcache", 
  "claim": "subject_srv.exe present in Amcache",
  "invocation_id": "inv_abc123",
  "exact_value": "C:\\Windows\\Temp\\subject_srv.exe"
}
```

### Step 3: Claude calls MCP tools

Claude calls `parse_amcache()`, `parse_memory()`, `correlate_evidence()`, etc. Each call is:
1. Routed through the MCP server
2. Executed as a SIFT tool against actual evidence
3. Parsed into structured JSON
4. Logged to `audit/mcp.jsonl` with an `invocation_id`
5. Returned to Claude (structured only — no raw shell output)

### Step 4: Claude writes findings

Claude calls `record_finding()` with evidence_quotes attached. The server validates the schema (no malformed quotes), writes the DRAFT finding to `findings.json`, and logs provenance tags back to the audit log.

### Step 5: Completion check

Claude emits `<promise>TASK_COMPLETE: [N] confirmed, [M] inferred, [K] self-corrections</promise>`. `ralph.sh` catches this signal.

### Step 6: Grounding verification

`ralph.sh` calls `scripts/grounding_verify.py` which:
1. Loads `findings.json`
2. For each finding, reads the `evidence_quotes`
3. Looks up each `invocation_id` in `audit/mcp.jsonl`
4. Verifies the tool was called and the claim matches the output
5. Produces a `claim_accuracy_report.json` with per-claim status (GROUNDED/UNGROUNDED/CONTRADICTED/INFERRED_LABELED)

### Step 7: Self-correction (if needed)

If any claims are CONTRADICTED, `ralph.sh` sends a correction prompt to Claude:
> "Your previous findings had contradictions. Here's what was wrong: [specific claims]. Fix them."

This isn't a generic "please try again" — it targets specific contradicted claims.

### Step 8: Final output

After the correction loop completes (or max iterations reached), the human examiner gets:
- `findings.json` — all DRAFT findings with verification metadata
- `claim_accuracy_report.json` — the verification results  
- `reports/` — HTML/PDF report generated by `scripts/generate_html_report.py`

## 5. Tensions and Trade-offs

### Trade-off 1: Structured Output vs. Rich Analysis

The MCP tools return structured JSON. This is great for verification — you can check exact field values. But it means Claude loses the context that raw tool output provides. A human reading `pyscca` output sees the full parse; Claude gets a summarized table.

**Commit `2af239b` shows this:** They had to fix Amcache `exact_value` examples because the tool summary format vs. CSV cell format caused the AI to use different strings for the same value.

### Trade-off 2: Deterministic Correlation vs. Nuanced Analysis

`correlate_evidence()` uses a simple decision tree. It's correct for the common cases, but it can't handle edge cases like "process appears in Amcache with different path than MFT — is this DLL sideloading or a rename?"

The tension is between correctness (deterministic = never wrong in the way the AI would be) and completeness (it misses some patterns). They handled this by having `correlate_evidence()` return a verdict, but Claude can still enrich it with additional context in the finding text. The trade-off accepts reduced subtlety for guaranteed non-hallucinated correlation.

### Trade-off 3: Self-Correction Loop Performance vs. Reliability

Each iteration of `ralph.sh` costs money (API calls to Claude) and time (the full analysis loop). Setting `MAX_ITER=25` means a worst-case of 25 complete investigation passes. That's expensive.

But the alternative — letting a hallucinated finding through — is worse in a forensic context. The commit `7435925` (rate limit early exit guard) shows they encountered this tension: if Claude hits a rate limit and returns empty output, the loop should fail fast, not waste money on useless retries.

### Trade-off 4: Audit Log Completeness vs. Performance

Every MCP tool call is logged to `audit/mcp.jsonl`. Every finding write generates provenance tags. Every verification check reads the audit log. This is a lot of I/O.

But in forensics, *the audit trail is the evidence*. Skipping audit entries to save milliseconds would undermine the entire verification architecture. The trade-off is explicitly accepted: the grounding file header says "Read-only access to audit/mcp.jsonl. Never write or mutate it."

### Trade-off 5: AI Autonomy vs. Human Control

`record_finding()` can only produce DRAFT findings. The `approve` command is blocked in `BLOCKED_COMMANDS` — Claude literally cannot approve its own findings. The password gate requires human TTY interaction.

This is a design tension: you want Claude to be autonomous enough to investigate thoroughly, but not so autonomous that it circumvents the human examiner. The `BLOCKED_COMMANDS` frozenset includes `approve` and `approve_finding` as explicit limitations.

### Trade-off 6: The Patch File Proliferation

Look at the file tree: there are **15 patch files** (`patch_*.py`, `fix_gap*.py`). These are one-off fixes applied during development to address specific issues discovered in runs. Each one represents a real vulnerability that was caught:

- `patch_ralph_ratelimit.py` — rate limit handling
- `patch_grounding_resolve_both.py` — tool name resolution on both sides
- `patch_tool_name_aliases.py` — the alias map fix
- `patch_detect_host_type.py`, `patch_detect_host_type_fix.py`, `patch_detect_host_type_fix2.py` — three iterations to get host type detection right

The trade-off here is between "ship fixes fast" and "code quality." They chose fast, accepting that some fixes would be replaced or refactored later. The commit history bears this out: `8e2c7b0` introduces `detect_host_type()`, then `33212db` wires it into the OODA loop, then two more patches refine it.

## The Bottom Line

CaseFile is not a forensic tool. It's a verification architecture that happens to include forensic tools. Every design decision — from the MCP server middleware to the two-tier grounding to the self-correction loop — exists to answer one question: "How do I know this AI isn't lying to me?"

The answer is: you don't trust the AI.
