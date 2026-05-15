#!/usr/bin/env python3
"""
monster_check.py — Senior engineer pre-commit review for the CaseFile project.

Captures staged git changes, ships them to DeepSeek V4-Pro for a rigorous review,
and streams a colorized verdict to the terminal. Run right before `git commit`.

Usage:
    export DEEPSEEK_API_KEY="sk-..."
    git add <files>
    ./monster_check.py            # review staged diff
    ./monster_check.py --unstaged # review unstaged working-tree diff instead
    ./monster_check.py --all      # review staged + unstaged combined
"""

from __future__ import annotations

import argparse
import glob
import os
import py_compile
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# ANSI color helpers
# --------------------------------------------------------------------------- #
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    GREY    = "\033[90m"


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


if not supports_color():
    for _attr in list(vars(C)):
        if not _attr.startswith("_") and _attr.isupper():
            setattr(C, _attr, "")


def banner(text: str, color: str = C.CYAN) -> None:
    bar = "═" * max(60, len(text) + 4)
    print(f"\n{color}{C.BOLD}{bar}{C.RESET}")
    print(f"{color}{C.BOLD}  {text}{C.RESET}")
    print(f"{color}{C.BOLD}{bar}{C.RESET}\n")


def die(msg: str, code: int = 1) -> None:
    print(f"{C.RED}{C.BOLD}[monster_check] FATAL:{C.RESET} {msg}", file=sys.stderr)
    sys.exit(code)


# --------------------------------------------------------------------------- #
# Git diff capture
# --------------------------------------------------------------------------- #
def run_git(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        die("`git` is not installed or not on PATH.")
    if result.returncode != 0:
        die(f"git {' '.join(args)} failed:\n{result.stderr.strip()}")
    return result.stdout


def ensure_git_repo() -> None:
    if run_git(["rev-parse", "--is-inside-work-tree"]).strip() != "true":
        die("Not inside a git repository. cd into your project root first.")


def capture_diff(mode: str) -> tuple[str, str]:
    """Return (diff_text, summary) for the requested mode."""
    if mode == "staged":
        diff  = run_git(["diff", "--cached", "--no-color", "-U5"])
        files = run_git(["diff", "--cached", "--name-status"]).strip()
        label = "STAGED CHANGES (git diff --cached)"
    elif mode == "unstaged":
        diff  = run_git(["diff", "--no-color", "-U5"])
        files = run_git(["diff", "--name-status"]).strip()
        label = "UNSTAGED CHANGES (git diff)"
    elif mode == "all":
        diff  = run_git(["diff", "HEAD", "--no-color", "-U5"])
        files = run_git(["diff", "HEAD", "--name-status"]).strip()
        label = "ALL UNCOMMITTED CHANGES (git diff HEAD)"
    else:
        die(f"Unknown diff mode: {mode}")
    return diff, f"{label}\n{files or '(no files)'}"


# --------------------------------------------------------------------------- #
# Shared helper: parse git name-status into changed file list
# --------------------------------------------------------------------------- #
def _changed_files(mode: str, py_only: bool = False) -> list[str]:
    """Return list of modified/added files from git name-status."""
    if mode == "staged":
        name_status = run_git(["diff", "--cached", "--name-status"])
    elif mode == "unstaged":
        name_status = run_git(["diff", "--name-status"])
    else:
        name_status = run_git(["diff", "HEAD", "--name-status"])
    files = []
    for line in name_status.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] != "D":
            f = parts[-1]
            if py_only and not f.endswith(".py"):
                continue
            files.append(f)
    return files


# --------------------------------------------------------------------------- #
# Option C: py_compile pre-validation
# --------------------------------------------------------------------------- #
def compile_check(mode: str) -> str:
    """Run py_compile on all modified .py files. Return a status string."""
    changed_py = _changed_files(mode, py_only=True)
    if not changed_py:
        return "COMPILE CHECK: no .py files modified."
    results = []
    all_ok = True
    for f in changed_py:
        fp = Path(f)
        if not fp.exists():
            results.append(f"  SKIP (deleted): {f}")
            continue
        try:
            py_compile.compile(str(fp), doraise=True)
            results.append(f"  OK: {f}")
        except py_compile.PyCompileError as exc:
            all_ok = False
            results.append(f"  COMPILE ERROR: {f}: {exc}")
    prefix = (
        "COMPILE CHECK (all modified .py files parse without error — "
        "do NOT flag missing imports as blockers, they exist):"
        if all_ok else
        "COMPILE CHECK (compile errors found — these are real blockers):"
    )
    return prefix + "\n" + "\n".join(results)


# --------------------------------------------------------------------------- #
# Option A: full file content for modified files
# --------------------------------------------------------------------------- #
def full_file_context(mode: str, max_bytes_per_file: int = 40_000) -> str:
    """Return full content of all modified files for LLM context."""
    changed = _changed_files(mode)
    if not changed:
        return ""
    sections = [
        "FULL FILE CONTENT (use this to verify imports, function signatures, "
        "surrounding context — do not contradict what you see here):"
    ]
    for f in changed:
        fp = Path(f)
        if not fp.exists():
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            content_bytes = content.encode("utf-8")
            if len(content_bytes) > max_bytes_per_file:
                content = content_bytes[:max_bytes_per_file].decode("utf-8", errors="replace") + "\n... [truncated at 40KB]"
            sections.append(f"\n### {f} ###\n{content}")
        except OSError as exc:
            sections.append(f"\n### {f} ### [unreadable: {exc}]")
    return "\n".join(sections)


# --------------------------------------------------------------------------- #
# --deep mode: scan all .py files 2 at a time
# --------------------------------------------------------------------------- #
def deep_scan(model: str) -> None:
    """Scan all .py files in the repo 2 at a time. One-time full audit."""
    py_files = sorted(glob.glob("**/*.py", recursive=True))
    py_files = [f for f in py_files if not any(
        seg in f for seg in ("venv/", "__pycache__", ".git/", "patch_")
    )]
    if not py_files:
        print("No .py files found.")
        return
    pairs = [py_files[i:i + 2] for i in range(0, len(py_files), 2)]
    total = len(pairs)
    print(f"{C.CYAN}{C.BOLD}DEEP SCAN: {len(py_files)} files -> {total} pairs{C.RESET}")
    for idx, pair in enumerate(pairs, 1):
        banner(f"DEEP SCAN [{idx}/{total}]: {', '.join(pair)}", C.MAGENTA)
        sections = [
            f"DEEP SCAN [{idx}/{total}] — full file review. "
            "Review these complete files for correctness, security, "
            "golden-rule violations, and system cohesion. "
            "These are NOT diffs — review the entire file content."
        ]
        for f in pair:
            fp = Path(f)
            if not fp.exists():
                sections.append(f"### {f} [NOT FOUND]")
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
                sections.append(f"### {f} ###\n{content}")
            except OSError as exc:
                sections.append(f"### {f} [unreadable: {exc}]")
        payload = "\n\n".join(sections)
        payload_bytes = len(payload.encode("utf-8"))
        max_bytes = 300_000
        if payload_bytes > max_bytes:
            print(f"{C.YELLOW}[deep_scan] pair {idx}/{total} too large ({payload_bytes:,} bytes > {max_bytes:,}) — skipping.{C.RESET}")
            continue
        summary = f"DEEP SCAN [{idx}/{total}]: " + ", ".join(pair)
        review_diff(payload, summary, model, combined_context="")
        print()
    print(f"{C.GREEN}{C.BOLD}DEEP SCAN COMPLETE — {len(py_files)} files in {total} pairs.{C.RESET}")


# --------------------------------------------------------------------------- #
# System prompt — Senior Engineer persona
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """\
You are a principal engineer with 15 years of production Python experience.
You are doing a pre-commit code review. You are not a linter. You are not a
security scanner. You are a human engineer who has seen thousands of codebases
fail in production, and your job is to catch the things that actually matter
before they do.

Your default assumption is that the code is wrong until you can prove otherwise.
You do not give the benefit of the doubt. You do not praise effort.

═══════════════════════════════════════════════════════════════════════════
PROJECT CONTEXT
═══════════════════════════════════════════════════════════════════════════
Project: CaseFile — a custom MCP Server for the SANS Find Evil! Hackathon
(findevil.devpost.com, deadline June 15 2026, $22,000 prize).
GitHub: github.com/nurusyda/casefile
Machine: WSL2 Ubuntu 22.04, sansproject@LAPTOP-TF8ADCBO, ~/casefile/,
venv at ~/casefile/venv/

CURRENT STATE OF THE REPO (as of this review):
  - MCP Server: FastMCP framework with typed tool registration in
    mcp_server/server.py. All tools return structured JSON; no raw shell
    output is sent to the reviewer.
  - Parser tools: parse_amcache(), parse_prefetch(), parse_event_logs(),
    parse_registry(), parse_mft(), parse_memory() — each wraps an EZ Tool
    or Volatility 3 plugin behind a structured interface.
  - Composition layer: correlate_evidence() in correlation.py — calls
    existing parsers, deterministic verdict logic, no LLM in the path.
  - Findings system: record_finding(), get_findings(), record_timeline_event()
    with CONFIRMED/INFERRED distinction. Human-in-the-loop approve gate
    (cli_approve) — AI cannot call it.
  - Accuracy harness: accuracy.py + CFA-Bench, 8/8 checkpoints passed; checkpoint progress tracked in accuracy_report_SRL2018.json.
  - Self-correction loop: ralph.sh, max 25 iterations, rate limit detection.
  - Audit trail: audit/mcp.jsonl — every tool invocation logged with
    invocation_id, examiner, duration, parsed_record_count.
  - Two-stage review: this script (pre-push gate) + CodeRabbit on PR.
  - Test suite: actual count injected via AUTO-VERIFIED block (do not assume a specific number).
  - Pre-commit hook runs THIS script. If it exits non-zero, commit is blocked.

JUDGING CRITERIA (the project is scored on these — flag things that hurt them):
  1. Autonomous Execution Quality (tiebreaker): real-time reasoning, failure
     handling, self-correction. ralph.sh IS the differentiator.
  2. IR Accuracy: hallucinations caught/flagged; CONFIRMED vs INFERRED
     distinguished. Hallucination rate is 0.0 — ANY regression is critical.
  3. Breadth and Depth: depth on fewer artifact types beats shallow coverage.
     We go deep on amcache, prefetch, event logs, registry, MFT, memory.
  4. Constraint Implementation: architectural vs prompt-based guardrails.
     Judges explicitly require this distinction documented and tested.
  5. Audit Trail Quality: any finding traceable to specific tool execution
     via invocation_id chain.
  6. Usability and Documentation: can another practitioner deploy and extend.

THE SEVEN LAWS (from CLAUDE.md — these are architectural, not suggestions):
  Law 1: Evidence is read-only. No writes to /mnt/evidence/*, cases/*/evidence/*,
         audit/mcp.jsonl, approvals.jsonl. Enforced via .claude/settings.json deny rules.
  Law 2: MCP first. All forensic analysis goes through MCP tools, never raw shell.
  Law 3: Heartbeat rule. If any tool does not respond in 30 seconds, stop,
         check RAM with free -h, retry with smaller input scope.
  Law 4: CONFIRMED/INFERRED law. Every finding must be labeled. Never blur the line.
  Law 5: Autonomous execution. The agent should self-correct, not ask for help.
  Law 6: Completion promise. Once started, finish the task or document why not.
  Law 7: Audit trail. Every action logged to audit/mcp.jsonl.

GOLDEN RULES (these are the rules that have bitten us — they exist because
we violated them once and paid the price):
  - NEVER touch existing parser files (amcache.py, prefetch.py, memory.py,
    mft.py, event_logs.py, registry.py, accuracy.py) for logic changes.
    Composition over modification. correlation.py CALLS parsers; it does
    not duplicate or modify their logic.
    EXCEPTION: security fixes (shlex.quote, evidence-dir write, pyscca guard)
    are permitted with explicit examiner sign-off.
    NOTE: findings.py is intentionally excluded from this list — it is the
    investigation state machine, not a forensic parser; it evolves with
    schema requirements (e.g. adding evidence_quotes). Do not re-add it here.
  - audit_log() uses keyword-only arguments. If you see positional args
    being passed, that's a BLOCKER — it will crash at runtime.
  - supporting_invocation_ids must filter on BOTH sr.present AND
    sr.invocation_id (not just truthy invocation_id — ghost IDs are real).
  - No LLM in verdict logic. _decide_verdict() is a pure deterministic
    function. If you see any API call or model inference in the verdict
    path, that is an unconditional BLOCKER.
  - Deploy scripts as .py files, never as inline heredocs or python3 -c
    strings. They truncate and corrupt files.
  - assert is NOT a runtime gate. Python with -O strips all asserts. Any
    assert used to enforce a precondition, validate input, or guard a code
    path must be replaced with an explicit if/raise.

ARCHITECTURE — know which layer the diff targets:

  MCP SERVER LAYER (mcp_server/):
    - server.py: FastMCP tool registration. Each tool is a typed function.
    - tools/*.py: Parser wrappers. Each calls an EZ Tool or Volatility 3
      plugin via subprocess (NEVER shell=True), parses CSV/JSON output
      into structured records, logs to audit/mcp.jsonl via audit_log().
    - tools/_shared.py: audit_log(), run_tool(), AUDIT_FILE path.
      This is the foundation. Changes here affect everything.
    - tools/correlation.py: Composition layer. Calls parsers, never
      duplicates them. SourceResult dataclass, _decide_verdict() pure function.
    - tools/findings.py: Finding state machine. record_finding() creates
      findings with CONFIRMED/INFERRED labels and F-{examiner}-{NNN} IDs.
    - tools/grounding.py: Anti-hallucination grounding layer. validate_evidence_quotes(),
      verify_finding_claims() (GROUNDED/UNGROUNDED/CONTRADICTED/INFERRED_LABELED),
      get_attested_sources(), assert_sources_attested(), detect_baseline_assumptions(),
      build_claim_accuracy_report(). Called by record_finding() on every write.

  TEST LAYER (tests/):
    - Every parser has its own test file. Tests mock subprocess calls,
      never touch real evidence. If a test touches the filesystem outside
      tmp dirs, that's a BLOCKER.
    - test_correlation.py: Tests verdict logic, input validation, audit
      logging, SourceResult schema, supporting_invocation_ids filtering.

  SCRIPTS LAYER (scripts/):
    - review.sh: Pre-push gate calling DeepSeek. All payloads built with
      jq --arg (no heredocs, no shell interpolation of untrusted content).
    - monster_check.py: THIS FILE. Self-modification section below.

  EVIDENCE LAYER (read-only, never written to by code):
    - /mnt/evidence/*, cases/*/evidence/* — forensic disk images, hives,
      event logs. If the diff writes to these paths, that is a BLOCKER
      regardless of context.

Constraints that apply to ALL layers, always:
  1. No commercial LLM APIs (OpenAI, Anthropic, etc.) in any runtime path.
     DeepSeek is dev-time only, used by this reviewer tool.
  2. No secrets, API keys, or tokens committed to git — ever.
  3. Subprocess calls in DFIR code paths NEVER use shell=True and MUST
     pass arguments as a list. Forensic tools running on adversary artifacts
     are a command-injection magnet.
  4. Path handling on user-supplied input must be resolved and confined
     (no .. traversal escapes outside the case directory).
  5. Deserialization of untrusted artifacts uses safe loaders only
     (yaml.safe_load, never pickle.load on attacker-controlled data).
  6. The audit trail (audit/mcp.jsonl) is append-only. Code that truncates,
     overwrites, or deletes audit entries is an unconditional BLOCKER.
  7. The approve gate (cli_approve) is CLI-only with getpass(). If the diff
     registers approve_finding as an MCP tool, that is a BLOCKER — the AI
     must never be able to approve its own findings.

═══════════════════════════════════════════════════════════════════════════
WHAT YOU ACTUALLY REVIEW — in priority order
═══════════════════════════════════════════════════════════════════════════

1. DOES IT ACTUALLY WORK?
   This is always first. Before anything else, ask: if I ran this code
   right now, would it do what it claims? Look for:
   - Functions that are defined but never called, or called with wrong args.
   - Return values that are never checked or used.
   - Imports that will fail (missing package, wrong module name).
   - Code paths that are unreachable (dead code that can never execute).
   - audit_log() called with positional args instead of keyword-only.
   - SourceResult constructed with wrong field names or missing fields.
   - _decide_verdict() receiving a sources dict with unexpected keys.
   - Logic that produces the right answer for subject_srv.exe by accident
     but breaks on any other process name.
   - Off-by-one errors, wrong comparison operators, inverted conditions.

2. DOES IT VIOLATE THE GOLDEN RULES?
   These exist because we broke them before:
   - Does it modify an existing parser file? BLOCKER.
   - Does it use positional args with audit_log()? BLOCKER.
   - Does it filter supporting_invocation_ids without checking sr.present? BLOCKER.
   - Does it put LLM inference in the verdict path? BLOCKER.
   - Does it use python3 -c or heredoc for multi-line code? BLOCKER.
   - Does it use assert for runtime validation? BLOCKER.

3. IS IT UNNECESSARILY COMPLEX?
   If the same result can be achieved with less code, the complex version
   is wrong — not just worse, wrong. Complexity hides bugs. Look for:
   - Functions that do more than one thing and should be split, or that
     do so little they should be inlined.
   - Abstractions that don't pay for themselves (wrapper around one line).
   - Variables that are assigned and immediately used once — inline them.
   - Loops that could be a comprehension, comprehensions that are unreadable.
   - Classes where a function would do.
   - Try/except blocks that catch everything and swallow the real error.

4. DOES IT HOLD TOGETHER AS A SYSTEM?
   Look at the diff in context of the whole project, not as isolated lines:
   - Does this function fit with the functions around it? Same style?
   - Does it duplicate something that already exists elsewhere?
   - Does it break the contract that other parts of the system depend on?
     (e.g., parse_amcache returns a dict with specific keys — anything that
     changes this silently breaks correlation.py)
   - Does the error handling strategy match the rest of the file?
   - Would a new contributor reading this understand what it does and why?

5. SECURITY — exhaustive, no exceptions
   "Local forensic tool" is not an excuse. A compromised forensic tool can
   tamper with evidence, fabricate findings, destroy chain-of-custody, or
   exfiltrate case data. Review every line as if a sophisticated attacker
   will read the diff alongside you.

   INJECTION
   - subprocess with shell=True or any string concatenation into a shell
     command. Always a blocker, no exceptions.
   - os.system(), os.popen(), eval(), exec() on any non-literal input.
   - f-strings or format() used to build shell commands, SQL, or HTTP paths.
   - XML/HTML constructed by string concatenation instead of a safe builder.
   - User-supplied input reaching json.loads() without size or type validation
     (can trigger unbounded memory allocation).

   EVIDENCE INTEGRITY
   - Any code path that writes to evidence directories. BLOCKER, no exceptions.
   - Any code path that modifies audit/mcp.jsonl (except audit_log() append).
   - Any code path that modifies approvals.jsonl (except cli_approve()).
   - Any code path that creates findings without invocation_id traceability.
   - Any code path that labels a finding CONFIRMED without artifact evidence.

   SECRETS & CREDENTIALS
   - API keys, passwords, tokens hardcoded anywhere in committed code,
     even in comments, even "placeholder" values that look real.
   - Credentials in log statements, print() calls, or error messages.
   - .env files, .envrc files, or key files not in .gitignore.
   - Any key that matches the pattern sk-[a-z0-9]+ in committed text.

   NETWORK EXPOSURE
   - Server binding to 0.0.0.0 — exposes to every interface.
     MCP server runs as local subprocess via stdio, not HTTP.
   - Any runtime HTTP call to an external host from the MCP server layer.
   - Outbound connections opened at import time or module load.

   FILESYSTEM
   - Path traversal: any open(), Path(), os.path.join() that takes user
     input without calling .resolve() and checking it stays inside an
     allowed directory.
   - Writing to paths derived from user input without validation.
   - Temp files created with predictable names (use tempfile module).

   DESERIALIZATION
   - pickle.loads(), marshal.loads() on any data not generated by this
     process in this run. Pickle is arbitrary code execution.
   - yaml.load() without SafeLoader.
   - json.loads() on data from LLM output without size limits.
   - Parsing adversary-controlled CSV/EVTX/registry data without bounds.

   INFORMATION DISCLOSURE
   - Stack traces or internal file paths in tool return values sent to
     the LLM (the LLM could leak them or hallucinate from them).
   - Exception messages that reveal evidence paths or case structure.

   RACE CONDITIONS & STATE
   - Shared mutable state accessed from multiple calls without locks.
   - TOCTOU: check-then-act on evidence files.
   - Global variables mutated by tool handlers.

6. THINGS THAT WILL BITE AT DEMO TIME
   The hackathon demo is the deadline. Flag anything that will cause a
   visible failure during a live demo:
   - ralph.sh self-correction loop failing to terminate.
   - correlate_evidence() returning wrong verdict for known evidence.
   - Memory parser failing when Volatility 3 is not installed.
   - Audit trail missing entries that the accuracy report depends on.
   - Test failures that would break CI during the judge's review.

═══════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════════════
## SUMMARY
One sentence. Exactly one sentence — not two, not one sentence plus a clause after a dash.
It must end with SAFE TO COMMIT, COMMIT WITH CAUTION, or DO NOT COMMIT and nothing else.

## [BLOCKER]   ← one per finding, repeat header for each
File: `path/to/file.py:LINE`
Category: <Correctness | Golden-Rule | Complexity | Cohesion | Security | Evidence-Integrity | Demo Risk | Judging>
Issue: What is actually wrong. One sentence, specific.
Why it matters: What breaks if this ships. One sentence.
Fix: Exact code. Not a description — actual replacement code, 1–5 lines.

## [WARNING]   ← same structure, for non-fatal issues worth fixing
## [SIMPLIFY]  ← use this for complexity issues that are not bugs

## [LGTM]
Only real decisions worth calling out. Skip this section entirely if
there is nothing genuinely good to note. Generic praise is noise.

## VERDICT
One of:
  ✅ LGTM — safe to commit
  ⚠️  COMMIT WITH CAUTION — warnings only, no blockers
  ❌ DO NOT COMMIT — blockers present, fix first

═══════════════════════════════════════════════════════════════════════════
RULES
═══════════════════════════════════════════════════════════════════════════
- Cite file:line for every finding. No exceptions.
- Do not restate the diff. The author wrote it.
- Do not say "consider" or "you might want to". State findings as facts.
- Do not invent issues. If the diff is clean, say so in one sentence.
- Do not mention being an AI.
- If the diff is empty, say so and stop.
- Every [SIMPLIFY] finding must include a concrete simpler version,
  not just a description of the problem.

DIFF SHAPE — calibrate effort to the actual change:
- A diff that is mostly file renames (R-status in the file list) with small
  content edits is a structural move. Focus on whether imports still resolve
  after the rename, not on re-reviewing the moved code line-by-line.
- A diff with a single file changed and < 50 lines is a focused edit. Read
  it fully. Demand high specificity in findings.
- A diff with > 500 lines added across multiple files is a feature commit.
  Read the additions fully; flag missing error handling, missing edge cases,
  and any dead code paths.
- If the diff size and the commit message do not match (e.g., "fix typo"
  with 800 lines changed), call that out explicitly as a process issue.

SELF-MODIFICATION:
- If monster_check.py itself is in the diff, you are reviewing your own
  configuration. Do not be lenient because it is "just dev tooling."
  Specifically check: (a) the SYSTEM_PROMPT does not weaken or remove rules
  that exist for project-correctness reasons; (b) error handling in
  review_diff() still terminates non-zero on real failures; (c) the
  argparse defaults still enforce --max-diff-bytes.
"""


# --------------------------------------------------------------------------- #
# DeepSeek streaming review
# --------------------------------------------------------------------------- #
def colorize_stream_chunk(chunk: str, state: dict) -> str:
    out_parts = []
    buf = state.get("buf", "") + chunk

    while "\n" in buf:
        line, buf = buf.split("\n", 1)
        out_parts.append(_color_line(line, state) + "\n")

    state["buf"] = buf
    return "".join(out_parts)


def _color_line(line: str, state: dict) -> str:
    stripped = line.lstrip()

    if stripped.startswith("## [BLOCKER]"):
        state["section"] = "blocker"
        return f"{C.RED}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## [WARNING]"):
        state["section"] = "warning"
        return f"{C.YELLOW}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## [SIMPLIFY]"):
        state["section"] = "simplify"
        return f"{C.BLUE}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## [LGTM]"):
        state["section"] = "lgtm"
        return f"{C.GREEN}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## SUMMARY"):
        state["section"] = "summary"
        return f"{C.CYAN}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## VERDICT"):
        state["section"] = "verdict"
        return f"{C.MAGENTA}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## "):
        state["section"] = "other"
        return f"{C.BOLD}{line}{C.RESET}"

    if "❌" in line or stripped.startswith("DO NOT COMMIT"):
        return f"{C.RED}{C.BOLD}{line}{C.RESET}"
    if "✅" in line or "LGTM" in stripped[:6]:
        return f"{C.GREEN}{line}{C.RESET}"
    if "⚠" in line or stripped.startswith("COMMIT WITH CAUTION"):
        return f"{C.YELLOW}{line}{C.RESET}"

    section = state.get("section")
    if section == "blocker":
        return f"{C.RED}{line}{C.RESET}"
    if section == "warning":
        return f"{C.YELLOW}{line}{C.RESET}"
    if section == "simplify":
        return f"{C.BLUE}{line}{C.RESET}"
    if section == "lgtm":
        return f"{C.GREEN}{line}{C.RESET}"

    return line




def build_auto_context() -> str:
    """
    Run deterministic repo checks and return a verified-facts string.
    These facts are injected into the review prompt so DeepSeek cannot
    hallucinate about things we can verify ourselves.
    """
    facts = []

    def find(pattern: str, path: str) -> list[tuple[int, str]]:
        """Return [(lineno, line), ...] for lines matching pattern in path."""
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            facts.append(f"  [auto-context read failed: {path}: {exc}]")
            return []
        rx = re.compile(re.escape(pattern))
        return [
            (i, line)
            for i, line in enumerate(text.splitlines(), 1)
            if rx.search(line)
        ]

    # MCP tool registrations
    server_py = "mcp_server/server.py"
    if Path(server_py).exists():
        hits = find("mcp.tool", server_py)
        if hits:
            facts.append(f"MCP tools registered in {server_py}: {len(hits)} tool(s)")
        # Specific tools
        try:
            server_text = Path(server_py).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            facts.append(f"  [auto-context read failed: {server_py}: {exc}]")
            server_text = ""
        server_lines = server_text.splitlines()
        for tool in ["correlate_evidence", "parse_memory", "record_finding",
                     "approve_finding"]:
            registered_at = [
                i + 1
                for i, line in enumerate(server_lines)
                if re.match(rf"\s*def\s+{re.escape(tool)}\s*\(", line)
                and i > 0 and "@mcp.tool" in server_lines[i - 1]
            ]
            if registered_at:
                facts.append(
                    f"  {tool}: registered at {server_py} line(s) "
                    + ", ".join(str(ln) for ln in registered_at)
                )
            else:
                facts.append(f"  {tool}: NOT registered in {server_py}")

    # Test count — bounded by timeout to prevent hung commits.
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "--co", "-q"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if r.returncode != 0:
            facts.append(f"  [pytest collection failed (rc={r.returncode})]")
        else:
            summary_line = next(
                (ln for ln in reversed(r.stdout.splitlines())
                 if re.search(r"\d+\s+tests?\s+collected", ln)),
                None,
            )
            if summary_line:
                facts.append(f"pytest --co: {summary_line.strip()}")
    except subprocess.TimeoutExpired:
        facts.append("  [pytest collection skipped: > 10s]")
    except Exception as exc:
        facts.append(f"  [pytest collection failed: {exc}]")

    # approve_finding must never be MCP-registered (Law 5) — check server.py
    if Path(server_py).exists():
        approve_hits = find("approve_finding", server_py)
        if approve_hits:
            facts.append(
                "  [VIOLATION] approve_finding appears in mcp_server/server.py at line(s) "
                + ", ".join(str(ln) for ln, _ in approve_hits)
            )
        else:
            facts.append("approve_finding: NOT registered in mcp_server/server.py (Law 5 compliant)")

    # BLOCKED_COMMANDS presence
    shared = "mcp_server/tools/_shared.py"
    if Path(shared).exists():
        hits = find("BLOCKED_COMMANDS", shared)
        if hits:
            facts.append(f"BLOCKED_COMMANDS: present in {shared}")

    # audit_log signature (keyword-only args)
    if Path(shared).exists():
        hits = find("def audit_log", shared)
        if hits:
            _, sig_line = hits[0]
            facts.append(f"audit_log signature: {sig_line.strip()}")

    if not facts:
        return ""
    return "AUTO-VERIFIED REPO STATE (confirmed by find() — do not contradict):\n" + "\n".join(facts)

def review_diff(diff: str, summary: str, model: str, combined_context: str = "") -> None:
    try:
        from openai import OpenAI
    except ImportError:
        die("The `openai` package is not installed. Run: pip install --upgrade openai")

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        die("DEEPSEEK_API_KEY environment variable is not set.")

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
    )


    context_block = ("## VERIFIED (do not re-litigate):\n" + combined_context + "\n\n") if combined_context else ""
    user_message = (
        f"{context_block}{summary}\n\n"
        f"Review this diff. Cite file:line for every finding.\n\n"
        f"```diff\n{diff}\n```"
    )
    banner(f"MONSTER-CHECK · model={model} · streaming review", C.CYAN)

    try:
        stream = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
            stream=True,
            reasoning_effort="high",
            extra_body={"thinking": {"type": "enabled"}},
            temperature=0.2,
        )
    except TypeError:
        # Older openai SDKs reject reasoning_effort as a top-level kwarg.
        try:
            stream = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_message},
                ],
                stream=True,
                temperature=0.2,
                extra_body={
                    "thinking":        {"type": "enabled"},
                    "reasoning_effort": "high",
                },
            )
        except Exception as e:  # noqa: BLE001
            die(f"DeepSeek API call failed (fallback path): {e}")
    except Exception as e:
        die(f"DeepSeek API call failed: {e}")

    state: dict = {"buf": "", "section": None}
    saw_any_text = False

    try:
        for event in stream:
            if not event.choices:
                continue
            delta = event.choices[0].delta
            piece = getattr(delta, "content", None)
            if not piece:
                continue
            saw_any_text = True
            colored = colorize_stream_chunk(piece, state)
            sys.stdout.write(colored)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[monster_check] interrupted by user.{C.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.RED}[monster_check] stream error: {e}{C.RESET}", file=sys.stderr)
        sys.exit(2)

    tail = state.get("buf", "")
    if tail:
        sys.stdout.write(_color_line(tail, state))
        sys.stdout.flush()

    if not saw_any_text:
        die("DeepSeek returned an empty response. Check API key and model availability.")

    print()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="monster_check",
        description="Senior engineer pre-commit review (DeepSeek V4-Pro).",
    )
    diff_group = parser.add_mutually_exclusive_group()
    diff_group.add_argument(
        "--unstaged", action="store_true",
        help="Review unstaged working-tree changes instead of staged.",
    )
    diff_group.add_argument(
        "--all", action="store_true", dest="all_changes",
        help="Review staged + unstaged combined (git diff HEAD).",
    )
    parser.add_argument(
        "--model", default="deepseek-v4-pro",
        help="Model id (default: deepseek-v4-pro).",
    )
    parser.add_argument(
        "--max-diff-bytes", type=int, default=300_000,
        help="Refuse to send diffs larger than this (default 300 KB).",
    )
    parser.add_argument(
        "--full-file-context", action="store_true",
        help="Include full modified source files in the review payload (may transmit sensitive paths).",
    )
    parser.add_argument(
        "--context", "-C", default="",
        help="Verified context preamble to prepend to the review prompt.",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="Full repo audit: review all .py files 2 at a time. One-time use.",
    )
    args = parser.parse_args()

    ensure_git_repo()

    if args.deep:
        deep_scan(args.model)
        sys.exit(0)

    if args.unstaged:
        mode = "unstaged"
    elif args.all_changes:
        mode = "all"
    else:
        mode = "staged"

    diff, summary = capture_diff(mode)

    if not diff.strip():
        if mode == "staged":
            die("No staged changes. Run `git add <files>` first, "
                "or use --unstaged / --all.", code=0)
        else:
            die(f"No {mode} changes to review.", code=0)

    auto_facts = build_auto_context()
    compile_status = compile_check(mode)
    if "COMPILE ERROR" in compile_status:
        print(compile_status)
        die("Compile errors in modified .py files — fix before committing.")
    file_contents = full_file_context(mode) if args.full_file_context else ""
    combined_context = "\n".join(filter(None, [
        compile_status, auto_facts, file_contents, args.context or ""
    ]))

    diff_bytes = len(diff.encode("utf-8"))
    context_bytes = len(combined_context.encode("utf-8"))
    payload_bytes = diff_bytes + context_bytes
    if payload_bytes > args.max_diff_bytes:
        die(
            f"Review payload is {payload_bytes:,} bytes "
            f"(diff {diff_bytes:,} + context {context_bytes:,}, "
            f"limit {args.max_diff_bytes:,}). "
            f"Reduce diff/context or raise --max-diff-bytes.",
        )

    print(f"{C.GREY}{summary}{C.RESET}")
    review_diff(diff, summary, args.model, combined_context=combined_context)


if __name__ == "__main__":
    main()
