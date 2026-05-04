#!/usr/bin/env python3
"""
monster_check.py — Local "Semi-CodeRabbit" for the casefile / SANS Find-Evil project.

Captures staged git changes, ships them to DeepSeek V4-Pro for a rigorous review
(security, logic flaws, architecture drift), and streams a colorized verdict to
the terminal. Designed to be run right before `git commit` so you don't pay the
1-hour CI tax for trivial defects.

Usage:
    export DEEPSEEK_API_KEY="sk-..."
    git add <files>
    ./monster_check.py            # review staged diff
    ./monster_check.py --unstaged # review unstaged working-tree diff instead
    ./monster_check.py --all      # review staged + unstaged combined
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Optional

# --------------------------------------------------------------------------- #
# ANSI color helpers
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"


def supports_color() -> bool:
    """Disable color when piped or when NO_COLOR is set (https://no-color.org)."""
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


# Strip color codes if the environment can't render them.
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
    try:
        out = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True,
    )
    if out.returncode != 0 or out.stdout.strip() != "true":
        die("Not inside a git repository. cd into your project root first.")


def capture_diff(mode: str) -> tuple[str, str]:
    """Return (diff_text, summary) for the requested mode."""
    if mode == "staged":
        diff = run_git(["diff", "--cached", "--no-color", "-U5"])
        files = run_git(["diff", "--cached", "--name-status"]).strip()
        label = "STAGED CHANGES (git diff --cached)"
    elif mode == "unstaged":
        diff = run_git(["diff", "--no-color", "-U5"])
        files = run_git(["diff", "--name-status"]).strip()
        label = "UNSTAGED CHANGES (git diff)"
    elif mode == "all":
        diff = run_git(["diff", "HEAD", "--no-color", "-U5"])
        files = run_git(["diff", "HEAD", "--name-status"]).strip()
        label = "ALL UNCOMMITTED CHANGES (git diff HEAD)"
    else:
        die(f"Unknown diff mode: {mode}")
    return diff, f"{label}\n{files or '(no files)'}"


# --------------------------------------------------------------------------- #
# System prompt — the "True CodeRabbit" persona
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """\
You are MONSTER-CHECK, a ruthless senior code reviewer embedded in the SANS
Find-Evil Hackathon `casefile` project. You are the local stand-in for
CodeRabbit, but faster and more opinionated. Your job is to catch the bugs
that would otherwise burn an hour of CI time and embarrass the author.

═══════════════════════════════════════════════════════════════════════════
PROJECT CONTEXT (treat as ground truth)
═══════════════════════════════════════════════════════════════════════════
• Codebase: `casefile` — a Python DFIR / forensics CLI built on Click,
  installed via pyproject.toml, deployed to SANS SIFT Workstations.
• Hackathon hard rules:
    - Must run fully LOCAL on a SIFT box. No paid cloud APIs in runtime path.
    - No outbound calls to OpenAI, Anthropic, or any commercial LLM from
      production code paths. (Dev-time tools like THIS reviewer are fine.)
    - Evidence handling must preserve chain-of-custody and be reproducible.
• Architectural conventions:
    - CLI commands live under `mcp_server/tools/<name>.py and src/casefile/commands/<name>.py` and follow
      the Click group pattern established by existing commands.
    - Identity, approval auth, gateway, verification, and case I/O are
      centralized in `src/casefile/` siblings — DO NOT reimplement them
      inside command modules.
    - Subprocess calls in DFIR code paths must NEVER use `shell=True` and
      must pass arguments as a list. Forensic tools running on adversary
      artifacts are a command-injection magnet.
    - Path handling on user-supplied input must be resolved and confined
      (no `..` traversal escapes outside the case directory).
    - Deserialization of untrusted artifacts uses safe loaders only
      (`yaml.safe_load`, never `pickle.load` on attacker-controlled data).

═══════════════════════════════════════════════════════════════════════════
REVIEW DIMENSIONS — score every diff on ALL of these
═══════════════════════════════════════════════════════════════════════════
1. SECURITY / SAST
    - Command injection (subprocess shell=True, os.system, unsanitized
      f-strings into shell, `Popen` with concatenated input).
    - Path traversal (open()/Path() on user input without resolve+confine).
    - Unsafe deserialization (pickle, yaml.load without SafeLoader,
      marshal, eval/exec on file contents). CRITICAL for DFIR tools.
    - Hardcoded secrets, API keys, tokens, credentials.
    - SQL/LDAP/XML injection if any query construction is touched.
    - TOCTOU races on filesystem checks.

2. STATE / LOGIC FLAWS
    - Race conditions (shared mutable state, missing locks, async/await
      mistakes, file handles across threads).
    - Unhandled exceptions (bare `except:`, swallowed errors, missing
      cleanup, `finally` blocks that mask the real failure).
    - Infinite loops or unbounded recursion (missing termination
      condition, off-by-one in `while`, recursion without base case).
    - Resource leaks (unclosed files/sockets, missing `with` blocks).
    - Off-by-one, integer overflow, float comparison with ==.
    - Missing input validation on Click options/arguments.

3. ARCHITECTURE DRIFT
    - Does this violate `casefile` structure? (e.g., a new command not
      under `commands/`, or duplicating logic from `gateway.py` /
      `identity.py` / `approval_auth.py` / `verification.py`).
    - Does it introduce a paid API or non-local dependency, breaking
      the Hackathon "runs locally, no paid APIs" rule?
    - Does it bypass the existing approval/identity/audit chain?
    - Does it break the chain-of-custody / evidence-integrity guarantees?
    - Style: does it follow Click patterns used by sibling commands
      (approve.py, review.py, evidence.py, etc.)?

4. CORRECTNESS & TESTS
    - Does the diff break public CLI signatures used elsewhere?
    - Are there obvious cases where the new code path is never reached?
    - Is logging / audit-trail emission present where required?

═══════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT — STRICT
═══════════════════════════════════════════════════════════════════════════
Produce output in this exact structure. Be terse. Do not pad.

## SUMMARY
One sentence verdict. State whether the diff is SAFE TO COMMIT, COMMIT WITH
CAUTION, or DO NOT COMMIT.

## [BLOCKER]  (use this header for each, one per finding)
File: `path/to/file.py:LINE`
Category: <Security | Logic | Architecture | Correctness>
Issue: <one tight sentence>
Why it matters: <one sentence>
Fix: <concrete code-level remediation, ideally with a 1-3 line snippet>

## [WARNING]  (same shape as BLOCKER, but for non-fatal smells)

## [LGTM]
Bullet list of things the diff got right. Keep it short — only call out
genuinely good decisions, not generic praise.

## VERDICT
One of:
  ✅ LGTM — safe to commit
  ⚠️  COMMIT WITH CAUTION — warnings only, no blockers
  ❌ DO NOT COMMIT — blockers present, fix first

═══════════════════════════════════════════════════════════════════════════
RULES OF ENGAGEMENT
═══════════════════════════════════════════════════════════════════════════
• Cite file:line for every finding. If line numbers aren't visible in the
  hunk header, cite the hunk's @@ range.
• Do not invent issues. If the diff is clean, say so and emit a single
  ✅ LGTM verdict with an empty BLOCKER/WARNING section.
• Do not restate the diff back at the user. They wrote it. They've seen it.
• Do not mention "I am an AI" or hedge with "you might want to consider".
  State findings directly.
• If the diff is empty or whitespace-only, say so in one line and stop.
"""


# --------------------------------------------------------------------------- #
# DeepSeek streaming review
# --------------------------------------------------------------------------- #
def colorize_stream_chunk(chunk: str, state: dict) -> str:
    """
    Lightweight inline colorization of streamed markdown.
    We tag entire lines based on detected headers and let the carry-over
    state persist across chunk boundaries.
    """
    out_parts = []
    buf = state.get("buf", "") + chunk

    while "\n" in buf:
        line, buf = buf.split("\n", 1)
        out_parts.append(_color_line(line, state) + "\n")

    state["buf"] = buf
    return "".join(out_parts)


def _color_line(line: str, state: dict) -> str:
    stripped = line.lstrip()

    # Section detection
    if stripped.startswith("## [BLOCKER]"):
        state["section"] = "blocker"
        return f"{C.RED}{C.BOLD}{line}{C.RESET}"
    if stripped.startswith("## [WARNING]"):
        state["section"] = "warning"
        return f"{C.YELLOW}{C.BOLD}{line}{C.RESET}"
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

    # Inline highlights regardless of section
    if "❌" in line or stripped.startswith("DO NOT COMMIT"):
        return f"{C.RED}{C.BOLD}{line}{C.RESET}"
    if "✅" in line or "LGTM" in stripped[:6]:
        return f"{C.GREEN}{line}{C.RESET}"
    if "⚠" in line or stripped.startswith("COMMIT WITH CAUTION"):
        return f"{C.YELLOW}{line}{C.RESET}"

    # Section-tinted body
    section = state.get("section")
    if section == "blocker":
        return f"{C.RED}{line}{C.RESET}"
    if section == "warning":
        return f"{C.YELLOW}{line}{C.RESET}"
    if section == "lgtm":
        return f"{C.GREEN}{line}{C.RESET}"

    return line


def review_diff(diff: str, summary: str, model: str) -> None:
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

    user_message = (
        f"{summary}\n\n"
        f"Review the following unified diff against the rules in your system prompt. "
        f"Cite file:line for every finding.\n\n"
        f"```diff\n{diff}\n```"
    )

    banner(f"MONSTER-CHECK · model={model} · streaming review", C.CYAN)

    try:
        stream = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            stream=True,
            reasoning_effort="high",
            extra_body={"thinking": {"type": "enabled"}},
            temperature=0.2,
        )
    except TypeError:
        # Older openai SDKs reject reasoning_effort as a top-level kwarg.
        stream = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            stream=True,
            temperature=0.2,
            extra_body={
                "thinking": {"type": "enabled"},
                "reasoning_effort": "high",
            },
        )
    except Exception as e:  # noqa: BLE001
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
    except Exception as e:  # noqa: BLE001
        print(f"\n{C.RED}[monster_check] stream error: {e}{C.RESET}", file=sys.stderr)
        sys.exit(2)

    # Flush any trailing buffered text
    tail = state.get("buf", "")
    if tail:
        sys.stdout.write(_color_line(tail, state))
        sys.stdout.flush()

    if not saw_any_text:
        die("DeepSeek returned an empty response. Check API key and model availability.")

    print()  # final newline


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="monster_check",
        description="Local Semi-CodeRabbit for casefile (DeepSeek V4-Pro).",
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
    args = parser.parse_args()

    ensure_git_repo()

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

    if len(diff.encode("utf-8")) > args.max_diff_bytes:
        die(
            f"Diff is {len(diff.encode('utf-8')):,} bytes "
            f"(limit {args.max_diff_bytes:,}). "
            f"Commit in smaller chunks or raise --max-diff-bytes.",
        )

    print(f"{C.GREY}{summary}{C.RESET}")
    review_diff(diff, summary, args.model)


if __name__ == "__main__":
    main()
