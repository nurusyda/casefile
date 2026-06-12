#!/usr/bin/env python3
"""
capture_tokens.py — Extract token usage from the latest Claude Code session transcript.

Reads the most recently modified JSONL transcript under the project's
session directory, sums token usage across all assistant messages, and
prints a JSON object suitable for appending to results/<CASE>_session_tokens.json.

Usage:
    python3 scripts/capture_tokens.py <case_name> <iteration> [--correction N]

Output (stdout):
    {"iteration": 1, "is_correction": false, "input_tokens": N, ...}
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_latest_transcript(project_dir: Path) -> Path | None:
    """Return the most recently modified .jsonl transcript file."""
    if not project_dir.is_dir():
        return None
    jsonl_files = sorted(project_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return jsonl_files[0] if jsonl_files else None


def extract_token_usage(transcript_path: Path) -> dict:
    """Parse a Claude Code session transcript and sum token usage.

    Returns a dict with input_tokens, output_tokens, cache_read_input_tokens,
    cache_creation_input_tokens, and num_turns (count of assistant messages).
    """
    input_tokens = 0
    output_tokens = 0
    cache_read = 0
    cache_creation = 0
    num_turns = 0

    with transcript_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if record.get("type") != "assistant":
                continue

            num_turns += 1
            message = record.get("message", {})
            usage = message.get("usage", {})

            if not usage:
                pass  # no usage data, skip
            else:
                has_top = any(k in usage for k in (
                    "input_tokens", "output_tokens",
                    "cache_read_input_tokens", "cache_creation_input_tokens"
                ))
                if has_top:
                    input_tokens += usage.get("input_tokens", 0)
                    output_tokens += usage.get("output_tokens", 0)
                    cache_read += usage.get("cache_read_input_tokens", 0)
                    cache_creation += usage.get("cache_creation_input_tokens", 0)
                elif "iterations" in usage:
                    for it in usage["iterations"]:
                        input_tokens += it.get("input_tokens", 0)
                        output_tokens += it.get("output_tokens", 0)
                        cache_read += it.get("cache_read_input_tokens", 0)
                        cache_creation += it.get("cache_creation_input_tokens", 0)

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_creation,
        "num_turns": num_turns,
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: capture_tokens.py <case_name> <iteration> [--correction N]", file=sys.stderr)
        sys.exit(1)

    case_name = sys.argv[1]
    iteration = int(sys.argv[2])
    is_correction = "--correction" in sys.argv
    correction_num = None
    if is_correction:
        try:
            idx = sys.argv.index("--correction")
            correction_num = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass

    # Locate the project transcript directory
    claude_projects_root = Path(
        os.environ.get("CLAUDE_PROJECT_DIR",
                       str(Path.home() / ".claude" / "projects"))
    )
    if not claude_projects_root.is_dir():
        print(f"WARNING: CLAUDE_PROJECT_DIR does not exist: {claude_projects_root}",
              file=sys.stderr)

    # Derive project slug from current working directory at runtime
    # /home/sansproject/casefile -> -home-sansproject-casefile
    cwd_slug = os.getcwd().replace("/", "-")
    project_dir = claude_projects_root / cwd_slug

    transcript = find_latest_transcript(project_dir)
    if transcript is None:
        result = {
            "case": case_name,
            "iteration": iteration,
            "is_correction": is_correction,
            "error": "no_transcript_found",
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        if correction_num is not None:
            result["correction_iteration"] = correction_num
    else:
        usage = extract_token_usage(transcript)
        result = {
            "case": case_name,
            "iteration": iteration,
            "is_correction": is_correction,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "transcript_file": str(transcript.name),
            **usage,
        }
        if correction_num is not None:
            result["correction_iteration"] = correction_num

    print(json.dumps(result))


if __name__ == "__main__":
    main()
