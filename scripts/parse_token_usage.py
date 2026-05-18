#!/usr/bin/env python3
"""Parse token usage from Claude Code output and write to audit log.

Claude Code's ``claude -p`` reports token usage in its output.  This script
extracts those numbers and appends a structured JSON entry to the ralph
iteration audit log.

Usage (called from ralph.sh)::

    python3 scripts/parse_token_usage.py \\
        --output "$CLAUDE_OUTPUT" \\
        --iteration "$ITER" \\
        --case-dir "$CASE_DIR" \\
        --phase "main"        # or "correction"

If no token info is found in the output, writes an entry with
``tokens_found: false`` so the audit trail is never incomplete.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_token_counts(text: str) -> dict:
    """Extract token usage from Claude Code output.

    Claude Code may report usage in several formats.  We try all known
    patterns and return what we find.

    Returns
    -------
    dict
        Keys may include: input_tokens, output_tokens, total_tokens,
        cache_read_tokens, cache_write_tokens, tokens_found (bool).
    """
    result: dict = {"tokens_found": False}

    # Pattern 1: "Total tokens: N" or "Total cost: $X.XX (N tokens)"
    m = re.search(r"[Tt]otal\s+tokens?[:\s]+(\d[\d,]*)", text)
    if m:
        result["total_tokens"] = int(m.group(1).replace(",", ""))
        result["tokens_found"] = True

    # Pattern 2: "input: N tokens" / "output: N tokens"
    m_in = re.search(r"[Ii]nput[:\s]+(\d[\d,]*)\s*tokens?", text)
    m_out = re.search(r"[Oo]utput[:\s]+(\d[\d,]*)\s*tokens?", text)
    if m_in:
        result["input_tokens"] = int(m_in.group(1).replace(",", ""))
        result["tokens_found"] = True
    if m_out:
        result["output_tokens"] = int(m_out.group(1).replace(",", ""))
        result["tokens_found"] = True

    # Pattern 3: "cache_read: N" / "cache_creation: N"
    m_cr = re.search(r"cache[_\s]read[:\s]+(\d[\d,]*)", text)
    m_cw = re.search(r"cache[_\s](?:creation|write)[:\s]+(\d[\d,]*)", text)
    if m_cr:
        result["cache_read_tokens"] = int(m_cr.group(1).replace(",", ""))
        result["tokens_found"] = True
    if m_cw:
        result["cache_write_tokens"] = int(m_cw.group(1).replace(",", ""))
        result["tokens_found"] = True

    # Pattern 4: JSON-like {"usage": {"input_tokens": N, ...}}
    m_json = re.search(r'"usage"\s*:\s*\{[^}]+\}', text)
    if m_json:
        try:
            usage = json.loads("{" + m_json.group(0) + "}")["usage"]
            for key in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                        "cache_creation_input_tokens"):
                if key in usage and isinstance(usage[key], int):
                    result[key] = usage[key]
                    result["tokens_found"] = True
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # Pattern 5: "cost: $X.XX" — extract cost even if tokens not found
    m_cost = re.search(r"[Cc]ost[:\s]+\$(\d+\.?\d*)", text)
    if m_cost:
        result["estimated_cost_usd"] = float(m_cost.group(1))
        result["tokens_found"] = True

    # Compute total if we have input + output but not total
    if "input_tokens" in result and "output_tokens" in result and "total_tokens" not in result:
        result["total_tokens"] = result["input_tokens"] + result["output_tokens"]

    return result


def write_token_log(
    case_dir: str,
    iteration: int,
    phase: str,
    token_info: dict,
    output_chars: int,
) -> Path:
    """Append token usage entry to ralph_token_usage.jsonl."""
    audit_dir = Path(case_dir).resolve() / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    log_file = audit_dir / "ralph_token_usage.jsonl"

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": "ralph_token_tracker",
        "iteration": iteration,
        "phase": phase,
        "output_chars": output_chars,
        "examiner": os.environ.get("CASEFILE_EXAMINER", "unknown"),
        **token_info,
    }

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())

    return log_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse token usage from Claude output")
    parser.add_argument("--output", required=True, help="Claude output text (or @file to read from file)")
    parser.add_argument("--iteration", type=int, required=True, help="Ralph iteration number")
    parser.add_argument("--case-dir", required=True, help="Case directory path")
    parser.add_argument("--phase", default="main", help="Phase: main or correction")
    args = parser.parse_args()

    # Read output from file if prefixed with @
    if args.output.startswith("@"):
        filepath = args.output[1:]
        try:
            with open(filepath, encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            print(f"[token-tracker] Could not read {filepath}: {e}", file=sys.stderr)
            text = ""
    else:
        text = args.output

    token_info = parse_token_counts(text)
    log_file = write_token_log(
        case_dir=args.case_dir,
        iteration=args.iteration,
        phase=args.phase,
        token_info=token_info,
        output_chars=len(text),
    )

    if token_info["tokens_found"]:
        summary_parts = []
        if "input_tokens" in token_info:
            summary_parts.append(f"in={token_info['input_tokens']}")
        if "output_tokens" in token_info:
            summary_parts.append(f"out={token_info['output_tokens']}")
        if "total_tokens" in token_info:
            summary_parts.append(f"total={token_info['total_tokens']}")
        if "estimated_cost_usd" in token_info:
            summary_parts.append(f"cost=${token_info['estimated_cost_usd']:.4f}")
        print(f"[token-tracker] {', '.join(summary_parts)}", flush=True)
    else:
        print("[token-tracker] No token info found in output (logged as tokens_found=false)", flush=True)


if __name__ == "__main__":
    main()
