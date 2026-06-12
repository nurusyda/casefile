#!/usr/bin/env python3
"""
append_session_tokens.py — Append a token entry to a session tokens JSON file.

Reads an existing session tokens file, appends a new iteration entry,
recomputes totals across all iterations, and writes back atomically.

Usage:
    python3 scripts/append_session_tokens.py <token_entry_json> <tokens_file>

Arguments:
    token_entry_json : JSON string representing a single iteration's token usage
    tokens_file      : Path to the session tokens JSON file (created if absent)

Exit codes:
    0 — success
    1 — error (details printed to stderr)
"""

import json
import os
import sys
import tempfile
from pathlib import Path


def compute_cost(input_tokens: int, output_tokens: int,
                 cache_read_tokens: int = 0,
                 cache_creation_tokens: int = 0) -> float:
    """Compute approximate cost in USD using Claude Opus pricing.

    Pricing (per 1M tokens, as of 2025):
        input:             $15.00
        output:            $75.00
        cache_read:         $1.50
        cache_creation:    $18.75
    """
    cost = 0.0
    cost += (input_tokens / 1_000_000) * 15.00
    cost += (output_tokens / 1_000_000) * 75.00
    cost += (cache_read_tokens / 1_000_000) * 1.50
    cost += (cache_creation_tokens / 1_000_000) * 18.75
    return round(cost, 6)


def recompute_totals(iterations: list) -> dict:
    """Compute aggregate totals across all iterations."""
    total_in = 0
    total_out = 0
    total_cache_read = 0
    total_cache_creation = 0
    total_cost = 0.0

    for it in iterations:
        total_in += it.get("input_tokens", 0)
        total_out += it.get("output_tokens", 0)
        total_cache_read += it.get("cache_read_input_tokens", 0)
        total_cache_creation += it.get("cache_creation_input_tokens", 0)

    total_cost = compute_cost(total_in, total_out, total_cache_read, total_cache_creation)

    return {
        "input_tokens": total_in,
        "output_tokens": total_out,
        "cache_read_input_tokens": total_cache_read,
        "cache_creation_input_tokens": total_cache_creation,
        "total_cost_usd": total_cost,
        "iterations_count": len(iterations),
    }


def main():
    if len(sys.argv) != 3:
        print("Usage: append_session_tokens.py <token_entry_json> <tokens_file>",
              file=sys.stderr)
        sys.exit(1)

    token_entry_json = sys.argv[1]
    tokens_file = sys.argv[2]

    try:
        entry = json.loads(token_entry_json)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON for token_entry: {exc}", file=sys.stderr)
        sys.exit(1)

    # Read existing file or start fresh
    data = {}
    tokens_path = Path(tokens_file)
    if tokens_path.exists():
        try:
            with tokens_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"ERROR: cannot read tokens file {tokens_file}: {exc}",
                  file=sys.stderr)
            sys.exit(1)

    # Ensure iterations list exists
    if "iterations" not in data:
        data["iterations"] = []

    # Append entry
    data["iterations"].append(entry)

    # Recompute totals
    data["totals"] = recompute_totals(data["iterations"])

    # Write atomically: write to temp file, then replace
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=tokens_path.parent,
            prefix=".tmp_session_tokens_",
            suffix=".json",
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.write("\n")
        except Exception:
            # Clean up temp file on write failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        os.replace(tmp_path, tokens_path)
    except Exception as exc:
        print(f"ERROR: cannot write tokens file {tokens_file}: {exc}",
              file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
