#!/usr/bin/env python3
"""
append_session_tokens.py — Append a token entry to a session tokens JSON file.

Reads an existing session tokens file, appends a new iteration entry,
recomputes token totals and the API-equivalent cost across all iterations,
and writes back atomically.

Usage:
    python3 scripts/append_session_tokens.py <token_entry_json> <tokens_file>

Exit codes: 0 success, 1 error.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Public Anthropic API pricing for Claude Sonnet 4.5 / 4.6 (identical pricing),
# per 1M tokens, sourced from https://www.anthropic.com/pricing.
# This submission ran under Claude Code on a flat-rate Pro subscription,
# so the figure below is the pay-as-you-go API equivalent, NOT what was
# actually paid. We compute and report it so judges can see what an
# autonomous CaseFile investigation would cost at the API rate card.
PRICING_MODEL = "claude-sonnet-4.6"
PRICE_INPUT_PER_MTOK = 3.00
PRICE_OUTPUT_PER_MTOK = 15.00
PRICE_CACHE_READ_PER_MTOK = 0.30
PRICE_CACHE_CREATION_PER_MTOK = 3.75


def compute_cost(input_tokens: int, output_tokens: int,
                 cache_read_tokens: int = 0,
                 cache_creation_tokens: int = 0) -> float:
    """Return the API-equivalent cost in USD at current Sonnet rates."""
    cost = 0.0
    cost += (input_tokens / 1_000_000) * PRICE_INPUT_PER_MTOK
    cost += (output_tokens / 1_000_000) * PRICE_OUTPUT_PER_MTOK
    cost += (cache_read_tokens / 1_000_000) * PRICE_CACHE_READ_PER_MTOK
    cost += (cache_creation_tokens / 1_000_000) * PRICE_CACHE_CREATION_PER_MTOK
    return round(cost, 6)


def recompute_totals(iterations: list) -> dict:
    """Aggregate token totals and API-equivalent cost across all iterations."""
    total_in = total_out = total_cache_read = total_cache_creation = 0
    for it in iterations:
        total_in += it.get("input_tokens", 0)
        total_out += it.get("output_tokens", 0)
        total_cache_read += it.get("cache_read_input_tokens", 0)
        total_cache_creation += it.get("cache_creation_input_tokens", 0)
    return {
        "input_tokens": total_in,
        "output_tokens": total_out,
        "cache_read_input_tokens": total_cache_read,
        "cache_creation_input_tokens": total_cache_creation,
        "iterations_count": len(iterations),
        "pricing_model": PRICING_MODEL,
        "total_cost_usd_api_equivalent": compute_cost(
            total_in, total_out, total_cache_read, total_cache_creation),
        "billing_note": (
            "total_cost_usd_api_equivalent uses public Anthropic API rates for "
            "Claude Sonnet 4.6 ($3 input / $15 output / $0.30 cache_read / "
            "$3.75 cache_creation per 1M tokens). This investigation ran on a "
            "flat-rate Claude Pro subscription via Claude Code, so the figure "
            "is the pay-as-you-go API equivalent — not what was actually paid."
        ),
    }


def main():
    if len(sys.argv) != 3:
        print("Usage: append_session_tokens.py <token_entry_json> <tokens_file>",
              file=sys.stderr)
        sys.exit(1)
    token_entry_json, tokens_file = sys.argv[1], sys.argv[2]
    try:
        entry = json.loads(token_entry_json)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON for token_entry: {exc}", file=sys.stderr)
        sys.exit(1)
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
    data.setdefault("iterations", []).append(entry)
    data["totals"] = recompute_totals(data["iterations"])
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
