#!/usr/bin/env python3
"""Read max_iterations from a PRD JSON file.

Usage: python3 scripts/read_max_iter.py <prd_file>
Exits with code 1 if the file is missing or malformed (caller falls back to default).
"""
import json
import sys
from pathlib import Path

if len(sys.argv) < 2:
    sys.exit(1)

prd_file = Path(sys.argv[1]).resolve()
allowed_root = Path(__file__).resolve().parent.parent  # project root
if not prd_file.is_relative_to(allowed_root):
    sys.exit(1)

try:
    with open(prd_file, encoding="utf-8") as f:
        val = json.load(f).get("max_iterations")
    if not isinstance(val, int) or not val > 0:
        sys.exit(1)
    print(val)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    sys.exit(1)
