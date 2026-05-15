#!/usr/bin/env python3
"""Read max_iterations from a PRD JSON file.

Usage: python3 scripts/read_max_iter.py <prd_file>
Exits with code 1 if the file is missing or malformed (caller falls back to default).
"""
import json
import sys

try:
    with open(sys.argv[1]) as f:
        print(json.load(f)["max_iterations"])
except (IndexError, KeyError, OSError, ValueError, json.JSONDecodeError):
    sys.exit(1)
