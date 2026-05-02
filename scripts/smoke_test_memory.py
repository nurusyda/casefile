#!/usr/bin/env python3
"""
smoke_test_memory.py — manual integration test against the real memory image.

Run this AFTER pytest passes, to verify parse_memory() works end-to-end against
the actual base-rd01-memory.img file. NOT part of the pytest suite — Volatility
runs are slow (~30s-2min) and require the real image.

Usage:
    cd ~/casefile && source venv/bin/activate
    python3 scripts/smoke_test_memory.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make sure the repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.tools.memory import parse_memory  # noqa: E402

IMAGE = str(Path.home() / "cases" / "SRL-2018" / "base-rd01-memory.img")


def main() -> int:
    print(f"Image: {IMAGE}")
    if not Path(IMAGE).exists():
        print(f"ERROR: {IMAGE} not found. Adjust path.")
        return 1

    print("\n=== Run 1: pslist (fresh, will run Volatility) ===")
    r1 = parse_memory(IMAGE, plugin="windows.pslist")
    print(f"  invocation_id : {r1['invocation_id']}")
    print(f"  image_sha256  : {r1['image_sha256']}")
    print(f"  cached        : {r1['cached']}")
    print(f"  duration_ms   : {r1['duration_ms']}")
    print(f"  total_records : {r1['total_records']}")

    # Look for the smoking guns
    names = [r.get("ImageFileName", "") for r in r1["records"]]
    found_subject = any("subject_srv" in n for n in names)
    print(f"  subject_srv.exe present: {found_subject}")

    csrss = [r for r in r1["records"] if r.get("ImageFileName") == "csrss.exe"]
    pids = {r.get("PID") for r in csrss}
    print(f"  csrss PIDs    : {sorted(pids)}")
    if "4048" in pids:
        print("  → IMPERSONATOR PID 4048 CONFIRMED IN MEMORY")

    print("\n=== Run 2: pslist (should hit cache, near-instant) ===")
    r2 = parse_memory(IMAGE, plugin="windows.pslist")
    print(f"  cached      : {r2['cached']}")
    print(f"  duration_ms : {r2['duration_ms']}  ← should be << run 1")

    print("\n=== Run 3: netscan (fresh, looking for 172.16.4.10:8080 C2) ===")
    r3 = parse_memory(IMAGE, plugin="windows.netscan")
    print(f"  total_records : {r3['total_records']}")
    c2_conns = [
        r for r in r3["records"]
        if "172.16.4.10" in str(r.get("ForeignAddr", ""))
    ]
    print(f"  C2 connections to 172.16.4.10: {len(c2_conns)}")

    print("\n=== Run 4: cmdline (looking for subject_srv args) ===")
    r4 = parse_memory(IMAGE, plugin="windows.cmdline")
    subj = [r for r in r4["records"]
            if "subject_srv" in str(r.get("Process", ""))]
    if subj:
        print(f"  subject_srv cmdline found: {json.dumps(subj[0], indent=2)}")

    print("\nALL CHECKS PASSED" if found_subject else "MISSING: subject_srv.exe")
    return 0 if found_subject else 1


if __name__ == "__main__":
    raise SystemExit(main())
