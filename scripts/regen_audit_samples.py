#!/usr/bin/env python3
"""
regen_audit_samples.py — make results/*_audit_sample.jsonl actually contain the
invocation_ids cited by results/*_findings.json, so a judge's three-claim trace
resolves against the obvious file.

THE PROBLEM THIS FIXES
  results/<CASE>_findings.json cites invocation_ids (e.g. 6cad926d-...). Those
  ids did not appear in the committed results/<CASE>_audit_sample.jsonl, because
  the samples were trimmed independently of the findings. A judge tracing a
  finding against the sample file gets "could not locate" — a failed trace.

WHAT THIS DOES
  1. Builds a global index of real audit entries, keyed by invocation_id, from
     every source you give it: the committed fixture logs, and (recommended) your
     full local audit logs.
  2. For each results/<CASE>_findings.json, collects the invocation_ids cited.
  3. Pulls the matching real entries from the index, sanitizes absolute paths,
     and writes results/<CASE>_audit_sample.jsonl — guaranteeing every cited id
     is present. Optionally pads with N context entries from the same source.
  4. Re-runs the trace and prints, per case, how many cited ids now resolve.

It never invents an entry. If a cited id is not found in any source log, it is
reported as MISSING (so you commit the real full log, not a fabricated line).

USAGE
  # Use only the committed fixtures as the source (works in a fresh clone):
  python3 scripts/regen_audit_samples.py

  # Recommended: also point at your real, full local audit logs (any number):
  python3 scripts/regen_audit_samples.py \
      --extra-audit ~/cases/*/audit/mcp.jsonl \
      --extra-audit audit/mcp.jsonl \
      --context 8

  # Dry run (report only, write nothing):
  python3 scripts/regen_audit_samples.py --dry-run
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Map a results findings file stem to the fixture case dir that holds its logs.
# (results uses SRL-2018_workstation for the disk workstation; the fixture is SRL-2018.)
RESULTS_TO_FIXTURE = {
    "SRL-2018-DC": "SRL-2018-DC",
    "SRL-2018-FILE": "SRL-2018-FILE",
    "SRL-2018_workstation": "SRL-2018",
    "SRL-2018-WKSTN": "SRL-2018-WKSTN",
}

# Path fragments to collapse back to the {{CASE_DIR}} token verify.sh expands.
SANITIZE_PATTERNS = [
    re.compile(r"/home/[^/]+/cases/[^/\"' ]+"),
    re.compile(r"/home/[^/]+/casefile/fixtures/reproducibility/[^/\"' ]+"),
    re.compile(r"/root/cases/[^/\"' ]+"),
    re.compile(r"[^\"' ]*/fixtures/reproducibility/[^/\"' ]+"),
]


def sanitize(entry: dict) -> dict:
    """Replace absolute case paths with the {{CASE_DIR}} token, in place-ish."""
    raw = json.dumps(entry, ensure_ascii=False)
    for pat in SANITIZE_PATTERNS:
        raw = pat.sub("{{CASE_DIR}}", raw)
    return json.loads(raw)


def load_audit_file(path: Path) -> list[dict]:
    out = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        pass
    return out


def collect_cited_ids(obj) -> set[str]:
    ids: set[str] = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if "invocation" in k.lower() and isinstance(v, str) and UUID_RE.match(v):
                    ids.add(v)
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(obj)
    return ids


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-root", default=".", help="repo root (default: cwd)")
    ap.add_argument("--extra-audit", action="append", default=[],
                    help="glob(s) of additional full audit logs to source from (repeatable)")
    ap.add_argument("--context", type=int, default=6,
                    help="extra non-cited entries from the matched source for context (default: 6)")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    results_dir = root / "results"
    fixtures_dir = root / "fixtures" / "reproducibility"

    # ---- Build sources ------------------------------------------------------
    # Global index for resolving any cited id, plus per-source ordered lists for context padding.
    global_index: dict[str, dict] = {}
    source_lists: dict[str, list[dict]] = {}

    fixture_logs = sorted(fixtures_dir.glob("*/audit/mcp.jsonl"))
    extra_logs = []
    for g in args.extra_audit:
        extra_logs.extend(Path(p) for p in glob.glob(os.path.expanduser(g)))

    for log in fixture_logs + extra_logs:
        entries = load_audit_file(log)
        source_lists[str(log)] = entries
        for e in entries:
            iid = e.get("invocation_id")
            if iid and iid not in global_index:
                global_index[iid] = e

    print(f"Indexed {len(global_index)} audit entries from "
          f"{len(fixture_logs)} fixture log(s) + {len(extra_logs)} extra log(s).\n")

    # ---- Process each results findings file --------------------------------
    findings_files = sorted(results_dir.glob("*_findings.json"))
    if not findings_files:
        print("No results/*_findings.json found — nothing to do.")
        return 0

    overall_missing = 0
    for ff in findings_files:
        stem = ff.name.replace("_findings.json", "")
        data = json.loads(ff.read_text(encoding="utf-8"))
        cited = collect_cited_ids(data)

        resolved = {i: global_index[i] for i in cited if i in global_index}
        missing = sorted(cited - resolved.keys())
        overall_missing += len(missing)

        # Pick a context source: the fixture log for this case, if known.
        fx = RESULTS_TO_FIXTURE.get(stem, stem)
        ctx_path = str(fixtures_dir / fx / "audit" / "mcp.jsonl")
        ctx_entries = source_lists.get(ctx_path, [])

        # Assemble sample: all resolved cited entries + up to N context entries
        # (skipping ones already included), sanitized, de-duped, ts-sorted.
        chosen: dict[str, dict] = dict(resolved)
        for e in ctx_entries:
            if len(chosen) >= len(resolved) + args.context:
                break
            iid = e.get("invocation_id")
            if iid and iid not in chosen:
                chosen[iid] = e

        sample = [sanitize(e) for e in chosen.values()]
        sample.sort(key=lambda e: e.get("ts", ""))

        out_path = results_dir / f"{stem}_audit_sample.jsonl"
        status = "OK" if not missing else f"MISSING {len(missing)}"
        print(f"[{stem}] cited={len(cited)} resolved={len(resolved)} "
              f"context+={len(sample) - len(resolved)} -> {out_path.name}  [{status}]")
        if missing:
            for m in missing:
                print(f"    !! cited id not in any source log: {m}")
            print("    -> commit the real full audit log for this case and re-run with "
                  "--extra-audit pointing at it.")

        if not args.dry_run and resolved:
            with out_path.open("w", encoding="utf-8") as fh:
                for e in sample:
                    fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    print()
    if overall_missing:
        print(f"WARNING: {overall_missing} cited id(s) were not found in any source log. "
              f"Those traces will still fail until the real logs are committed.")
        return 1
    print("All cited invocation_ids resolve. Three-claim trace will pass against results/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
