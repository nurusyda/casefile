"""
parse_amcache() — MCP tool wrapping Eric Zimmerman's AmcacheParser.dll

Amcache.hve records SHA1 hashes + first-execution timestamps for every
program that ran on the system. This is one of the highest-value artifacts
for:
  - Confirming program execution (unlike Shimcache, Amcache IS execution evidence)
  - VirusTotal pivots via SHA1 hash (a hash is CONFIRMED; the VT verdict is INFERRED)
  - Detecting renamed malware (path mismatch vs. known-good hash)
  - Establishing program-execution timeline for IOC triage

Inference Constraint Level: HIGH
  AmcacheParser output is fully parsed CSV → structured JSON before the LLM
  ever sees it. The LLM receives typed fields, never raw CSV rows.

Key schema fields returned per entry:
  name, full_path, sha1, first_run_utc, last_modified_utc,
  file_size_bytes, publisher, product_name, description,
  program_id, file_id, source (InventoryApplicationFile | InventoryApplication)

Usage by Claude:
  result = parse_amcache(amcache_path="/cases/cr01/evidence/Amcache.hve")
  # result.entries is a list of AmcacheEntry dicts
  # result.suspicious has pre-filtered candidates (no publisher, weird path, etc.)
  # Every finding citing this tool MUST note: CONFIRMED (AmcacheParser)
"""

import csv
import io
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_server.tools._shared import audit_log, run_tool

# Verified path on Protocol SIFT, April 28 2026
AMCACHE_BIN = "dotnet /opt/zimmermantools/AmcacheParser.dll"

# These path fragments are suspicious regardless of hash
_SUSPICIOUS_PATHS = [
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\recycle",
    "\\$recycle",
]

# Known-legitimate publisher strings (lower-cased substring match)
# Used to flag entries with NO publisher for closer review
_KNOWN_PUBLISHERS = [
    "microsoft",
    "google",
    "mozilla",
    "adobe",
    "oracle",
    "intel",
    "nvidia",
    "amd",
]


def _parse_amcache_csv(csv_text: str) -> list[dict[str, Any]]:
    """
    Parse AmcacheParser CSV output into a list of typed dicts.

    AmcacheParser --csv produces two files:
      *_InventoryApplicationFile.csv   ← per-file execution entries (main data)
      *_InventoryApplication.csv       ← per-application entries (metadata)

    We merge both. The 'source' field tracks which file each row came from.
    """
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        # Normalise field names — AmcacheParser uses PascalCase
        entry: dict[str, Any] = {
            "name":              row.get("Name", "").strip(),
            "full_path":         row.get("FullPath", row.get("Path", "")).strip(),
            "sha1":              row.get("SHA1", row.get("Sha1", "")).strip().lower(),
            "first_run_utc":     _norm_ts(row.get("FileKeyLastWriteTimestamp",
                                                   row.get("KeyLastWriteTimestamp", ""))),
            "last_modified_utc": _norm_ts(row.get("LinkDate", "")),
            "file_size_bytes":   _safe_int(row.get("Size", "")),
            "publisher":         row.get("Publisher", "").strip(),
            "product_name":      row.get("ProductName", "").strip(),
            "description":       row.get("FileDescription", row.get("Description", "")).strip(),
            "program_id":        row.get("ProgramId", "").strip(),
            "file_id":           row.get("FileId", "").strip(),
            "language":          row.get("Language", "").strip(),
            "source":            row.get("_source", "InventoryApplicationFile"),
        }
        # Drop empty-name ghost rows (blank lines AmcacheParser sometimes emits)
        if entry["name"]:
            entries.append(entry)

    return entries


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Pre-filter entries that warrant analyst review.
    Returns a subset — each entry gains a 'suspicion_reasons' list.
    These are INFERRED flags, not CONFIRMED malicious findings.
    """
    flagged = []
    for e in entries:
        reasons: list[str] = []
        path_lower = e["full_path"].lower()

        # Path anomalies — execution from temp/public/programdata dirs
        for frag in _SUSPICIOUS_PATHS:
            if frag in path_lower:
                reasons.append(f"Executed from suspicious path: {e['full_path']}")
                break

        # No publisher for an executable (likely unsigned or packed binary)
        if not e["publisher"] and e["full_path"].endswith(".exe"):
            reasons.append("No publisher (unsigned or unpacked binary)")

        # System32 but publisher is not a known major vendor — classic masquerading
        if "\\system32\\" in path_lower and e["publisher"]:
            pub_lower = e["publisher"].lower()
            if not any(k in pub_lower for k in _KNOWN_PUBLISHERS):
                reasons.append(
                    f"In System32 but publisher is '{e['publisher']}' — possible masquerading"
                )

        # SHA1 VT pivot note — only appended when entry is ALREADY suspicious
        # We don't want to flag every legitimate binary just because it has a hash
        if reasons and e["sha1"] and len(e["sha1"]) == 40:
            reasons.append(f"SHA1 available for VT pivot: {e['sha1']}")

        if reasons:
            flagged_entry = dict(e)
            flagged_entry["suspicion_reasons"] = reasons
            flagged.append(flagged_entry)

    return flagged


def _norm_ts(raw: str) -> Optional[str]:
    """Return ISO-8601 UTC string or None. AmcacheParser outputs vary by version."""
    if not raw or raw.strip() in ("", "0", "N/A"):
        return None
    # Already ISO-ish: '2024-03-15 14:22:01' or '2024-03-15T14:22:01'
    raw = raw.strip().replace(" ", "T")
    if not raw.endswith("Z") and "+" not in raw:
        raw += "Z"
    try:
        datetime.fromisoformat(raw.rstrip("Z"))
        return raw
    except ValueError:
        return raw  # return as-is rather than drop it


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return None


def parse_amcache(
    amcache_path: str,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse an Amcache.hve registry hive using AmcacheParser and return
    structured execution evidence as typed JSON.

    Args:
        amcache_path:
            Absolute path to the Amcache.hve file extracted from a Windows image.
            Example: /cases/cr01/evidence/Amcache.hve

        output_dir:
            Directory where AmcacheParser writes its CSV output files.
            Defaults to a sibling 'amcache_out/' directory next to the hive.
            The directory is created if it does not exist.
            Intermediate CSV files remain here for audit purposes.

        include_all:
            If False (default), entries list is capped at 500 records to avoid
            flooding Claude's context window. The full record count is always
            reported in summary. Set True only when you need the complete dataset
            for a downstream script — not for conversational analysis.

    Returns a dict with:
        invocation_id   — UUID for this call (correlate with audit/mcp.jsonl)
        tool            — "AmcacheParser"
        amcache_path    — echoed input path
        run_ts_utc      — when the MCP function ran
        total_entries   — total records parsed
        entries         — list of AmcacheEntry dicts (capped at 500 unless include_all)
        suspicious      — pre-filtered subset with suspicion_reasons (INFERRED)
        output_dir      — where CSV files were written (for audit trail)
        duration_ms     — wall-clock time for the dotnet invocation
        error           — null on success; error string on failure

    Evidence integrity:
        This function is READ-ONLY. It never modifies amcache_path.
        AmcacheParser opens the hive in read-only mode.
        Output CSV files are written to output_dir, never to evidence paths.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    hive = Path(amcache_path)
    if not hive.exists():
        return _error_result(
            invocation_id, amcache_path,
            f"Amcache.hve not found: {amcache_path}\n"
            "Extract it from the image first: "
            "icat <image> <inode_of_Amcache.hve> > /cases/.../Amcache.hve"
        )
    if not hive.is_file():
        return _error_result(invocation_id, amcache_path,
                             f"Path is not a file: {amcache_path}")

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = hive.parent / "amcache_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Build AmcacheParser command ───────────────────────────────────────────
    # AmcacheParser flags:
    #   -f   input hive
    #   --csv  output directory
    #   --csvf  optional filename prefix (we use the hive stem)
    #   -q   quiet mode (suppress progress bar so stdout is clean CSV only)
    prefix = hive.stem  # e.g. "Amcache"
    cmd = (
        f"{AMCACHE_BIN} "
        f"-f {hive} "
        f"--csv {out_dir} "
        f"--csvf {prefix}"
    )

    # ── Run AmcacheParser ─────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=120)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="AmcacheParser",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, amcache_path, str(exc))
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="AmcacheParser",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, amcache_path,
                             f"Unexpected error: {exc}")

    # ── Locate and parse CSV output files ─────────────────────────────────────
    # AmcacheParser writes one CSV per inventory type, e.g.:
    #   Amcache_InventoryApplicationFile.csv
    #   Amcache_InventoryApplication.csv
    # We parse ALL matching CSVs and merge.
    csv_files = list(out_dir.glob("*.csv"))
    if not csv_files:
        # AmcacheParser sometimes writes no CSV for clean/empty hives
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="AmcacheParser",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output files found — hive may be empty or corrupt"},
        )
        return {
            "invocation_id": invocation_id,
            "tool": "AmcacheParser",
            "amcache_path": str(hive),
            "run_ts_utc": datetime.now(timezone.utc).isoformat(),
            "total_entries": 0,
            "entries": [],
            "suspicious": [],
            "output_dir": str(out_dir),
            "duration_ms": duration_ms,
            "error": None,
            "note": (
                "AmcacheParser produced no CSV output. "
                "The hive may be empty, heavily stripped, or from an OS version "
                "that uses a different Amcache schema. "
                "Verify the hive is readable: file {hive}"
            ),
        }

    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        source_tag = csv_file.stem.replace(prefix + "_", "")
        raw_csv = csv_file.read_text(encoding="utf-8-sig", errors="replace")
        # Tag each row with its source file type
        # We inject _source as a virtual column via pre-processing
        tagged_csv = _inject_source_column(raw_csv, source_tag)
        parsed = _parse_amcache_csv(tagged_csv)
        all_entries.extend(parsed)

    # ── Sort by first_run_utc (ascending) — execution timeline ────────────────
    all_entries.sort(
        key=lambda e: (e.get("first_run_utc") or "0000"),
        reverse=False,
    )

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(all_entries)

    # ── Cap entries for context window safety ─────────────────────────────────
    total = len(all_entries)
    if not include_all and total > 500:
        # Keep ALL suspicious entries (they're the ones Claude needs to see).
        # Fill remaining slots with the most-recently-executed non-suspicious entries.
        # Build suspicious set by sha1+path identity (stable, not id())
        susp_keys = {(e["sha1"], e["full_path"]) for e in suspicious}
        non_susp = [
            e for e in all_entries
            if (e["sha1"], e["full_path"]) not in susp_keys
        ]
        cap = max(0, 500 - len(suspicious))
        entries_out = suspicious + non_susp[-cap:]
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Write audit record ────────────────────────────────────────────────────
    audit_log(
        tool="AmcacheParser",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "amcache_path": str(hive),
            "output_dir": str(out_dir),
            "csv_files": [str(f) for f in csv_files],
            "suspicious_count": len(suspicious),
            "capped": (not include_all and total > 500),
        },
    )

    return {
        "invocation_id": invocation_id,
        "tool": "AmcacheParser",
        "amcache_path": str(hive),
        "run_ts_utc": datetime.now(timezone.utc).isoformat(),
        "total_entries": total,
        "entries_returned": len(entries_out),
        "entries_capped": (not include_all and total > 500),
        "entries": entries_out,
        "suspicious": suspicious,
        "output_dir": str(out_dir),
        "duration_ms": duration_ms,
        "error": None,
        # Reminder embedded in return value so LLM always sees it
        "analyst_note": (
            "Amcache records confirm a file WAS executed and WAS present on the system. "
            "SHA1 hashes can be pivoted to VirusTotal for INFERRED malware verdicts — "
            "a positive VT hit is INFERRED, not CONFIRMED malicious without further analysis. "
            "Suspicious entries are INFERRED candidates; verify each finding independently."
        ),
    }


def _inject_source_column(csv_text: str, source_tag: str) -> str:
    """Prepend a _source column to every row so the parser can tag entries."""
    lines = csv_text.splitlines()
    if not lines:
        return csv_text
    header = lines[0] + ",_source"
    body = [line + f",{source_tag}" for line in lines[1:] if line.strip()]
    return "\n".join([header] + body)


def _error_result(invocation_id: str, amcache_path: str, error_msg: str) -> dict:
    return {
        "invocation_id": invocation_id,
        "tool": "AmcacheParser",
        "amcache_path": amcache_path,
        "run_ts_utc": datetime.now(timezone.utc).isoformat(),
        "total_entries": 0,
        "entries_returned": 0,
        "entries_capped": False,
        "entries": [],
        "suspicious": [],
        "output_dir": None,
        "duration_ms": 0,
        "error": error_msg,
        "analyst_note": None,
    }
