"""
parse_usn_journal() — MCP tool wrapping Eric Zimmerman's MFTECmd.dll ($J mode)

The USN Change Journal ($UsnJrnl:$J) is a hidden NTFS file that records every
file-system operation — create, delete, rename, write, security-change — in a
rolling circular buffer.  It is the single most powerful anti-forensics counter
in this toolkit because it survives SDELETE and wevtutil log-clearing:

  • SDELETE overwrites file content and MFT entry, but USN still records the
    DELETE_FILE and CLOSE reasons on that record number.
  • wevtutil cl Security deletes the evtx file but the USN shows RENAME and
    DELETE operations on the EVTX path.

What $UsnJrnl:$J gives you:
  - File deleted records (reason flags: 0x200 DELETE_FILE + 0x8000 CLOSE)
  - Rename/move history (old and new filename in consecutive records)
  - Timestomping corroboration (FILE_CREATE followed by DATA_OVERWRITE with
    earlier $SI timestamps than $FN)
  - Anti-forensics detection: tools like SDELETE produce characteristic
    DATA_OVERWRITE + DATA_TRUNCATION + RENAME + DELETE sequences

MFTECmd flags used:
  -f      Path to extracted $J file  ($UsnJrnl:$J extracted from image)
  --csv   Output directory
  --csvf  Filename prefix
  -q      Quiet

Inference Constraint Level: HIGH
  MFTECmd CSV is parsed server-side. The LLM receives typed, bounded fields —
  never raw CSV.  Context cap: 500 records (journal can contain millions).
  Use filename_filter / reason_filter to target specific operations.

Usage by Claude:
  result = parse_usn_journal(
      journal_path="/cases/cr01/evidence/$J",
      filename_filter=["sdelete.exe", "Security.evtx"],
      reason_filter=["DELETE_FILE"],
  )
  # result["entries"]   — filtered USN records
  # result["deleted"]   — files with DELETE_FILE reason
  # result["suspicious"] — anti-forensics patterns (SDELETE sequence, etc.)
  # Every finding MUST cite: CONFIRMED (MFTECmd $J, USN sequence N)

On-disk evidence path: the $J stream must be extracted from the NTFS image
before running this tool.  Common extraction commands:
  icat -o <offset> <image> <$UsnJrnl inode>:$J > /tmp/J
  or: mftexp.pl -j <image> (if installed on SIFT)
"""

from __future__ import annotations

import csv
import io
import os
import re
import shlex
import tempfile
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_server.tools._shared import audit_log, run_tool, PathConfinementError, _enforce_case_root

# Verified on Protocol SIFT — same binary, different input mode
MFTECMD_BIN = "dotnet /opt/zimmermantools/MFTECmd.dll"

# USN Reason flags we care about (bitmask values from MSDN)
# MFTECmd expands these to human-readable pipe-separated strings
_REASON_DELETE = "DELETE_FILE"
_REASON_RENAME_OLD = "RENAME_OLD_NAME"
_REASON_RENAME_NEW = "RENAME_NEW_NAME"
_REASON_DATA_OVERWRITE = "DATA_OVERWRITE"
_REASON_DATA_TRUNCATION = "DATA_TRUNCATION"
_REASON_CLOSE = "CLOSE"

# Anti-forensics: SDELETE produces this sequence on a target file:
#   DATA_OVERWRITE (multiple) → DATA_TRUNCATION → RENAME_OLD_NAME →
#   RENAME_NEW_NAME → DELETE_FILE + CLOSE
# If we see DELETE_FILE + (DATA_OVERWRITE or DATA_TRUNCATION) on the same
# MFT entry number, flag it.
_SDELETE_REASONS = frozenset({_REASON_DATA_OVERWRITE, _REASON_DATA_TRUNCATION})

# Suspicious path fragments (mirrors mft.py for consistency)
_SUSPICIOUS_PATHS = [
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\temp\\",
    "\\users\\public\\",
    "\\recycle",
    "\\$recycle",
    "\\downloads\\",
]

# Maximum records returned to the LLM (journal can be millions of rows)
_MAX_RECORDS = 500


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _norm_ts_to_iso(raw: str) -> Optional[str]:
    """Normalise MFTECmd timestamp to ISO-8601 UTC string or None.

    Handles fractional seconds (e.g. \"2024-02-10 14:30:00.1234567\") which
    MFTECmd $J mode emits.  Digits beyond microsecond precision are truncated.
    """
    if not raw or raw.strip() in ("-", ""):
        return None
    raw = raw.strip().rstrip("Z")
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    # Last resort: strip trailing sub-second digits and retry
    cleaned = re.sub(r"\.(\d{6})\d+", r".\1", raw)
    if cleaned != raw:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
    return None  # unparseable — return None rather than non-ISO string


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return None


def _parse_reasons(raw: str) -> list[str]:
    """Split pipe/comma-separated reason flags into a list."""
    if not raw:
        return []
    return [r.strip() for r in raw.replace(",", "|").split("|") if r.strip()]


def _parse_usn_csv(csv_text: str, max_rows: int = 10000) -> list[dict[str, Any]]:
    """
    Parse MFTECmd $J CSV into typed dicts.

    MFTECmd $J CSV schema (key columns, v1.3+):
      Name, ParentPath, UpdateSequenceNumber, UpdateTimestamp, UpdateReasons,
      FileAttributes, OffsetToData, SourceInfo, SecurityId, MFTEntryNumber,
      MFTSequenceNumber

    Args:
        csv_text: Raw CSV text from MFTECmd output.
        max_rows: Hard limit on rows parsed into memory.  Journals can contain
                  millions of entries; exceeding this limit would OOM a typical
                  SIFT workstation.  Default 10 000.
    """
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_text.replace("\x00", "")))

    for row in reader:
        if len(entries) >= max_rows:
            break
        reasons = _parse_reasons(row.get("UpdateReasons") or "")
        name = (row.get("Name") or "").strip()
        parent = (row.get("ParentPath") or "").strip()
        full_path = f"{parent}\\{name}" if parent else name

        entry: dict[str, Any] = {
            "name": name,
            "parent_path": parent,
            "full_path": full_path,
            "usn": _safe_int(row.get("UpdateSequenceNumber") or ""),
            "timestamp_utc": _norm_ts_to_iso(row.get("UpdateTimestamp") or ""),
            "reasons": reasons,
            "is_delete": _REASON_DELETE in reasons,
            "is_rename_old": _REASON_RENAME_OLD in reasons,
            "is_rename_new": _REASON_RENAME_NEW in reasons,
            "is_data_overwrite": _REASON_DATA_OVERWRITE in reasons,
            "is_data_truncation": _REASON_DATA_TRUNCATION in reasons,
            "is_close": _REASON_CLOSE in reasons,
            "file_attributes": (row.get("FileAttributes") or "").strip(),
            "mft_entry": _safe_int(row.get("MFTEntryNumber") or ""),
            "mft_sequence": _safe_int(row.get("MFTSequenceNumber") or ""),
            "source_info": (row.get("SourceInfo") or "").strip(),
        }

        # Flag suspicious paths
        fp_lower = full_path.lower()
        entry["is_suspicious_path"] = any(sp in fp_lower for sp in _SUSPICIOUS_PATHS)

        entries.append(entry)

    return entries


def _detect_sdelete_sequences(entries: list[dict]) -> list[dict]:
    """
    Detect SDELETE anti-forensics sequences.

    SDELETE pattern on a single MFT entry:
      DATA_OVERWRITE (1+) → DATA_TRUNCATION → RENAME_OLD_NAME →
      RENAME_NEW_NAME (to ZZZZZZZ...) → DELETE_FILE + CLOSE

    We group entries by mft_entry and look for DELETE_FILE records
    that also have DATA_OVERWRITE or DATA_TRUNCATION in the group.
    If RENAME records show a rename to all-Z filename, confidence = HIGH.
    """
    by_entry: dict[int, list[dict]] = defaultdict(list)
    for e in entries:
        if e.get("mft_entry") is not None:
            by_entry[e["mft_entry"]].append(e)

    sequences = []
    for mft_num, group in by_entry.items():
        reasons_seen: set[str] = set()
        for rec in group:
            reasons_seen.update(rec.get("reasons", []))

        has_delete = _REASON_DELETE in reasons_seen
        has_sdelete_marker = bool(reasons_seen & _SDELETE_REASONS)

        if not (has_delete and has_sdelete_marker):
            continue

        # Check for ZZZZZ rename pattern
        new_names = [
            rec["name"] for rec in group
            if rec["is_rename_new"]
        ]
        zzz_rename = any(
            name.upper().startswith("ZZZ") for name in new_names if name
        )

        # Original filename (before rename)
        original_names = [
            rec["name"] for rec in group
            if rec["is_rename_old"]
        ] or [
            rec["name"] for rec in group
            if rec["name"]
        ]
        original_name = original_names[0] if original_names else "UNKNOWN"

        sequences.append({
            "mft_entry": mft_num,
            "original_name": original_name,
            "reasons_observed": sorted(reasons_seen),
            "zzz_rename_detected": zzz_rename,
            "confidence": "HIGH" if zzz_rename else "MEDIUM",
            "mitre": "T1070.004",  # File Deletion
            "implication": (
                f"SDELETE anti-forensics pattern detected on MFT entry {mft_num} "
                f"('{original_name}'): DATA_OVERWRITE+TRUNCATION followed by DELETE. "
                + ("ZZZ rename pattern confirms SDELETE. " if zzz_rename else "")
                + "File content was securely wiped but USN records the operation."
            ),
            "record_timestamps": sorted(
                {rec["timestamp_utc"] for rec in group if rec.get("timestamp_utc")}
            ),
        })

    return sequences


def _detect_evtx_clearing(entries: list[dict]) -> list[dict]:
    """
    Detect event log clearing via wevtutil cl.

    wevtutil cl <log> typically produces:
      RENAME (Security.evtx → temp) or DELETE_FILE + CLOSE on .evtx path,
      followed by FILE_CREATE on the same path (new empty log).

    Heuristic — only flag when:
      a) The same .evtx file is re-created (FILE_CREATE) after deletion
         (indicates deliberate clearing, not log rotation), OR
      b) The deletion occurs in a suspicious path (temp, public, etc.).
    This avoids false positives from legitimate log management.
    """
    # Collect evtx files that are created or deleted, keyed by full_path
    # (falls back to name when full_path is empty / unavailable).
    created_evtx: set[str] = set()
    for e in entries:
        name_lower = (e.get("name") or "").lower()
        if not name_lower.endswith(".evtx"):
            continue
        reasons = e.get("reasons", [])
        if "FILE_CREATE" in reasons:
            key = (e.get("full_path") or name_lower).lower()
            created_evtx.add(key)

    clears = []
    for e in entries:
        name_lower = (e.get("name") or "").lower()
        if not (name_lower.endswith(".evtx") and e.get("is_delete")):
            continue
        key = (e.get("full_path") or name_lower).lower()

        # Suppress if this looks like normal log rotation: file was deleted
        # but never re-created AND path is not suspicious.
        is_recreated = key in created_evtx
        is_suspicious = e.get("is_suspicious_path", False)
        if not is_recreated and not is_suspicious:
            continue

        implication = (
            f"Event log '{e['name']}' was deleted at {e.get('timestamp_utc')} "
            f"(USN sequence {e.get('usn')})"
        )
        if is_recreated:
            implication += (
                f" and subsequently re-created — consistent with wevtutil "
                f"log clearing (T1070.001)."
            )
        else:
            implication += (
                f" from a suspicious path — possible anti-forensic log "
                f"clearing (T1070.001)."
            )

        clears.append({
            "evtx_file": e["name"],
            "full_path": e.get("full_path"),
            "timestamp_utc": e.get("timestamp_utc"),
            "usn": e.get("usn"),
            "mft_entry": e.get("mft_entry"),
            "mitre": "T1070.001",
            "implication": implication,
        })
    return clears


# ---------------------------------------------------------------------------
# Public MCP tool
# ---------------------------------------------------------------------------

def parse_usn_journal(
    journal_path: str,
    filename_filter: Optional[list[str]] = None,
    reason_filter: Optional[list[str]] = None,
    max_results: int = _MAX_RECORDS,
    max_parse_rows: int = 10000,
) -> dict[str, Any]:
    """Parse the NTFS USN Change Journal ($UsnJrnl:$J) extracted from an image.

    Args:
        journal_path: Absolute path to the extracted $J file on the SIFT host.
        filename_filter: If set, only return records whose Name matches one of
            these strings (case-insensitive substring match).
        reason_filter: If set, only return records containing at least one of
            these reason flags (e.g. ["DELETE_FILE", "DATA_OVERWRITE"]).
        max_results: Cap on records returned to LLM (default 500).
        max_parse_rows: Hard limit on rows read from the CSV into memory
            (default 10 000).  Journals can contain millions of entries;
            exceeding this would OOM a typical SIFT workstation.

    Returns:
        dict with keys:
            entries       — filtered USN records (list)
            deleted       — subset with is_delete=True
            suspicious    — anti-forensics patterns detected
            sdelete_sequences — SDELETE-pattern groups by MFT entry
            evtx_clears   — event log clearing indicators
            total_parsed  — total records in CSV before filtering
            invocation_id — UUID for grounding traceability
            tool          — "MFTECmd $J"
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()
    _returncode = 1
    _error_str = ""
    parsed_count = 0

    try:
        # --- Path confinement -----------------------------------------------
        j_path = Path(journal_path).resolve()
        _enforce_case_root(j_path)
        if not j_path.exists():
            _error_str = f"$J file not found: {journal_path}"
            return {
                "error": _error_str,
                "invocation_id": invocation_id,
                "tool": "MFTECmd $J",
            }

        # --- Run MFTECmd in $J mode ----------------------------------------
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = (
                f"{MFTECMD_BIN} -f {shlex.quote(str(j_path))} "
                f"--csv {shlex.quote(tmpdir)} --csvf usn -q"
            )
            result = run_tool(cmd, timeout=300)
            # run_tool() raises RuntimeError on non-zero exit, so the only
            # path past this point is success — no error dict to unpack.

            # Find the output CSV
            csv_files = list(Path(tmpdir).glob("usn*.csv"))
            if not csv_files:
                _error_str = "MFTECmd produced no CSV output — $J may be corrupt or empty"
                return {
                    "error": _error_str,
                    "invocation_id": invocation_id,
                    "tool": "MFTECmd $J",
                }
            csv_text = csv_files[0].read_text(encoding="utf-8-sig", errors="replace")

        # --- Parse CSV ------------------------------------------------------
        full_entries = _parse_usn_csv(csv_text, max_rows=max_parse_rows)
        parsed_count = len(full_entries)

        # --- Derived views (run on FULL set before filtering) ----------------
        # Detection must operate on the complete journal slice so that
        # anti-forensics patterns (SDELETE, EVTX clearing) are reliable
        # regardless of user-supplied filename/reason filters.
        sdelete_sequences = _detect_sdelete_sequences(full_entries)
        evtx_clears = _detect_evtx_clearing(full_entries)
        deleted = [e for e in full_entries if e.get("is_delete")]
        suspicious = [e for e in full_entries if e.get("is_suspicious_path")]

        # --- Apply filename filter ------------------------------------------
        all_entries = full_entries
        if filename_filter:
            targets = [f.lower() for f in filename_filter]
            all_entries = [
                e for e in all_entries
                if any(t in (e.get("name") or "").lower() for t in targets)
            ]

        # --- Apply reason filter -------------------------------------------
        if reason_filter:
            rf_upper = [r.upper() for r in reason_filter]
            all_entries = [
                e for e in all_entries
                if any(r in e.get("reasons", []) for r in rf_upper)
            ]

        # Cap for LLM context safety
        entries = all_entries[:max_results]

        _returncode = 0
        return {
            "entries": entries,
            "deleted": deleted[:_MAX_RECORDS],
            "suspicious": suspicious[:_MAX_RECORDS],
            "sdelete_sequences": sdelete_sequences,
            "evtx_clears": evtx_clears[:_MAX_RECORDS],
            "total_parsed": parsed_count,
            "total_filtered": len(all_entries),
            "total_returned": len(entries),
            "capped": len(all_entries) > max_results,
            "invocation_id": invocation_id,
            "tool": "MFTECmd $J",
        }

    except PathConfinementError as exc:
        _error_str = str(exc)
        return {"error": _error_str, "invocation_id": invocation_id, "tool": "MFTECmd $J"}
    except Exception as exc:  # noqa: BLE001
        _error_str = str(exc)
        return {"error": _error_str, "invocation_id": invocation_id, "tool": "MFTECmd $J"}
    finally:
        elapsed_ms = (time.monotonic() - t_start) * 1000
        audit_log(
            tool="parse_usn_journal",
            invocation_id=invocation_id,
            cmd=f"MFTECmd $J -f {journal_path}",
            returncode=_returncode,
            stdout_lines=parsed_count,
            stderr_excerpt=_error_str[:500],
            parsed_record_count=parsed_count,
            duration_ms=round(elapsed_ms),
            examiner=os.environ.get("CASEFILE_EXAMINER", "unknown"),
            extra={
                "journal_path": journal_path,
                "filename_filter": filename_filter,
                "reason_filter": reason_filter,
            },
        )
