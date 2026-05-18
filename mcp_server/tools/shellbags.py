"""
parse_shellbags() -- MCP tool wrapping Eric Zimmerman's SBECmd.dll

Shellbags record Windows Explorer folder access and persist even after
folders are deleted. They are stored in NTUSER.DAT and UsrClass.dat.

Why shellbags matter for investigations:
  Shellbags prove a user browsed specific directories -- even if those
  directories and their contents were later deleted. This is critical for:
    - Proving attacker reconnaissance of the file system
    - Corroborating lateral movement paths (attacker browsed \\\\server\\share)
    - Identifying staging directories (attacker browsed C:\\Temp\\exfil\\)
    - USB device access (shellbags record removable drive folders)
    - Deleted directory structure recovery

Inference Constraint Level: HIGH
  SBECmd CSV output is parsed server-side into typed dicts.
  The LLM receives structured folder access records, never raw shellbag data.

Key schema fields returned per entry:
  absolute_path     -- full folder path browsed
  first_interacted  -- first time user browsed this folder (UTC)
  last_interacted   -- most recent browse (UTC)
  mru_position      -- most-recently-used position (lower = more recent)
  source_file       -- NTUSER.DAT or UsrClass.dat
  shell_type        -- type of shell item (drive, folder, network, etc.)
"""
from __future__ import annotations

import csv
import io
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import shlex
from mcp_server.tools._shared import audit_log, run_tool

SBECMD_BIN = "dotnet /opt/zimmermantools/SBECmd.dll"

_ANALYST_NOTE = (
    "CONFIRMED label requires shellbag entry traceable to SBECmd output. "
    "Folder access timestamps are from Explorer interaction -- they do NOT "
    "indicate file access within the folder, only that the folder was opened "
    "in Windows Explorer. Network paths (\\\\\\\\server\\\\share) confirm "
    "attacker browsed remote shares."
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_output_dir(hive_dir: Path, output_dir: Optional[str]) -> Path:
    if output_dir:
        p = Path(output_dir).expanduser().resolve()
    else:
        p = hive_dir.parent / "shellbags_out"
    # mkdir deferred to caller -- after confinement check
    return p


def _require_within_case_root(p: Path) -> None:
    case_root_raw = os.environ.get("CASEFILE_CASE_ROOT", "")
    if not case_root_raw:
        return  # dev/test passthrough
    case_root = Path(case_root_raw).expanduser().resolve()
    resolved = p.resolve()
    try:
        resolved.relative_to(case_root)
    except ValueError:
        raise PermissionError(
            f"Path {resolved} is outside CASEFILE_CASE_ROOT {case_root}"
        )


def _error_result(invocation_id: str, hive_dir: str, error: str, duration_ms: int = 0) -> dict[str, Any]:
    return {
        "invocation_id": invocation_id,
        "tool": "SBECmd",
        "hive_dir": hive_dir,
        "run_ts_utc": datetime.now(timezone.utc).isoformat(),
        "total_entries": 0,
        "entries_returned": 0,
        "entries": [],
        "entries_capped": False,
        "suspicious": [],
        "output_dir": None,
        "duration_ms": duration_ms,
        "error": error,
        "analyst_note": _ANALYST_NOTE,
    }


def _parse_sbecmd_csv(raw: str) -> list[dict[str, Any]]:
    """Parse SBECmd CSV output into typed dicts."""
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        entry: dict[str, Any] = {
            "absolute_path":    row.get("AbsolutePath", "").strip(),
            "first_interacted": row.get("FirstInteracted", "").strip() or None,
            "last_interacted":  row.get("LastInteracted", "").strip() or None,
            "mru_position":     _safe_int(row.get("MRUPosition", "")),
            "source_file":      row.get("SourceFile", "").strip(),
            "shell_type":       row.get("ShellType", "").strip(),
            "slot_modified":    row.get("SlotModified", "").strip() or None,
            "extension":        row.get("Extension", "").strip() or None,
            "value":            row.get("Value", "").strip() or None,
        }
        if entry["absolute_path"]:
            entries.append(entry)
    return entries


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return None


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag shellbag entries that indicate attacker activity."""
    suspicious = []
    for entry in entries:
        path = entry.get("absolute_path", "").lower()
        reasons = []

        # Network share access
        if path.startswith("\\\\") or "\\unc\\" in path or "network" in entry.get("shell_type", "").lower():
            reasons.append("Network share access -- possible lateral movement reconnaissance")

        # Temp/staging directories
        for pattern in ["\\temp\\", "\\tmp\\", "\\users\\public\\", "\\programdata\\"]:
            if pattern in path:
                reasons.append(f"Staging/temp directory accessed: {pattern}")
                break

        # USB/removable drive access
        if "removable" in entry.get("shell_type", "").lower():
            reasons.append("Removable media access -- possible data staging or exfil")

        # Unusual drive letters (not C: or D:)
        if len(path) >= 2 and path[1] == ":" and path[0] not in ("c", "d", "e"):
            reasons.append(f"Unusual drive letter: {path[0].upper()}:")

        # Recycle bin access
        if "$recycle.bin" in path or "recycler" in path:
            reasons.append("Recycle Bin accessed -- possible deleted file recovery")

        # AppData subdirectories
        if "\\appdata\\roaming\\" in path or "\\appdata\\local\\" in path:
            reasons.append("AppData directory browsed -- persistence/staging location")

        if reasons:
            flagged = dict(entry)
            flagged["suspicion_reasons"] = reasons
            flagged["confidence"] = "INFERRED"
            suspicious.append(flagged)

    return suspicious


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def parse_shellbags(
    hive_dir: str,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse Windows Shellbag artifacts using SBECmd to reveal folder access history.

    Shellbags persist in NTUSER.DAT and UsrClass.dat registry hives and record
    every folder a user opened in Windows Explorer -- even after folders are
    deleted. Critical for proving attacker reconnaissance, staging, and
    lateral movement.

    Args:
        hive_dir:
            Directory containing extracted user registry hive files.
            SBECmd needs NTUSER.DAT and/or UsrClass.dat here.
            Extract from C:\\Users\\[username]\\ on the image.
            Example: /cases/cr01/analysis/user_hives/

        output_dir:
            Where SBECmd writes CSV output.
            Defaults to sibling 'shellbags_out/' directory.

        include_all:
            If False (default), entries capped at 500 to protect context window.
            Suspicious entries always included in full.

    Returns a dict with:
        invocation_id     -- UUID (correlate with audit/mcp.jsonl)
        tool              -- "SBECmd"
        hive_dir          -- echoed input
        run_ts_utc        -- when this ran
        total_entries     -- total shellbag entries found
        entries_returned  -- count in entries[] (may be capped)
        entries           -- list of shellbag entry dicts
        suspicious        -- pre-flagged entries with suspicion_reasons
        output_dir        -- where CSV was written
        duration_ms       -- wall-clock time
        error             -- null on success
        analyst_note      -- CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. SBECmd does not modify hive files.
        Output CSV written to output_dir only.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # -- Input validation and path confinement --------------------------------
    hive_path = Path(hive_dir).expanduser().resolve()
    if not hive_path.exists():
        duration_ms = int((time.monotonic() - t_start) * 1000)
        err = f"hive_dir does not exist: {hive_dir}"
        audit_log(
            tool="SBECmd",
            invocation_id=invocation_id,
            cmd=f"parse_shellbags(hive_dir={hive_dir!r})",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=err,
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, err, int((time.monotonic() - t_start) * 1000))

    try:
        _require_within_case_root(hive_path)
    except PermissionError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="SBECmd",
            invocation_id=invocation_id,
            cmd=f"parse_shellbags(hive_dir={hive_dir!r})",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, str(exc), int((time.monotonic() - t_start) * 1000))

    # Check for required hive files
    hive_files = list(hive_path.glob("NTUSER.DAT")) + \
                 list(hive_path.glob("ntuser.dat")) + \
                 list(hive_path.glob("UsrClass.dat")) + \
                 list(hive_path.glob("usrclass.dat"))

    if not hive_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        err = (
            f"No NTUSER.DAT or UsrClass.dat found in {hive_dir}. "
            "Extract user hives from C:\\Users\\[username]\\ on the image. "
            "Update ingest.sh to include user hive extraction."
        )
        audit_log(
            tool="SBECmd",
            invocation_id=invocation_id,
            cmd=f"parse_shellbags(hive_dir={hive_dir!r})",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=err[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, err, int((time.monotonic() - t_start) * 1000))

    out_dir = _resolve_output_dir(hive_path, output_dir)
    try:
        _require_within_case_root(out_dir)
    except PermissionError as exc:
        return _error_result(invocation_id, hive_dir, str(exc), int((time.monotonic() - t_start) * 1000))
    out_dir.mkdir(parents=True, exist_ok=True)  # safe: after confinement

    # -- Build and run SBECmd command -----------------------------------------
    cmd = (
        f"{SBECMD_BIN} -d {shlex.quote(str(hive_path))} "
        f"--csv {shlex.quote(str(out_dir))} --dedupe"
    )

    try:
        result = run_tool(cmd, timeout=120)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="SBECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, str(exc), int((time.monotonic() - t_start) * 1000))
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="SBECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, f"Unexpected error: {exc}", int((time.monotonic() - t_start) * 1000))

    # -- Find and parse CSV output --------------------------------------------
    csv_files = list(out_dir.glob("*.csv"))

    if not csv_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="SBECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output -- hive may have no shellbag entries"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "SBECmd",
            "hive_dir":         str(hive_path),
            "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
            "total_entries":    0,
            "entries_returned": 0,
            "entries":          [],
            "suspicious":       [],
            "output_dir":       str(out_dir),
            "duration_ms":      duration_ms,
            "error":            None,
            "analyst_note": (
                "SBECmd produced no output. Either no shellbag entries exist "
                "in the hive files, or the hives were not recognized. "
                "Verify hive files: NTUSER.DAT and/or UsrClass.dat must be present."
            ),
        }

    # Parse all CSV files
    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        try:
            raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
            all_entries.extend(_parse_sbecmd_csv(raw))
        except Exception as _csv_exc:
            stderr_excerpt = f"[parse_shellbags] Failed to parse {csv_file.name}: {_csv_exc}"[:500]

    # Sort by last_interacted descending
    all_entries.sort(
        key=lambda e: (e.get("last_interacted") or "0000"),
        reverse=True,
    )

    # Flag suspicious entries
    suspicious = _flag_suspicious(all_entries)

    # Cap for context window
    total = len(all_entries)
    if not include_all and total > 500:
        susp_keys = {e["absolute_path"] for e in suspicious}
        non_susp = [e for e in all_entries if e["absolute_path"] not in susp_keys]
        cap = max(0, 500 - len(suspicious))
        entries_out = (suspicious[:500] + non_susp[:max(0, 500 - min(len(suspicious), 500))])[:500]
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    audit_log(
        tool="SBECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "hive_dir":         str(hive_path),
            "output_dir":       str(out_dir),
            "csv_files":        [str(f) for f in csv_files],
            "suspicious_count": len(suspicious),
            "capped":           (not include_all and total > 500),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "SBECmd",
        "hive_dir":         str(hive_path),
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > 500),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note":     _ANALYST_NOTE,
    }
