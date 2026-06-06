"""
parse_lnk() — MCP tool wrapping Eric Zimmerman's LECmd.dll

LECmd parses Windows Shortcut (.lnk) files. LNK files record:
  - Target path (where the shortcut points — even if target is deleted)
  - MAC address of the machine that created/modified the shortcut
  - Working directory and command-line arguments
  - Network share paths (UNC targets)
  - File size and timestamps of the target at shortcut creation time
  - Volume serial number and NetBIOS machine name

Why LNK files matter for investigations:
  - Prove an attacker interacted with a specific file or directory
  - Network share shortcuts reveal lateral movement paths
  - WorkingDirectory + Arguments show how a program was launched
  - MachineID (NetBIOS name) ties the shortcut to a specific host
  - LNK files persist after the target file is deleted
  - Tracking data (MAC, volume S/N) can link shortcuts across hosts

Inference Constraint Level: HIGH
  LECmd CSV output is parsed server-side into typed dicts.
  The LLM receives structured shortcut records, never raw binary LNK data.

Key schema fields returned per entry:
  source_file       — path to the .lnk file itself (where it was found)
  target_path       — where the shortcut points
  working_directory — directory the target runs in
  arguments         — command-line args passed to target
  machine_id        — NetBIOS name of creating machine
  mac_address       — MAC of creating machine's network adapter
  created_utc       — target creation timestamp (from LNK, not filesystem)
  modified_utc      — target modification timestamp
  accessed_utc      — target access timestamp
  file_size_bytes   — target file size when shortcut was created
  network_path      — UNC path if target is a network share
  local_path        — local filesystem path
  relative_path     — path relative to the LNK file location
"""

from __future__ import annotations

import csv
import io
import os
import shlex
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_server.tools._shared import audit_log, run_tool, PathConfinementError, _enforce_case_root

LECMD_BIN = "dotnet /opt/zimmermantools/LECmd.dll"

# Maximum LNK entries to return unless include_all=True
_DEFAULT_CAP = 500

_ANALYST_NOTE = (
    "LNK file entries are CONFIRMED — they are parsed from binary .lnk files "
    "on disk and record file system state at the time the shortcut was created "
    "or last modified. Network share targets (UNC paths) confirm lateral "
    "movement paths. MAC address and MachineID tie the shortcut to a specific "
    "workstation. Timestamps in the LNK reflect the TARGET file's metadata at "
    "shortcut creation time, not the LNK file's own filesystem timestamps. "
    "Corroborate LNK timestamps with MFT for the target file when possible."
)

# Suspicious patterns in LNK target paths
_SUSPICIOUS_TARGET_PATTERNS = [
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\appdata\\local\\temp\\",
    "\\recycle",
    "$recycle",
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "rundll32",
    "mshta",
    "regsvr32",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_lecmd_csv(raw: str) -> list[dict[str, Any]]:
    """Parse LECmd CSV output into typed dicts."""
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        entry: dict[str, Any] = {
            "source_file":       row.get("SourceFile", "").strip(),
            "target_path":       row.get("TargetPath", "").strip(),
            "working_directory": row.get("WorkingDirectory", "").strip(),
            "arguments":         row.get("Arguments", "").strip(),
            "machine_id":        row.get("MachineID", "").strip(),
            "mac_address":       row.get("MACAddress", row.get("MACFormatted", "")).strip(),
            "created_utc":       _norm_ts(row.get("TargetCreated", row.get("Created", ""))),
            "modified_utc":      _norm_ts(row.get("TargetModified", row.get("Modified", ""))),
            "accessed_utc":      _norm_ts(row.get("TargetAccessed", row.get("Accessed", ""))),
            "file_size_bytes":   _safe_int(row.get("FileSize", "")),
            "network_path":      row.get("NetworkPath", "").strip(),
            "local_path":        row.get("LocalPath", "").strip(),
            "relative_path":     row.get("RelativePath", "").strip(),
            "common_path":       row.get("CommonPath", "").strip(),
            "volume_droid":      row.get("VolumeDroid", "").strip(),
            "file_droid":        row.get("FileDroid", "").strip(),
            "tracker_data":      row.get("TrackerData", "").strip(),
            "drive_type":        _safe_int(row.get("DriveType", "")),
            "volume_label":      row.get("VolumeLabel", "").strip(),
            "show_window":       row.get("ShowWindow", "").strip(),
            "hot_key":           row.get("HotKey", "").strip(),
            "icon_location":     row.get("IconLocation", "").strip(),
        }
        # Only include entries that have at least a source or target path
        if entry["source_file"] or entry["target_path"]:
            entries.append(entry)
    return entries


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag LNK entries that warrant analyst review."""
    suspicious: list[dict[str, Any]] = []
    for entry in entries:
        reasons: list[str] = []
        target = (entry.get("target_path") or "").lower()
        src = (entry.get("source_file") or "").lower()
        args_raw = (entry.get("arguments") or "").lower()
        net_path = (entry.get("network_path") or "").lower()

        # UNC / network share targets — lateral movement indicator
        if target.startswith("\\\\") or net_path:
            reasons.append(
                f"Network share target: {entry.get('target_path') or entry.get('network_path')} "
                f"— possible lateral movement"
            )

        # Suspicious target directories
        for pattern in _SUSPICIOUS_TARGET_PATTERNS:
            if pattern in target or pattern in src:
                reasons.append(
                    f"Suspicious path pattern '{pattern}' in LNK — verify intent"
                )
                break

        # LNK with arguments — especially suspicious if invoking scripting hosts
        if args_raw:
            for host in ["powershell", "cmd.exe", "wscript", "cscript",
                         "rundll32", "mshta", "regsvr32", "certutil"]:
                if host in target or host in args_raw:
                    reasons.append(
                        f"LNK invokes {host} with arguments — possible execution chain"
                    )
                    break

        # LNK in startup folder or recent-files
        for persistence_path in ["\\startup\\", "\\start menu\\programs\\startup\\"]:
            if persistence_path in src:
                reasons.append("LNK in Startup folder — possible persistence mechanism")
                break

        # LNK in Recent folder (user recently accessed this)
        if "\\recent\\" in src:
            reasons.append("LNK in Recent folder — recently accessed by user")

        if reasons:
            flagged = dict(entry)
            flagged["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged["confidence"] = "INFERRED"
            suspicious.append(flagged)

    return suspicious


def _norm_ts(raw: str) -> Optional[str]:
    """Return ISO-8601 UTC string or None."""
    if not raw or raw.strip() in ("", "0", "N/A", "1601-01-01", "1601-01-01T00:00:00"):
        return None
    raw = raw.strip().replace(" ", "T")
    if not raw.endswith("Z") and "+" not in raw and "-" not in raw[10:]:
        raw += "Z"
    try:
        datetime.fromisoformat(raw.rstrip("Z"))
        return raw
    except ValueError:
        return raw  # return as-is


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return None


def _error_result(invocation_id: str, lnk_path: str, error_msg: str,
                  duration_ms: int = 0) -> dict[str, Any]:
    return {
        "invocation_id":    invocation_id,
        "tool":             "LECmd",
        "lnk_path":         lnk_path,
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    0,
        "entries_returned": 0,
        "entries_capped":   False,
        "entries":          [],
        "suspicious":       [],
        "output_dir":       None,
        "duration_ms":      duration_ms,
        "error":            error_msg,
        "analyst_note":     _ANALYST_NOTE,
    }


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def parse_lnk(
    lnk_path: str,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse Windows Shortcut (.lnk) files using LECmd and return structured
    shortcut evidence as typed JSON.

    Args:
        lnk_path:
            Path to either:
            - A directory containing .lnk files (processes all recursively)
              Example: /cases/cr01/evidence/lnk/
            - A single .lnk file
              Example: /cases/cr01/evidence/lnk/suspicious.lnk
            LECmd handles both.

        output_dir:
            Where LECmd writes CSV output.
            Defaults to sibling 'lnk_out/' directory.
            Created if it does not exist.

        include_all:
            If False (default), entries capped at 500 to protect context window.
            Suspicious entries always included in full.

    Returns a dict with:
        invocation_id     — UUID (correlate with audit/mcp.jsonl)
        tool              — "LECmd"
        lnk_path          — echoed input
        run_ts_utc        — when this ran
        total_entries     — total LNK entries found
        entries_returned  — count in entries[] (may be capped)
        entries_capped    — True if capped
        entries           — list of LNK entry dicts
        suspicious        — pre-flagged entries with suspicion_reasons
        output_dir        — where CSV was written
        duration_ms       — wall-clock time
        error             — null on success
        analyst_note      — CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. LECmd does not modify .lnk files.
        Output CSV written to output_dir only.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    lnk = Path(lnk_path).expanduser().resolve()
    try:
        _enforce_case_root(lnk)
    except PathConfinementError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        return _error_result(invocation_id, lnk_path, str(exc), duration_ms)

    if not lnk.exists():
        duration_ms = int((time.monotonic() - t_start) * 1000)
        err = f"LNK path not found: {lnk_path}"
        audit_log(
            tool="LECmd",
            invocation_id=invocation_id,
            cmd=f"parse_lnk(lnk_path={lnk_path!r})",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=err,
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, lnk_path, err, duration_ms)

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir).expanduser().resolve()
        try:
            _enforce_case_root(out_dir)
        except PathConfinementError as exc:
            duration_ms = int((time.monotonic() - t_start) * 1000)
            return _error_result(invocation_id, lnk_path, str(exc), duration_ms)
    else:
        root_var = os.environ.get("CASEFILE_CASE_ROOT")
        base = Path(root_var) if root_var else (Path.home() / "cases" / "active")
        out_dir = base / "analysis" / "lnk_out" / invocation_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Build LECmd command ───────────────────────────────────────────────────
    prefix = "lnk"
    if lnk.is_dir():
        input_flag = f"-d {shlex.quote(str(lnk))}"
    else:
        input_flag = f"-f {shlex.quote(str(lnk))}"
        prefix = lnk.stem

    cmd = (
        f"{LECMD_BIN} "
        f"{input_flag} "
        f"--csv {shlex.quote(str(out_dir))} "
        f"--csvf {shlex.quote(prefix)}"
    )

    # ── Run LECmd ─────────────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=120)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="LECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, lnk_path, str(exc), duration_ms)
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="LECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, lnk_path,
                             f"Unexpected error: {exc}", duration_ms)

    # ── Find and parse CSV output ─────────────────────────────────────────────
    csv_files = list(out_dir.glob("*.csv"))

    if not csv_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="LECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output — no .lnk files found or directory empty"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "LECmd",
            "lnk_path":         str(lnk),
            "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
            "total_entries":    0,
            "entries_returned": 0,
            "entries_capped":   False,
            "entries":          [],
            "suspicious":       [],
            "output_dir":       str(out_dir),
            "duration_ms":      duration_ms,
            "error":            None,
            "analyst_note": (
                "LECmd produced no output. Either no .lnk files exist in the "
                "target directory, or the files are not valid shortcut files. "
                "Verify the path contains Windows .lnk files."
            ),
        }

    # ── Parse all CSV files ───────────────────────────────────────────────────
    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        try:
            raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
            all_entries.extend(_parse_lecmd_csv(raw))
        except Exception:
            pass  # skip unparseable CSVs

    # ── Sort by created_utc ascending ─────────────────────────────────────────
    all_entries.sort(
        key=lambda e: (e.get("created_utc") or "9999"),
        reverse=False,
    )

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(all_entries)

    # ── Cap for context window safety ─────────────────────────────────────────
    total = len(all_entries)
    if not include_all and total > _DEFAULT_CAP:
        susp_keys = {(e.get("source_file"), e.get("target_path")) for e in suspicious}
        non_susp = [
            e for e in all_entries
            if (e.get("source_file"), e.get("target_path")) not in susp_keys
        ]
        cap = max(0, _DEFAULT_CAP - len(suspicious))
        entries_out = suspicious + non_susp[:cap]
        entries_out.sort(key=lambda e: (e.get("created_utc") or "9999"))
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="LECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "lnk_path":         str(lnk),
            "output_dir":       str(out_dir),
            "csv_files":        [str(f) for f in csv_files],
            "suspicious_count": len(suspicious),
            "capped":           (not include_all and total > _DEFAULT_CAP),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "LECmd",
        "lnk_path":         str(lnk),
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > _DEFAULT_CAP),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note":     _ANALYST_NOTE,
    }
