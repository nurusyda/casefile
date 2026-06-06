"""
parse_jumplists() — MCP tool wrapping Eric Zimmerman's JLECmd.dll

JLECmd parses Windows Jump List files (.automaticDestinations-ms and
.customDestinations-ms). Jump Lists are per-application "recent files"
menus stored in:

  %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\
  %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\

Why Jump Lists matter for investigations:
  - Prove a specific application opened a specific file
  - Track attacker tool usage (RDP, FileZilla, WinSCP, etc.)
  - Reveal staging directories and exfil paths
  - Identify lateral movement tools (RDP jump lists show remote targets)
  - Timestamps show first and last access time per file
  - Persist even after the target file is deleted
  - AppID maps to the application that created the entries

Key AppIDs for DFIR:
  - 1b4dd67f29cb1962  — Remote Desktop (RDP) connection history
  - f01b4d95cf55d32a  — File Explorer (folder access)
  - 9b9cdc69c1c24e2b  — Notepad / text editors
  - 5e5f0b3d5e8c4e3a  — Windows Terminal / PowerShell

Inference Constraint Level: HIGH
  JLECmd CSV output is parsed server-side into typed dicts.
  The LLM receives structured jump list records, never raw binary data.

Key schema fields returned per entry:
  source_file       — path to the .automaticDestinations-ms / .customDestinations-ms file
  app_id            — Application User Model ID that owns the jump list
  target_path       — full path of the destination file
  target_created    — target file creation timestamp (from jump list metadata)
  target_modified   — target file modification timestamp
  target_accessed   — target file access timestamp
  interaction_count — how many times the file was accessed via this jump list
  description       — human-readable description (e.g. "Remote Desktop Connection")
  lnk_path          — embedded LNK data within the jump list entry
  pinned            — whether the entry was pinned to the jump list
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

JLECMD_BIN = "dotnet /opt/zimmermantools/JLECmd.dll"

_DEFAULT_CAP = 500

_ANALYST_NOTE = (
    "Jump List entries are CONFIRMED — they are parsed from binary "
    ".automaticDestinations-ms and .customDestinations-ms files on disk. "
    "Each entry records a specific file that was opened by a specific "
    "application. RDP jump lists (AppID 1b4dd67f29cb1962) reveal remote "
    "desktop connection targets. Interaction count indicates frequency of "
    "use. Files listed may have been deleted — jump lists persist after "
    "target file deletion. Timestamps reflect the target file's metadata "
    "at the time of access, not the jump list file's own timestamps. "
    "Corroborate with MFT and registry for file system context."
)

# High-value AppIDs for DFIR investigations
_HIGH_VALUE_APP_IDS = {
    "1b4dd67f29cb1962": "Remote Desktop Connection (RDP) — lateral movement",
    "f01b4d95cf55d32a": "File Explorer — folder/file browsing history",
    "9b9cdc69c1c24e2b": "Notepad — text file access",
    "5e5f0b3d5e8c4e3a": "Windows Terminal — command-line access",
}

# Suspicious patterns in target paths
_SUSPICIOUS_TARGET_PATTERNS = [
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\appdata\\local\\temp\\",
    "\\recycle",
    "$recycle",
    "\\inetpub\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_jlecmd_csv(raw: str) -> list[dict[str, Any]]:
    """Parse JLECmd CSV output into typed dicts."""
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        entry: dict[str, Any] = {
            "source_file":        row.get("SourceFile", "").strip(),
            "app_id":             row.get("AppId", row.get("AppID", "")).strip(),
            "app_name":           row.get("AppName", "").strip(),
            "description":        row.get("Description", "").strip(),
            "target_path":        row.get("TargetPath", "").strip(),
            "lnk_path":           row.get("LnkPath", "").strip(),
            "target_created":     _norm_ts(row.get("TargetCreated", "")),
            "target_modified":    _norm_ts(row.get("TargetModified", "")),
            "target_accessed":    _norm_ts(row.get("TargetAccessed", "")),
            "interaction_count":  _safe_int(row.get("InteractionCount", "")),
            "pinned":             (row.get("Pinned", "false").strip().lower() == "true"),
            "arguments":          row.get("Arguments", "").strip(),
            "working_directory":  row.get("WorkingDirectory", "").strip(),
            "icon_location":      row.get("IconLocation", "").strip(),
            "entry_type":         row.get("JLEntryType", row.get("EntryType", "")).strip(),
        }
        # Only include entries that have at least a target path or app_id
        if entry["target_path"] or entry["app_id"]:
            entries.append(entry)
    return entries


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag jump list entries that warrant analyst review."""
    suspicious: list[dict[str, Any]] = []
    for entry in entries:
        reasons: list[str] = []
        target = (entry.get("target_path") or "").lower()
        app_id = (entry.get("app_id") or "").lower()

        # RDP connection history
        if "1b4dd67f29cb1962" in app_id:
            reasons.append(
                f"RDP connection target: {entry.get('target_path') or entry.get('lnk_path')} "
                f"— verify source and authorization"
            )

        # Suspicious target directories
        for pattern in _SUSPICIOUS_TARGET_PATTERNS:
            if pattern in target:
                reasons.append(
                    f"Suspicious target path pattern '{pattern}' — verify context"
                )
                break

        # High interaction count with unusual file
        interaction = entry.get("interaction_count")
        if interaction is not None and interaction > 50 and target:
            reasons.append(
                f"High interaction count ({interaction}) with {entry.get('target_path')}"
            )

        # Pinned entries — persistent access
        if entry.get("pinned"):
            reasons.append("Jump list entry is pinned — persistent user access")

        # Target is an executable
        if target.endswith(".exe") or target.endswith(".bat") or target.endswith(".ps1"):
            reasons.append(
                f"Jump list target is an executable: {entry.get('target_path')}"
            )

        if reasons:
            flagged = dict(entry)
            flagged["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged["confidence"] = "INFERRED"
            suspicious.append(flagged)

    return suspicious


def _norm_ts(raw: str) -> Optional[str]:
    if not raw or raw.strip() in ("", "0", "N/A", "1601-01-01", "1601-01-01T00:00:00"):
        return None
    raw = raw.strip().replace(" ", "T")
    if not raw.endswith("Z") and "+" not in raw and "-" not in raw[10:]:
        raw += "Z"
    try:
        datetime.fromisoformat(raw.rstrip("Z"))
        return raw
    except ValueError:
        return raw


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return None


def _error_result(invocation_id: str, jumplist_path: str, error_msg: str,
                  duration_ms: int = 0) -> dict[str, Any]:
    return {
        "invocation_id":    invocation_id,
        "tool":             "JLECmd",
        "jumplist_path":    jumplist_path,
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

def parse_jumplists(
    jumplist_path: str,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse Windows Jump List files using JLECmd and return structured
    application file-access evidence as typed JSON.

    Jump Lists are stored in:
      %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\
      %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\

    Pass the directory containing these folders (or the parent Recent folder).

    Args:
        jumplist_path:
            Path to a directory containing AutomaticDestinations and/or
            CustomDestinations subdirectories.
            Example: /cases/cr01/evidence/jumplists/
            Or a single .automaticDestinations-ms / .customDestinations-ms file.
            JLECmd handles both.

        output_dir:
            Where JLECmd writes CSV output.
            Defaults to sibling 'jumplists_out/' directory.
            Created if it does not exist.

        include_all:
            If False (default), entries capped at 500 to protect context window.
            Suspicious entries always included in full.

    Returns a dict with:
        invocation_id     — UUID (correlate with audit/mcp.jsonl)
        tool              — "JLECmd"
        jumplist_path     — echoed input
        run_ts_utc        — when this ran
        total_entries     — total entries found
        entries_returned  — count in entries[] (may be capped)
        entries_capped    — True if capped
        entries           — list of jump list entry dicts
        suspicious        — pre-flagged entries with suspicion_reasons
        output_dir        — where CSV was written
        duration_ms       — wall-clock time
        error             — null on success
        analyst_note      — CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. JLECmd does not modify jump list files.
        Output CSV written to output_dir only.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    jl = Path(jumplist_path).expanduser().resolve()
    try:
        _enforce_case_root(jl)
    except PathConfinementError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        return _error_result(invocation_id, jumplist_path, str(exc), duration_ms)

    if not jl.exists():
        duration_ms = int((time.monotonic() - t_start) * 1000)
        err = f"Jump list path not found: {jumplist_path}"
        audit_log(
            tool="JLECmd",
            invocation_id=invocation_id,
            cmd=f"parse_jumplists(jumplist_path={jumplist_path!r})",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=err,
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, jumplist_path, err, duration_ms)

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir).expanduser().resolve()
        try:
            _enforce_case_root(out_dir)
        except PathConfinementError as exc:
            duration_ms = int((time.monotonic() - t_start) * 1000)
            return _error_result(invocation_id, jumplist_path, str(exc), duration_ms)
    else:
        root_var = os.environ.get("CASEFILE_CASE_ROOT")
        base = Path(root_var) if root_var else (Path.home() / "cases" / "active")
        out_dir = base / "analysis" / "jumplists_out" / invocation_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Build JLECmd command ──────────────────────────────────────────────────
    prefix = "jumplists"
    if jl.is_dir():
        input_flag = f"-d {shlex.quote(str(jl))}"
    else:
        input_flag = f"-f {shlex.quote(str(jl))}"
        prefix = jl.stem

    cmd = (
        f"{JLECMD_BIN} "
        f"{input_flag} "
        f"--csv {shlex.quote(str(out_dir))} "
        f"--csvf {shlex.quote(prefix)}"
    )

    # ── Run JLECmd ────────────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=120)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="JLECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, jumplist_path, str(exc), duration_ms)
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="JLECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, jumplist_path,
                             f"Unexpected error: {exc}", duration_ms)

    # ── Find and parse CSV output ─────────────────────────────────────────────
    csv_files = list(out_dir.glob("*.csv"))

    if not csv_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="JLECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output — no jump list files found or directory empty"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "JLECmd",
            "jumplist_path":    str(jl),
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
                "JLECmd produced no output. Either no jump list files exist in "
                "the target directory, or the files are not valid. Verify the "
                "path contains .automaticDestinations-ms or .customDestinations-ms files."
            ),
        }

    # ── Parse all CSV files ───────────────────────────────────────────────────
    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        try:
            raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
            all_entries.extend(_parse_jlecmd_csv(raw))
        except Exception:
            pass

    # ── Sort by target_accessed descending (most recent first) ────────────────
    all_entries.sort(
        key=lambda e: (e.get("target_accessed") or "0000"),
        reverse=True,
    )

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(all_entries)

    # ── Cap for context window safety ─────────────────────────────────────────
    total = len(all_entries)
    if not include_all and total > _DEFAULT_CAP:
        susp_keys = {(e.get("app_id"), e.get("target_path")) for e in suspicious}
        non_susp = [
            e for e in all_entries
            if (e.get("app_id"), e.get("target_path")) not in susp_keys
        ]
        cap = max(0, _DEFAULT_CAP - len(suspicious))
        entries_out = suspicious + non_susp[:cap]
        entries_out.sort(key=lambda e: (e.get("target_accessed") or "0000"),
                         reverse=True)
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="JLECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "jumplist_path":    str(jl),
            "output_dir":       str(out_dir),
            "csv_files":        [str(f) for f in csv_files],
            "suspicious_count": len(suspicious),
            "capped":           (not include_all and total > _DEFAULT_CAP),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "JLECmd",
        "jumplist_path":    str(jl),
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
