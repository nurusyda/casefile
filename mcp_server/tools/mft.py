"""
parse_mft() — MCP tool wrapping Eric Zimmerman's MFTECmd.dll

The Master File Table ($MFT) is the NTFS filesystem's index of every file
and directory that exists or ever existed on a volume. It is one of the
most comprehensive artifacts available in Windows forensics.

What $MFT gives you:
  - Complete file system timeline: creation, modification, access, MFT entry change
  - Deleted files (records persist until overwritten)
  - TIMESTOMPING DETECTION: $MFT stores two sets of timestamps per file:
      $STANDARD_INFORMATION ($SI) — what users and tools normally see
      $FILE_NAME ($FN)            — written by the kernel, harder to forge
    When $SI timestamps predate $FN timestamps, timestomping is CONFIRMED.
    Attackers use tools like Timestomp to backdate $SI to hide when malware arrived.
  - Alternate Data Streams (ADS) — hidden data streams attached to files
  - Zone.Identifier ADS — marks files downloaded from the internet
  - File system slack space (with --rs flag)

Key MFTECmd flags used:
  --at    All timestamps — outputs BOTH $SI and $FN timestamps per file
          This is the ONLY way to detect timestomping
  -f      Single $MFT file extracted from image
  --csv   Output directory
  --csvf  Filename prefix
  -q      Quiet mode

Timestomping detection logic:
  IF si_created_utc < fn_created_utc:
      → $SI creation timestamp predates $FN — TIMESTOMPING CONFIRMED
  IF si_modified_utc < fn_modified_utc and delta > threshold:
      → Suspicious timestamp inconsistency — possible timestomping
  Note: Small deltas (< 2 seconds) are normal due to filesystem operations.
  Use a 60-second threshold to avoid false positives.

Inference Constraint Level: HIGH
  MFTECmd CSV is parsed server-side. The LLM receives typed fields:
  file_path, si timestamps, fn timestamps, is_deleted, ads_info.
  Never raw CSV. Context window cap at 500 (MFT can have millions of records).
  Use filename_filter to target specific files.

Usage by Claude:
  result = parse_mft(
      mft_path="/cases/cr01/evidence/MFT",
      filename_filter=["STUN.exe", "msedge.exe", "pssdnsvc.exe"],
  )
  # result.entries — filtered file records
  # result.timestomped — files with $SI/$FN timestamp inconsistencies
  # result.suspicious — deleted files, ADS, suspicious paths
  # Every finding MUST note: CONFIRMED (MFTECmd, MFT record N)
"""

import csv
import io
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_server.tools._shared import audit_log, run_tool

# Verified path on Protocol SIFT, April 28 2026
MFTECMD_BIN = "dotnet /opt/zimmermantools/MFTECmd.dll"

# Minimum timestamp delta (seconds) to flag as possible timestomping
# Small deltas are normal filesystem noise
TIMESTOMP_THRESHOLD_SECONDS = 60

# Suspicious path fragments for MFT entries
_SUSPICIOUS_PATHS = [
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\recycle",
    "\\$recycle",
    "\\downloads\\",
]

# CRIMSON OSPREY known IOC filenames
_KNOWN_IOCS = [
    "stun.exe",
    "msedge.exe",
    "pssdnsvc.exe",
    "pssdnsvc",
    "atmfd.dll",
]


def _parse_mft_csv(csv_text: str) -> list[dict[str, Any]]:
    """
    Parse MFTECmd --at CSV output into typed dicts.

    MFTECmd --at CSV schema (key columns):
      EntryNumber, SequenceNumber, InUse, ParentEntryNumber,
      FullPath, FileName, Extension, FileSize, ReferenceCount,
      ReparseTarget, IsDirectory, HasAds, IsAds, SI_LastModified,
      SI_LastAccess, SI_MFTRecordChanged, SI_Created,
      FN_LastModified, FN_LastAccess, FN_MFTRecordChanged, FN_Created,
      ObjectIdFileDroid, LogfileSequenceNumber, SecurityId,
      ZoneIdContents, SIMftEntryFlags, FNMftEntryFlags
    """
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        # Parse both SI and FN timestamp sets
        si_created    = _norm_ts(row.get("SI_Created") or "")
        si_modified   = _norm_ts(row.get("SI_LastModified") or "")
        si_access     = _norm_ts(row.get("SI_LastAccess") or "")
        si_mft        = _norm_ts(row.get("SI_MFTRecordChanged") or "")
        fn_created    = _norm_ts(row.get("FN_Created") or "")
        fn_modified   = _norm_ts(row.get("FN_LastModified") or "")
        fn_access     = _norm_ts(row.get("FN_LastAccess") or "")
        fn_mft        = _norm_ts(row.get("FN_MFTRecordChanged") or "")

        # Detect timestomping — $SI creation predates $FN creation
        timestomped, timestomp_delta_s = _check_timestomping(
            si_created, fn_created, si_modified, fn_modified
        )

        full_path = (row.get("FullPath") or "").strip()
        filename  = (row.get("FileName") or "").strip()

        entry: dict[str, Any] = {
            "entry_number":       _safe_int(row.get("EntryNumber") or ""),
            "sequence_number":    _safe_int(row.get("SequenceNumber") or ""),
            "in_use":             (row.get("InUse") or "").strip().upper() == "TRUE",
            "is_deleted":         (row.get("InUse") or "").strip().upper() == "FALSE",
            "full_path":          full_path,
            "filename":           filename,
            "extension":          (row.get("Extension") or "").strip().lower(),
            "file_size_bytes":    _safe_int(row.get("FileSize") or ""),
            "is_directory":       (row.get("IsDirectory") or "").strip().upper() == "TRUE",
            "has_ads":            (row.get("HasAds") or "").strip().upper() == "TRUE",
            "is_ads":             (row.get("IsAds") or "").strip().upper() == "TRUE",
            "zone_id":            (row.get("ZoneIdContents") or "").strip(),
            # $STANDARD_INFORMATION timestamps (what users see)
            "si_created_utc":     si_created,
            "si_modified_utc":    si_modified,
            "si_access_utc":      si_access,
            "si_mft_utc":         si_mft,
            # $FILE_NAME timestamps (kernel-written, harder to forge)
            "fn_created_utc":     fn_created,
            "fn_modified_utc":    fn_modified,
            "fn_access_utc":      fn_access,
            "fn_mft_utc":         fn_mft,
            # Timestomping analysis
            "timestomped":        timestomped,
            "timestomp_delta_s":  timestomp_delta_s,
            # MFT metadata
            "mft_entry":          _safe_int(row.get("EntryNumber") or ""),
            "log_seq_number":     (row.get("LogfileSequenceNumber") or "").strip(),
        }

        if entry["full_path"] or entry["filename"]:
            entries.append(entry)

    return entries


def _check_timestomping(
    si_created: Optional[str],
    fn_created: Optional[str],
    si_modified: Optional[str],
    fn_modified: Optional[str],
) -> tuple[bool, Optional[int]]:
    """
    Compare $SI and $FN timestamps to detect timestomping.

    Returns (is_timestomped, delta_seconds).
    delta_seconds is the creation timestamp difference (SI - FN).
    A negative delta means $SI predates $FN — classic timestomping.
    """
    if not si_created or not fn_created:
        return False, None

    try:
        si_dt = datetime.fromisoformat(si_created.rstrip("Z"))
        fn_dt = datetime.fromisoformat(fn_created.rstrip("Z"))
        delta = int((si_dt - fn_dt).total_seconds())

        # $SI predates $FN by more than threshold = timestomping
        if delta < -TIMESTOMP_THRESHOLD_SECONDS:
            return True, delta

        # Also check modified timestamps
        if si_modified and fn_modified:
            si_mod_dt = datetime.fromisoformat(si_modified.rstrip("Z"))
            fn_mod_dt = datetime.fromisoformat(fn_modified.rstrip("Z"))
            mod_delta = int((si_mod_dt - fn_mod_dt).total_seconds())
            if mod_delta < -TIMESTOMP_THRESHOLD_SECONDS:
                return True, mod_delta

    except (ValueError, AttributeError):
        pass

    return False, None


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Pre-filter MFT entries warranting analyst review.
    Returns subset with 'suspicion_reasons' list.
    All flags are INFERRED except timestomping (which is CONFIRMED).
    """
    flagged = []

    for e in entries:
        reasons: list[str] = []
        path_lower = e.get("full_path", "").lower()
        name_lower = e.get("filename", "").lower()

        # Timestomping — CONFIRMED forensic anomaly
        if e.get("timestomped"):
            delta = e.get("timestomp_delta_s", 0)
            reasons.append(
                f"TIMESTOMPING CONFIRMED — $SI creation predates $FN by "
                f"{abs(delta or 0)}s: {e['full_path']} "
                f"(SI: {e['si_created_utc']} vs FN: {e['fn_created_utc']})"
            )

        # Deleted file — may indicate anti-forensic cleanup
        if e.get("is_deleted"):
            reasons.append(
                f"DELETED file recovered from MFT: {e['full_path']} "
                f"(entry {e['mft_entry']})"
            )

        # Known IOC filenames
        for ioc in _KNOWN_IOCS:
            if ioc in name_lower:
                reasons.append(
                    f"Known CRIMSON OSPREY IOC filename: '{e['filename']}' "
                    f"at {e['full_path']}"
                )
                break

        # Suspicious path
        for frag in _SUSPICIOUS_PATHS:
            if frag in path_lower:
                reasons.append(
                    f"File in suspicious path: {e['full_path']}"
                )
                break

        # Alternate Data Streams — can hide malware payloads
        if e.get("has_ads") and not e.get("is_ads"):
            reasons.append(
                f"File has Alternate Data Stream(s): {e['full_path']} "
                f"— possible hidden payload"
            )

        # Zone.Identifier present — file was downloaded from internet
        if e.get("zone_id") and e.get("zone_id") != "":
            reasons.append(
                f"Zone.Identifier present (downloaded from internet): "
                f"{e['full_path']} — ZoneId: {e['zone_id']}"
            )

        if reasons:
            flagged_entry = dict(e)
            flagged_entry["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged.append(flagged_entry)

    return flagged


def _apply_filename_filter(
    entries: list[dict[str, Any]],
    filename_filter: list[str],
) -> list[dict[str, Any]]:
    """Filter entries to only those matching any of the given filenames."""
    if not filename_filter:
        return entries
    filter_lower = [f.lower() for f in filename_filter]
    return [
        e for e in entries
        if any(
            f in e.get("filename", "").lower() or f in e.get("full_path", "").lower()
            for f in filter_lower
        )
    ]


def _norm_ts(raw: str) -> Optional[str]:
    """Return ISO-8601 UTC string or None."""
    if not raw or raw.strip() in ("", "0", "N/A"):
        return None
    raw = raw.strip().replace(" ", "T")
    if not raw.endswith("Z") and "+" not in raw:
        raw += "Z"
    try:
        datetime.fromisoformat(raw.rstrip("Z"))
        return raw
    except ValueError:
        return raw


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(str(val).strip())
    except (ValueError, AttributeError):
        return None


def _error_result(invocation_id: str, mft_path: str, error_msg: str) -> dict:
    return {
        "invocation_id":      invocation_id,
        "tool":               "MFTECmd",
        "mft_path":           mft_path,
        "run_ts_utc":         datetime.now(timezone.utc).isoformat(),
        "total_entries":      0,
        "entries_returned":   0,
        "entries_capped":     False,
        "entries":            [],
        "timestomped":        [],
        "suspicious":         [],
        "output_dir":         None,
        "duration_ms":        0,
        "error":              error_msg,
        "analyst_note":       None,
    }


def parse_mft(
    mft_path: str,
    output_dir: Optional[str] = None,
    filename_filter: Optional[list[str]] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse the NTFS Master File Table ($MFT) using MFTECmd with --at flag
    for full timestamp analysis including timestomping detection.

    Args:
        mft_path:
            Path to the extracted $MFT file.
            Extract from image: icat <image> 0 > /cases/.../MFT
            Or use image_export: image_export.py --name '$MFT' -w /cases/.../ <image>
            Example: /cases/cr01/evidence/MFT

        output_dir:
            Where MFTECmd writes CSV output.
            Defaults to sibling 'mft_out/' directory.
            Created if it does not exist.

        filename_filter:
            Optional list of filenames or fragments to filter results.
            Without this, $MFT can have millions of records — too large for context.
            Example: ["STUN.exe", "msedge.exe", "pssdnsvc"]
            If None and include_all=False, only suspicious/timestomped entries
            are returned (recommended for initial triage).

        include_all:
            If True, returns all parsed entries (may be very large).
            If False (default), returns only suspicious + timestomped entries
            unless filename_filter is provided, in which case returns filtered set.
            Cap at 500 entries regardless.

    Returns a dict with:
        invocation_id       — UUID (correlate with audit/mcp.jsonl)
        tool                — "MFTECmd"
        mft_path            — echoed input
        run_ts_utc          — when this function ran
        total_entries       — total MFT records parsed (before filter/cap)
        entries_returned    — count in entries[] (filtered + capped)
        entries_capped      — True if results were capped at 500
        entries             — list of MFTEntry dicts
        timestomped         — entries where $SI predates $FN (CONFIRMED anomaly)
        suspicious          — broader set including deleted, IOCs, ADS (INFERRED)
        output_dir          — where CSV was written
        duration_ms         — wall-clock time (MFT parse can take 30-90s)
        error               — null on success
        analyst_note        — CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. MFTECmd does not modify the $MFT file.
        Output CSV written to output_dir only.

    Performance note:
        A typical Windows $MFT is 300MB-2GB and contains 300K-2M records.
        MFTECmd with --at takes 30-90 seconds on SIFT's 8GB laptop.
        Use filename_filter to target specific files and reduce parse time.
        The heartbeat rule applies: if no output after 90s, check RAM with
        free -h and retry with a targeted filter.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    mft = Path(mft_path)
    if not mft.exists():
        return _error_result(
            invocation_id, mft_path,
            f"$MFT file not found: {mft_path}\n"
            "Extract it from the image first:\n"
            "  icat -o <partition_offset> <image> 0 > /cases/.../MFT\n"
            "Or: image_export.py --name '$MFT' -w /cases/.../ <image>"
        )
    if not mft.is_file():
        return _error_result(invocation_id, mft_path,
                             f"Path is not a file: {mft_path}")

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = mft.parent / "mft_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = "mft"

    # ── Build MFTECmd command ─────────────────────────────────────────────────
    # MFTECmd flags:
    #   -f   input $MFT file
    #   --at ALL timestamps — $SI AND $FN (required for timestomping detection)
    #   --csv   output directory
    #   --csvf  filename prefix
    #   -q   quiet
    cmd = (
        f"{MFTECMD_BIN} "
        f"-f {mft} "
        f"--at "
        f"--csv {out_dir} "
        f"--csvf {prefix} "
        f"-q"
    )

    # ── Run MFTECmd ───────────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=300)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="MFTECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, mft_path, str(exc))
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="MFTECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, mft_path, f"Unexpected error: {exc}")

    # ── Find and parse CSV output ─────────────────────────────────────────────
    # MFTECmd --at writes: mft_MFTECmd_Output.csv
    csv_files = list(out_dir.glob(f"{prefix}*.csv"))

    if not csv_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="MFTECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output — $MFT may be corrupt or wrong format"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "MFTECmd",
            "mft_path":         str(mft),
            "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
            "total_entries":    0,
            "entries_returned": 0,
            "entries_capped":   False,
            "entries":          [],
            "timestomped":      [],
            "suspicious":       [],
            "output_dir":       str(out_dir),
            "duration_ms":      duration_ms,
            "error":            None,
            "analyst_note": (
                "MFTECmd produced no output. The $MFT file may be corrupt, "
                "truncated, or not a valid NTFS $MFT. "
                "Verify with: file <mft_path> — should show 'data' not empty."
            ),
        }

    # Parse CSV
    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
        all_entries.extend(_parse_mft_csv(raw))

    total = len(all_entries)

    # ── Apply filename filter if provided ─────────────────────────────────────
    if filename_filter:
        working_set = _apply_filename_filter(all_entries, filename_filter)
    elif not include_all:
        # No filter, no include_all — return only suspicious + timestomped
        # This protects context window when parsing full MFT without a target
        working_set = all_entries  # flagging below will subset this
    else:
        working_set = all_entries

    # ── Find timestomped entries ──────────────────────────────────────────────
    timestomped = [e for e in all_entries if e.get("timestomped")]

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(working_set if filename_filter else all_entries)

    # ── Build final entries list ──────────────────────────────────────────────
    if filename_filter:
        # Return filtered set — analyst asked for specific files
        entries_out = working_set
    elif include_all:
        entries_out = all_entries
    else:
        # Default: return suspicious + timestomped only (context window safe)
        ts_keys = {e["mft_entry"] for e in timestomped}
        susp_keys = {e["mft_entry"] for e in suspicious}
        combined_keys = ts_keys | susp_keys
        entries_out = [e for e in all_entries if e["mft_entry"] in combined_keys]

    # ── Cap at 500 ────────────────────────────────────────────────────────────
    capped = False
    if len(entries_out) > 500:
        entries_out = entries_out[:500]
        capped = True

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="MFTECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "mft_path":           str(mft),
            "output_dir":         str(out_dir),
            "filename_filter":    filename_filter,
            "timestomped_count":  len(timestomped),
            "suspicious_count":   len(suspicious),
            "capped":             capped,
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "MFTECmd",
        "mft_path":         str(mft),
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   capped,
        "entries":          entries_out,
        "timestomped":      timestomped,
        "suspicious":       suspicious,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note": (
            "MFT entry presence CONFIRMS a file existed on the filesystem. "
            "is_deleted=True means the file was deleted but the MFT record "
            "has not yet been overwritten — CONFIRMED deletion, not confirmed removal. "
            "TIMESTOMPING: when si_created_utc predates fn_created_utc by >"
            f"{TIMESTOMP_THRESHOLD_SECONDS}s, this is CONFIRMED forensic anomaly "
            "indicating $SI timestamps were modified after file creation. "
            "ADS (Alternate Data Streams) CONFIRM hidden data exists — "
            "content analysis is INFERRED until streams are extracted. "
            "Zone.Identifier CONFIRMS a file was downloaded from the internet."
        ),
    }
