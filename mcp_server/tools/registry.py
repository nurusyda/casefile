"""
parse_registry() — MCP tool wrapping Eric Zimmerman's RECmd.dll

Registry hives contain some of the most durable persistence and execution
evidence on a Windows system. RECmd with the Kroll_Batch.reb batch file
extracts dozens of artifact categories in a single pass.

Why batch mode is the right approach:
  Running RECmd once with Kroll_Batch.reb is faster and more comprehensive
  than running it multiple times for individual keys. The batch file is
  maintained by Kroll (forensic firm) and covers the most forensically
  relevant registry locations. One invocation = complete registry picture.

What the Kroll batch extracts (key categories):
  PERSISTENCE
    Run / RunOnce keys         — programs that auto-start on login
    Services                   — service configurations
    Scheduled tasks (legacy)   — AT job remnants in registry
    Boot Execute               — programs that run before Windows loads
    Image File Execution Options — debugger hijacking / persistence

  EXECUTION EVIDENCE
    UserAssist                 — GUI programs the user launched (with run count)
    BAM/DAM                    — Background Activity Moderator (Win10+)
                                 CONFIRMS execution even after file deletion
    MUICache                   — programs that displayed a UI
    AppCompatFlags             — compatibility shims applied

  USER ACTIVITY
    RecentDocs                 — recently opened documents by extension
    TypedPaths                 — paths typed into Explorer address bar
    WordWheelQuery             — Explorer search terms
    OpenSaveMRU                — files opened/saved via dialog boxes
    LastVisitedMRU             — applications used with open/save dialogs

  SYSTEM / HARDWARE
    USB / USBSTOR              — USB devices connected (VID/PID + timestamps)
    Network interfaces         — NIC configuration
    Timezone                   — system timezone (critical for timestamp analysis)
    Shutdown time              — last clean shutdown

  INSTALLED SOFTWARE
    Installed applications     — from SOFTWARE hive Uninstall keys

Inference Constraint Level: HIGH
  RECmd CSV output is parsed server-side into typed dicts grouped by
  category. The LLM receives structured findings, never raw registry
  key/value dumps.

Key schema fields returned per entry:
  category, hive_type, key_path, value_name, value_data,
  last_write_utc, description, source_hive

Usage by Claude:
  result = parse_registry(
      hive_dir="/cases/cr01/evidence/registry/",
      batch_file="/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb",
  )
  # result.entries — all findings grouped by category
  # result.suspicious — pre-flagged persistence/execution entries
  # Every finding MUST note: CONFIRMED (RECmd, key_path)
  # Registry key presence is CONFIRMED.
  # Whether it was used for malicious purposes is INFERRED.
"""

import csv
import io
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_server.tools._shared import audit_log, run_tool

# Verified paths on Protocol SIFT, April 28 2026
# NOTE: RECmd is in a subdirectory
RECMD_BIN        = "dotnet /opt/zimmermantools/RECmd/RECmd.dll"
KROLL_BATCH_FILE = "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb"

# Registry categories that are HIGH VALUE for persistence investigation
_PERSISTENCE_CATEGORIES = {
    "run",
    "runonce",
    "services",
    "bootexecute",
    "imagefileexecutionoptions",
    "appinit",
    "winlogon",
    "scheduledtasks",
}

# Suspicious value data patterns — flag these regardless of category
_SUSPICIOUS_DATA_PATTERNS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "-enc ",
    "-encodedcommand",
    "downloadstring",
    "iex(",
    "invoke-expression",
    "\\temp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "stun.exe",
    "pssdnsvc",
    "172.15.1.20",
    "172.16.6.12",
]

# Known clean Run key entries — reduces noise in suspicious output
_KNOWN_CLEAN_RUN_VALUES = [
    "SecurityHealth",
    "OneDrive",
    "MicrosoftEdgeAutoLaunch",
    "Teams",
    "Spotify",
]


def _parse_recmd_csv(csv_text: str) -> list[dict[str, Any]]:
    """
    Parse RECmd batch CSV output into typed dicts.

    RECmd batch mode CSV schema (key columns):
      HivePath, HiveType, Description, Category,
      KeyPath, ValueName, ValueData, ValueData2, ValueData3,
      Comment, Recursive, DeletedRecord, LastWriteTimestamp
    """
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        # Normalise — RECmd column names are consistent but we handle both
        value_name = (row.get("ValueName") or "").strip()
        value_data = (row.get("ValueData") or "").strip()
        # ValueData2 and ValueData3 hold additional data for multi-value entries
        value_data2 = (row.get("ValueData2") or "").strip()
        value_data3 = (row.get("ValueData3") or "").strip()

        # Combine all data fields into one searchable string
        combined_data = " | ".join(
            v for v in [value_data, value_data2, value_data3] if v
        )

        entry: dict[str, Any] = {
            "category":       (row.get("Category") or "").strip().lower(),
            "description":    (row.get("Description") or "").strip(),
            "hive_type":      (row.get("HiveType") or "").strip(),
            "key_path":       (row.get("KeyPath") or "").strip(),
            "value_name":     value_name,
            "value_data":     combined_data,
            "last_write_utc": _norm_ts(row.get("LastWriteTimestamp") or ""),
            "comment":        (row.get("Comment") or "").strip(),
            "deleted":        (row.get("DeletedRecord") or "").strip().lower() == "true",
            "source_hive":    (row.get("HivePath") or "").strip(),
        }

        # Only include rows that have actual data
        if entry["key_path"] or entry["value_name"]:
            entries.append(entry)

    return entries


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Pre-filter registry entries warranting analyst review.
    Returns subset with 'suspicion_reasons' list.
    All flags are INFERRED — analyst must verify independently.
    """
    flagged = []

    for e in entries:
        reasons: list[str] = []
        category = e.get("category", "")
        data_lower = e.get("value_data", "").lower()
        key_lower = e.get("key_path", "").lower()
        val_name = e.get("value_name", "")

        # Persistence categories — always flag, they're high value
        if any(p in category for p in _PERSISTENCE_CATEGORIES):
            # But skip known-clean entries to reduce noise
            if val_name not in _KNOWN_CLEAN_RUN_VALUES:
                reasons.append(
                    f"Persistence category '{e['description'] or category}': "
                    f"{val_name} = {e['value_data'][:100]}"
                )

        # Suspicious data patterns in any category
        for pattern in _SUSPICIOUS_DATA_PATTERNS:
            if pattern.lower() in data_lower:
                reasons.append(
                    f"Suspicious pattern '{pattern}' in value data: "
                    f"{e['value_data'][:150]}"
                )
                break  # One pattern match per entry is enough

        # Deleted registry key — may indicate anti-forensics
        if e.get("deleted"):
            reasons.append(
                f"DELETED registry entry recovered — possible anti-forensics: "
                f"{e['key_path']}"
            )

        # Known IOC strings in key path or value name
        iocs = ["stun", "pssdnsvc", "172.15.1.20", "172.16.6.12"]
        for ioc in iocs:
            if ioc in key_lower or ioc in e.get("value_name", "").lower():
                reasons.append(
                    f"Known CRIMSON OSPREY IOC in registry key: '{ioc}' — "
                    f"{e['key_path']}"
                )
                break

        if reasons:
            flagged_entry = dict(e)
            flagged_entry["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged.append(flagged_entry)

    return flagged


def _build_category_summary(entries: list[dict[str, Any]]) -> dict[str, int]:
    """Return count of entries per category for quick overview."""
    summary: dict[str, int] = {}
    for e in entries:
        cat = e.get("category") or "unknown"
        summary[cat] = summary.get(cat, 0) + 1
    return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))


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


def _error_result(invocation_id: str, hive_dir: str, error_msg: str) -> dict:
    return {
        "invocation_id":      invocation_id,
        "tool":               "RECmd",
        "hive_dir":           hive_dir,
        "batch_file":         KROLL_BATCH_FILE,
        "run_ts_utc":         datetime.now(timezone.utc).isoformat(),
        "total_entries":      0,
        "entries_returned":   0,
        "entries_capped":     False,
        "entries":            [],
        "suspicious":         [],
        "category_summary":   {},
        "output_dir":         None,
        "duration_ms":        0,
        "error":              error_msg,
        "analyst_note":       None,
    }


def parse_registry(
    hive_dir: str,
    batch_file: Optional[str] = None,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse Windows registry hives using RECmd with the Kroll batch file and
    return structured persistence and execution evidence as typed JSON.

    Args:
        hive_dir:
            Directory containing extracted registry hive files.
            RECmd will process all hives it finds here recursively.
            Expected hives: NTUSER.DAT, SOFTWARE, SYSTEM, SAM, SECURITY,
            UsrClass.dat — extract these from the image before calling.
            Example: /cases/cr01/evidence/registry/

        batch_file:
            Path to the RECmd batch file (.reb) defining what to extract.
            Defaults to Kroll_Batch.reb at the verified SIFT path.
            Override only if you need a custom batch for specific artifacts.

        output_dir:
            Where RECmd writes its CSV output.
            Defaults to sibling 'registry_out/' directory.
            Created if it does not exist.

        include_all:
            If False (default), entries capped at 500 to protect context window.
            Suspicious entries always included in full.
            Set True only for downstream scripts.

    Returns a dict with:
        invocation_id       — UUID (correlate with audit/mcp.jsonl)
        tool                — "RECmd"
        hive_dir            — echoed input
        batch_file          — batch file used
        run_ts_utc          — when this function ran
        total_entries       — total registry entries extracted
        entries_returned    — count in entries[] (may be capped)
        entries_capped      — True if total > 500 and include_all=False
        entries             — list of RegistryEntry dicts
        suspicious          — pre-flagged subset with suspicion_reasons (INFERRED)
        category_summary    — dict of {category: count} for quick overview
        output_dir          — where CSV was written
        duration_ms         — wall-clock time
        error               — null on success
        analyst_note        — CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. RECmd does not modify hive files.
        Output CSV written to output_dir only.

    Important notes:
        - Registry last_write_utc timestamps are for the KEY, not the value.
          A key timestamp tells you when ANY value in that key last changed,
          not when a specific value was written.
        - UserAssist data is ROT-13 encoded in the raw hive. RECmd decodes it.
        - BAM/DAM is only present on Windows 10 version 1709+ and Server 2019+.
          Its absence on older systems is expected and not a finding.
        - NTUSER.DAT is per-user. If multiple users exist, pass the hive dir
          containing all users' NTUSER.DAT files so all are processed.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    hive_path = Path(hive_dir)
    if not hive_path.exists():
        return _error_result(
            invocation_id, hive_dir,
            f"Hive directory not found: {hive_dir}\n"
            "Extract registry hives from the image first:\n"
            "  image_export.py --name NTUSER.DAT --name SOFTWARE "
            "--name SYSTEM --name SAM -w /cases/.../registry/ <image>"
        )

    # ── Resolve batch file ────────────────────────────────────────────────────
    batch = Path(batch_file) if batch_file else Path(KROLL_BATCH_FILE)
    if not batch.exists():
        return _error_result(
            invocation_id, hive_dir,
            f"Batch file not found: {batch}\n"
            "Verify RECmd is installed: ls /opt/zimmermantools/RECmd/BatchExamples/"
        )

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = hive_path.parent / "registry_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = "registry"

    # ── Build RECmd command ───────────────────────────────────────────────────
    # RECmd batch mode flags:
    #   -d   directory of hive files (processes all recursively)
    #   --bn batch file (.reb)
    #   --csv   output directory
    #   --csvf  filename prefix
    #   -q   quiet
    cmd = (
        f"{RECMD_BIN} "
        f"-d {hive_path} "
        f"--bn {batch} "
        f"--csv {out_dir} "
        f"--csvf {prefix} "
        f"-q"
    )

    # ── Run RECmd ─────────────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=300)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="RECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, str(exc))
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="RECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, hive_dir, f"Unexpected error: {exc}")

    # ── Find and parse CSV output ─────────────────────────────────────────────
    csv_files = list(out_dir.glob(f"{prefix}*.csv"))

    if not csv_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="RECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output — no matching keys or hives not found"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "RECmd",
            "hive_dir":         str(hive_path),
            "batch_file":       str(batch),
            "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
            "total_entries":    0,
            "entries_returned": 0,
            "entries_capped":   False,
            "entries":          [],
            "suspicious":       [],
            "category_summary": {},
            "output_dir":       str(out_dir),
            "duration_ms":      duration_ms,
            "error":            None,
            "analyst_note": (
                "RECmd produced no output. Either no hive files matched the "
                "expected names, or the batch file found no matching keys. "
                "Verify hive files exist: ls -la {hive_dir} and check for "
                "NTUSER.DAT, SOFTWARE, SYSTEM. "
                "Absence of Run key entries is itself a finding on an active system."
            ),
        }

    # Parse all CSV files
    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
        all_entries.extend(_parse_recmd_csv(raw))

    # ── Sort by last_write_utc descending (most recent changes first) ─────────
    all_entries.sort(
        key=lambda e: (e.get("last_write_utc") or "0000"),
        reverse=True,
    )

    # ── Build category summary ────────────────────────────────────────────────
    category_summary = _build_category_summary(all_entries)

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(all_entries)

    # ── Cap for context window ────────────────────────────────────────────────
    total = len(all_entries)
    if not include_all and total > 500:
        susp_keys = {(e["key_path"], e["value_name"]) for e in suspicious}
        non_susp = [
            e for e in all_entries
            if (e["key_path"], e["value_name"]) not in susp_keys
        ]
        cap = max(0, 500 - len(suspicious))
        entries_out = suspicious + non_susp[:cap]
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="RECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "hive_dir":         str(hive_path),
            "batch_file":       str(batch),
            "output_dir":       str(out_dir),
            "csv_files":        [str(f) for f in csv_files],
            "category_summary": category_summary,
            "suspicious_count": len(suspicious),
            "capped":           (not include_all and total > 500),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "RECmd",
        "hive_dir":         str(hive_path),
        "batch_file":       str(batch),
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > 500),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "category_summary": category_summary,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note": (
            "Registry key presence is CONFIRMED. "
            "Run key entries CONFIRM a persistence mechanism exists — "
            "whether it was placed by malware is INFERRED without corroborating evidence. "
            "last_write_utc is the KEY timestamp, not the value timestamp — "
            "it tells you when any value in that key last changed. "
            "UserAssist and BAM/DAM entries CONFIRM program execution. "
            "Deleted entries are recovered by RECmd and marked deleted=True — "
            "their presence may indicate anti-forensic activity."
        ),
    }
