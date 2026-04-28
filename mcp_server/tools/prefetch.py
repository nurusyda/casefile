r"""
parse_prefetch() — MCP tool wrapping Eric Zimmerman's PECmd.dll

Prefetch files (.pf) in C:\Windows\Prefetch\ record every program that ran
on the system. Windows creates one .pf file per executable, updated on each
run. This makes Prefetch one of the most reliable execution evidence sources.

Key facts about Prefetch as an artifact:
  - CONFIRMS a program ran (unlike Registry Run keys which only show persistence)
  - Records up to 8 last run timestamps (Windows 8+)
  - Records exact run count since Prefetch file creation
  - Records every file and directory loaded during execution
    (DLLs, config files, data files — reveals what the malware touched)
  - File name includes hash of the executable path:
    EVIL.EXE-AB12CD34.pf -- same binary run from different paths = different hash
    This means a renamed binary in a different dir creates a NEW .pf file

Inference Constraint Level: HIGH
  PECmd CSV output is fully parsed server-side before the LLM sees it.
  The LLM receives typed fields: name, run_count, last_run_utc, files_loaded.
  Never raw CSV.

Key schema fields returned per entry:
  executable_name, full_path, run_count,
  last_run_utc, previous_run_times (list, up to 7),
  files_loaded (list of paths loaded during execution),
  directories_referenced (list),
  volume_name, volume_serial, volume_created,
  source_file (.pf filename)

Usage by Claude:
  result = parse_prefetch(prefetch_path="/cases/cr01/evidence/Prefetch/")
  # result.entries — all prefetch entries sorted by last_run_utc
  # result.suspicious — pre-flagged candidates
  # Every finding MUST note: CONFIRMED (PECmd)
  # Run count and timestamps are CONFIRMED.
  # What the execution *did* is INFERRED from files_loaded.
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
PECMD_BIN = "dotnet /opt/zimmermantools/PECmd.dll"

# Suspicious path fragments in prefetch full_path or files_loaded
_SUSPICIOUS_PATHS = [
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\recycle",
    "\\$recycle",
    "\\downloads\\",
]

# Known LOLBAS / dual-use binaries that are suspicious when run unexpectedly
# Running certutil.exe or mshta.exe is not inherently malicious, but warrants review
_LOLBAS = [
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "cmd.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "net.exe",
    "net1.exe",
    "schtasks.exe",
    "at.exe",
    "psexec.exe",
    "psexesvc.exe",
]


def _parse_prefetch_csv(csv_text: str) -> list[dict[str, Any]]:
    """
    Parse PECmd CSV output into typed dicts.

    PECmd --csv produces one file:
      *_Timeline.csv  — one row per execution timestamp (multiple rows per binary)
      *_PECmd.csv     — one row per .pf file (our primary source)

    We parse the main PECmd CSV. The Timeline CSV is optional and used for
    enriching previous_run_times.
    """
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        # PECmd CSV column names (verified against PECmd 1.5+)
        # Files loaded and directories are pipe-separated within the cell
        files_raw = row.get("FilesLoaded", row.get("Files Loaded", ""))
        dirs_raw  = row.get("Directories", row.get("DirectoriesReferenced", ""))

        files_loaded = [f.strip() for f in files_raw.split("|") if f.strip()]
        directories  = [d.strip() for d in dirs_raw.split("|") if d.strip()]

        # Previous run times — PECmd stores up to 7 additional timestamps
        prev_times: list[Optional[str]] = []
        for i in range(1, 8):
            col = f"RunTime{i}" if f"RunTime{i}" in row else f"Run Time {i}"
            raw = row.get(col, "").strip()
            if raw:
                prev_times.append(_norm_ts(raw))

        entry: dict[str, Any] = {
            "executable_name":        row.get("ExecutableName", row.get("Executable Name", "")).strip(),
            "full_path":              row.get("SourceFilePath", row.get("Source File Path", "")).strip(),
            "source_file":            row.get("SourceFileName", row.get("Source File Name", "")).strip(),
            "run_count":              _safe_int(row.get("RunCount", row.get("Run Count", ""))),
            "last_run_utc":           _norm_ts(row.get("LastRun", row.get("Last Run", ""))),
            "previous_run_times":     [t for t in prev_times if t],
            "files_loaded":           files_loaded,
            "files_loaded_count":     len(files_loaded),
            "directories_referenced": directories,
            "volume_name":            row.get("VolumeName", row.get("Volume Name", "")).strip(),
            "volume_serial":          row.get("VolumeSerial", row.get("Volume Serial", "")).strip(),
            "volume_created":         _norm_ts(row.get("VolumeCreated", row.get("Volume Created", ""))),
            "hash":                   row.get("Hash", "").strip(),  # path hash in .pf filename
            "size":                   _safe_int(row.get("Size", "")),
        }

        if entry["executable_name"]:
            entries.append(entry)

    return entries


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Pre-filter prefetch entries that warrant analyst review.
    Returns a subset with 'suspicion_reasons' list added.
    All flags are INFERRED — analyst must verify each independently.
    """
    flagged = []

    for e in entries:
        reasons: list[str] = []
        name_lower  = e["executable_name"].lower()
        path_lower  = e["full_path"].lower()

        # Executed from a suspicious directory
        for frag in _SUSPICIOUS_PATHS:
            if frag in path_lower:
                reasons.append(f"Executed from suspicious path: {e['full_path']}")
                break

        # LOLBAS / dual-use binary — not malicious by itself, but flag for review
        if name_lower in _LOLBAS:
            reasons.append(
                f"LOLBAS / dual-use binary: {e['executable_name']} "
                f"(run count: {e['run_count']}, last run: {e['last_run_utc']})"
            )

        # High run count for something in a temp/user-writable path
        rc = e.get("run_count") or 0
        if rc > 20 and any(frag in path_lower for frag in _SUSPICIOUS_PATHS):
            reasons.append(
                f"High run count ({rc}) from suspicious path — possible persistence loop"
            )

        # Executable name looks like a system binary but path is not System32
        system_names = ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                        "services.exe", "smss.exe", "wininit.exe"]
        if name_lower in system_names and "\\system32\\" not in path_lower:
            reasons.append(
                f"System binary name '{e['executable_name']}' ran from non-System32 path — "
                f"possible masquerading: {e['full_path']}"
            )

        # Loaded a suspicious file during execution (DLL sideloading, config drop)
        for f in e.get("files_loaded", []):
            f_lower = f.lower()
            for frag in _SUSPICIOUS_PATHS:
                if frag in f_lower:
                    reasons.append(
                        f"Loaded file from suspicious path during execution: {f}"
                    )
                    break

        if reasons:
            flagged_entry = dict(e)
            flagged_entry["suspicion_reasons"] = list(dict.fromkeys(reasons))  # dedup
            flagged.append(flagged_entry)

    return flagged


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


def _error_result(invocation_id: str, prefetch_path: str, error_msg: str) -> dict:
    return {
        "invocation_id":    invocation_id,
        "tool":             "PECmd",
        "prefetch_path":    prefetch_path,
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    0,
        "entries_returned": 0,
        "entries_capped":   False,
        "entries":          [],
        "suspicious":       [],
        "output_dir":       None,
        "duration_ms":      0,
        "error":            error_msg,
        "analyst_note":     None,
    }


def parse_prefetch(
    prefetch_path: str,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse Prefetch files (.pf) using PECmd and return structured execution
    evidence as typed JSON.

    Args:
        prefetch_path:
            Path to either:
            - A directory containing .pf files (e.g. extracted Prefetch folder)
              Example: /cases/cr01/evidence/Prefetch/
            - A single .pf file
              Example: /cases/cr01/evidence/Prefetch/STUN.EXE-AB12CD34.pf
            PECmd handles both — if a directory is given it processes all .pf files.

        output_dir:
            Where PECmd writes its CSV output.
            Defaults to a sibling 'prefetch_out/' directory next to prefetch_path.
            Created if it does not exist.

        include_all:
            If False (default), entries list capped at 500 to protect context window.
            Suspicious entries always included in full regardless of cap.
            Set True only for downstream scripts, not conversational analysis.

    Returns a dict with:
        invocation_id       — UUID for this call (correlate with audit/mcp.jsonl)
        tool                — "PECmd"
        prefetch_path       — echoed input path
        run_ts_utc          — when this function ran
        total_entries       — total .pf files parsed
        entries_returned    — how many are in entries[] (may be capped)
        entries_capped      — True if total > 500 and include_all=False
        entries             — list of PrefetchEntry dicts sorted by last_run_utc desc
        suspicious          — pre-filtered subset with suspicion_reasons (INFERRED)
        output_dir          — where CSV files were written
        duration_ms         — wall-clock time for the dotnet invocation
        error               — null on success, error string on failure
        analyst_note        — embedded reminder about CONFIRMED vs INFERRED

    Evidence integrity:
        READ-ONLY. PECmd opens .pf files in read mode only.
        Output CSV files written to output_dir, never to evidence paths.

    Common gotcha:
        Prefetch is DISABLED by default on Windows Server editions and SSDs
        with certain firmware. If the Prefetch folder is empty or absent,
        document this as a finding — absence of Prefetch is itself significant.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    pf_path = Path(prefetch_path)
    if not pf_path.exists():
        return _error_result(
            invocation_id, prefetch_path,
            f"Prefetch path not found: {prefetch_path}\n"
            "Extract the Prefetch folder from the image first:\n"
            "  image_export.py --extension pf -w /cases/.../Prefetch/ <image>"
        )

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir)
    else:
        # Place output next to the prefetch path regardless of file vs dir
        base = pf_path if pf_path.is_dir() else pf_path.parent
        out_dir = base.parent / "prefetch_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Build PECmd command ───────────────────────────────────────────────────
    # PECmd flags:
    #   -f   single .pf file
    #   -d   directory of .pf files (process all)
    #   --csv   output directory
    #   --csvf  filename prefix
    #   -q   quiet (no progress bar)
    prefix = "prefetch"
    if pf_path.is_dir():
        input_flag = f"-d {pf_path}"
    else:
        input_flag = f"-f {pf_path}"
        prefix = pf_path.stem  # e.g. "STUN.EXE-AB12CD34"

    cmd = (
        f"{PECMD_BIN} "
        f"{input_flag} "
        f"--csv {out_dir} "
        f"--csvf {prefix} "
        f"-q"
    )

    # ── Run PECmd ─────────────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=180)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="PECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, prefetch_path, str(exc))
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="PECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, prefetch_path,
                             f"Unexpected error: {exc}")

    # ── Find and parse CSV output ─────────────────────────────────────────────
    # PECmd writes:
    #   prefetch_PECmd_Output.csv    ← main output, one row per .pf file
    #   prefetch_Timeline.csv        ← one row per execution timestamp
    # We parse the main output. Timeline is used for enrichment if present.
    main_csvs = [
        f for f in out_dir.glob(f"{prefix}*.csv")
        if "timeline" not in f.name.lower()
    ]
    timeline_csvs = [
        f for f in out_dir.glob(f"{prefix}*.csv")
        if "timeline" in f.name.lower()
    ]

    if not main_csvs:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="PECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output — Prefetch folder may be empty or disabled"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "PECmd",
            "prefetch_path":    str(pf_path),
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
                "PECmd produced no output. Prefetch may be disabled (common on "
                "Windows Server or some SSD configurations) or the folder is empty. "
                "Document absence of Prefetch as a finding — it is not neutral."
            ),
        }

    # Parse main CSV
    all_entries: list[dict[str, Any]] = []
    for csv_file in main_csvs:
        raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
        all_entries.extend(_parse_prefetch_csv(raw))

    # ── Sort by last_run_utc descending (most recent first) ───────────────────
    # Descending for Prefetch — analyst cares most about RECENT executions
    all_entries.sort(
        key=lambda e: (e.get("last_run_utc") or "0000"),
        reverse=True,
    )

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(all_entries)

    # ── Cap for context window safety ─────────────────────────────────────────
    total = len(all_entries)
    if not include_all and total > 500:
        susp_keys = {(e["executable_name"], e["source_file"]) for e in suspicious}
        non_susp = [
            e for e in all_entries
            if (e["executable_name"], e["source_file"]) not in susp_keys
        ]
        cap = max(0, 500 - len(suspicious))
        entries_out = suspicious + non_susp[:cap]  # most recent non-suspicious first
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="PECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "prefetch_path":    str(pf_path),
            "output_dir":       str(out_dir),
            "main_csvs":        [str(f) for f in main_csvs],
            "timeline_csvs":    [str(f) for f in timeline_csvs],
            "suspicious_count": len(suspicious),
            "capped":           (not include_all and total > 500),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "PECmd",
        "prefetch_path":    str(pf_path),
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > 500),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note": (
            "Prefetch CONFIRMS execution — run_count and last_run_utc are CONFIRMED. "
            "files_loaded shows what the binary touched during execution — "
            "DLL paths, config files, staging directories — treat as CONFIRMED presence "
            "but INFERRED intent. "
            "Suspicious entries are INFERRED candidates; verify each independently. "
            "Absent Prefetch on a workstation (not server) is itself a suspicious finding."
        ),
    }
