"""
parse_event_logs() — MCP tool wrapping Eric Zimmerman's EvtxECmd.dll

Windows Event Logs (.evtx) are the primary source for:
  - Logon/authentication events (who logged in, from where, how)
  - Process creation with command-line arguments (what ran and with what flags)
  - Service installation (persistence via services)
  - PowerShell script block logging (what scripts executed)
  - Lateral movement (RDP, net use, explicit credential use)
  - Defender alerts (malware detections, real-time protection changes)

EvtxECmd normalises ALL event log types into a single consistent CSV schema.
This means one parser handles Security.evtx, System.evtx, PowerShell/Operational,
Microsoft-Windows-TaskScheduler/Operational, and hundreds more.

Inference Constraint Level: HIGH
  EvtxECmd CSV is parsed server-side into typed dicts before the LLM sees it.
  The LLM receives structured fields: event_id, timestamp, machine, user,
  payload_data (key fields extracted from the XML payload).
  Never raw XML or raw CSV.

Key Event IDs and what they confirm:

  EXECUTION / PROCESS
  4688  Process created — CONFIRMED execution (requires AuditProcessCreation + cmdline logging)
  4689  Process exited

  AUTHENTICATION
  4624  Logon success — type 2=interactive, 3=network, 10=remote interactive (RDP)
  4625  Logon failure
  4648  Explicit credentials used (runas / Pass-the-Hash indicator)
  4672  Admin privileges assigned to new logon

  POWERSHELL
  4103  Module logging
  4104  Script block logging — HIGHEST VALUE for malware scripts
  400   PowerShell engine started

  RDP
  1149  RDP auth success + source IP (Microsoft-Windows-TerminalServices-RemoteConnectionManager)
  4778  RDP session reconnect
  4779  RDP session disconnect

  SERVICES / PERSISTENCE
  7034  Service crashed unexpectedly
  7045  New service installed — CONFIRMED persistence attempt

  SCHEDULED TASKS
  106   Task registered
  129   Task launched
  200   Task action started

  DEFENDER
  1116  Malware detected
  5001  Real-time protection disabled

  WMI
  5861  WMI permanent subscription created — persistence

Usage by Claude:
  result = parse_event_logs(
      evtx_path="/cases/cr01/evidence/evtx/",
      event_ids=[4688, 4624, 4648, 7045, 1116],
  )
  # result.entries — events sorted oldest-first (timeline order)
  # result.suspicious — pre-flagged high-interest events
  # Every finding MUST note: CONFIRMED (EvtxECmd, EventID XXXX)
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
# NOTE: EvtxECmd is in a subdirectory unlike the other EZ Tools
EVTXECMD_BIN = "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"

# Default Event IDs to collect when caller passes none
# These are the highest-value IDs for a typical intrusion investigation
DEFAULT_EVENT_IDS = [
    4624,   # Logon success
    4625,   # Logon failure
    4648,   # Explicit credentials
    4672,   # Admin logon
    4688,   # Process creation
    4689,   # Process exit
    4103,   # PowerShell module
    4104,   # PowerShell script block
    1149,   # RDP auth success
    4778,   # RDP reconnect
    7034,   # Service crash
    7045,   # New service installed
    106,    # Scheduled task registered
    200,    # Scheduled task action started
    1116,   # Defender malware detection
    5001,   # Defender real-time protection disabled
    5861,   # WMI permanent subscription
]

# Event IDs that are HIGH CONFIDENCE indicators of malicious activity
# These get flagged in suspicious regardless of other context
_HIGH_CONFIDENCE_IDS = {
    4104,   # PowerShell script block — almost always worth reviewing
    7045,   # New service — persistence
    1116,   # Defender detection
    5001,   # Defender disabled
    5861,   # WMI subscription — persistence
    4648,   # Explicit credentials — lateral movement indicator
}

# Suspicious process names in 4688 events
_SUSPICIOUS_PROCESSES = [
    "stun.exe",
    "psexec.exe",
    "psexesvc.exe",
    "mimikatz.exe",
    "procdump.exe",
    "wce.exe",
    "pwdump.exe",
]

# Suspicious command-line fragments in 4688 events
_SUSPICIOUS_CMDLINE = [
    "net use",          # lateral movement / share mapping
    "net user",         # account enumeration/creation
    "net localgroup",   # group membership changes
    "-enc ",            # PowerShell encoded command (often used to hide payload)
    "-encodedcommand",
    "iex(",             # Invoke-Expression — classic download cradle
    "invoke-expression",
    "downloadstring",   # download cradle
    "webclient",
    "certutil -decode", # certutil abuse
    "certutil -urlcache",
    "bitsadmin /transfer",
    "wmic process call create",
    "schtasks /create",
    "sc create",
    "reg add",
    "172.15.1.20",      # CRIMSON OSPREY attacker IP
    "172.16.6.12",      # lateral movement target
]

# Logon types and their human-readable meaning
_LOGON_TYPES = {
    "2":  "Interactive (local keyboard)",
    "3":  "Network (e.g. net use, SMB)",
    "4":  "Batch (scheduled task)",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials (runas /netonly)",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def _parse_evtx_csv(csv_text: str) -> list[dict[str, Any]]:
    """
    Parse EvtxECmd CSV output into typed dicts.

    EvtxECmd CSV schema (key columns):
      Channel, Computer, EventId, TimeCreated, UserId,
      UserName, MapDescription, PayloadData1..6, ExecutableInfo,
      RemoteHost, Keywords, Provider, RecordNumber
    """
    entries: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        event_id = _safe_int(row.get("EventId", row.get("Event Id", "")))
        if event_id is None:
            continue

        # PayloadData1-6 contain the extracted fields EvtxECmd parsed from XML
        payload_fields = []
        for i in range(1, 7):
            val = (row.get(f"PayloadData{i}") or row.get(f"Payload Data {i}") or "").strip()
            if val:
                payload_fields.append(val)

        entry: dict[str, Any] = {
            "event_id":       event_id,
            "timestamp_utc":  _norm_ts(row.get("TimeCreated", row.get("Time Created", ""))),
            "channel":        (row.get("Channel") or "").strip(),
            "computer":       (row.get("Computer") or "").strip(),
            "user_id":        (row.get("UserId") or row.get("User Id") or "").strip(),
            "username":       (row.get("UserName") or row.get("User Name") or "").strip(),
            "description":    (row.get("MapDescription") or row.get("Map Description") or "").strip(),
            "payload_data":   payload_fields,
            "executable":     (row.get("ExecutableInfo") or row.get("Executable Info") or "").strip(),
            "remote_host":    (row.get("RemoteHost") or row.get("Remote Host") or "").strip(),
            "keywords":       (row.get("Keywords") or "").strip(),
            "record_number":  _safe_int(row.get("RecordNumber", row.get("Record Number", ""))),
            "source_file":    (row.get("SourceFile") or row.get("Source File") or "").strip(),
        }

        # Enrich logon type description for 4624/4625/4648
        if event_id in (4624, 4625, 4648):
            for p in payload_fields:
                if p.startswith("LogonType:"):
                    lt = p.split(":", 1)[-1].strip()
                    entry["logon_type"] = lt
                    entry["logon_type_desc"] = _LOGON_TYPES.get(lt, f"Type {lt}")
                    break

        entries.append(entry)

    return entries


def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Pre-filter events that warrant immediate analyst review.
    Returns subset with 'suspicion_reasons' list added.
    All flags are INFERRED — analyst must verify each independently.
    """
    flagged = []

    for e in entries:
        reasons: list[str] = []
        eid = e["event_id"]
        payload_str = " ".join(e.get("payload_data", [])).lower()
        exe = e.get("executable", "").lower()

        # High-confidence event IDs — always flag
        if eid in _HIGH_CONFIDENCE_IDS:
            label = {
                4104: "PowerShell script block logging — review script content",
                7045: "New service installed — possible persistence",
                1116: "Windows Defender malware detection",
                5001: "Windows Defender real-time protection DISABLED",
                5861: "WMI permanent subscription — possible persistence",
                4648: "Explicit credentials used — possible lateral movement or Pass-the-Hash",
            }.get(eid, f"High-confidence Event ID {eid}")
            reasons.append(label)

        # 4688 process creation — check executable name and cmdline
        if eid == 4688:
            for proc in _SUSPICIOUS_PROCESSES:
                if proc in exe or proc in payload_str:
                    reasons.append(f"Suspicious process created: {e.get('executable', proc)}")
                    break
            for frag in _SUSPICIOUS_CMDLINE:
                if frag.lower() in payload_str:
                    reasons.append(
                        f"Suspicious command-line fragment '{frag}' in process creation event"
                    )
                    # Don't break — multiple fragments can match

        # 4624 logon — flag network logons from unexpected sources
        if eid == 4624:
            lt = e.get("logon_type", "")
            remote = e.get("remote_host", "").lower()
            if lt in ("3", "10") and remote and remote not in ("localhost", "127.0.0.1", "-", ""):
                reasons.append(
                    f"Remote logon (type {lt}: {e.get('logon_type_desc', '')}) "
                    f"from {e.get('remote_host')} — verify if expected"
                )
            # Flag logons from known attacker IP
            if "172.15.1.20" in remote or "172.16.6.12" in remote:
                reasons.append(
                    f"Logon from known IOC IP: {e.get('remote_host')} — CONFIRMED IOC"
                )

        # Any event mentioning known IOC IPs or filenames
        crimson_iocs = ["172.15.1.20", "172.16.6.12", "stun.exe", "pssdnsvc"]
        for ioc in crimson_iocs:
            if ioc in payload_str or ioc in exe:
                reasons.append(f"Known CRIMSON OSPREY IOC referenced: '{ioc}'")
                break

        if reasons:
            flagged_entry = dict(e)
            flagged_entry["suspicion_reasons"] = list(dict.fromkeys(reasons))
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


def _error_result(invocation_id: str, evtx_path: str, error_msg: str) -> dict:
    return {
        "invocation_id":    invocation_id,
        "tool":             "EvtxECmd",
        "evtx_path":        evtx_path,
        "event_ids_filter": [],
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    0,
        "entries_returned": 0,
        "entries_capped":   False,
        "entries":          [],
        "suspicious":       [],
        "event_id_counts":  {},
        "output_dir":       None,
        "duration_ms":      0,
        "error":            error_msg,
        "analyst_note":     None,
    }


def parse_event_logs(
    evtx_path: str,
    event_ids: Optional[list[int]] = None,
    output_dir: Optional[str] = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Parse Windows Event Log files (.evtx) using EvtxECmd and return
    filtered, structured events as typed JSON.

    Args:
        evtx_path:
            Path to either:
            - A directory containing .evtx files (processes all recursively)
              Example: /cases/cr01/evidence/evtx/
            - A single .evtx file
              Example: /cases/cr01/evidence/evtx/Security.evtx
            EvtxECmd handles both.

        event_ids:
            List of Event IDs to include. Uses --inc flag in EvtxECmd.
            If None or empty, uses DEFAULT_EVENT_IDS (the 17 highest-value IDs
            for intrusion investigations).
            Pass event_ids=[] to collect ALL events (warning: very large output).
            Example: [4688, 4624, 4648, 7045, 1116]

        output_dir:
            Where EvtxECmd writes CSV output.
            Defaults to sibling 'evtx_out/' directory.
            Created if it does not exist.

        include_all:
            If False (default), entries capped at 1000 (event logs can be huge).
            Suspicious entries always included in full.
            Set True only for downstream scripts.

    Returns a dict with:
        invocation_id       — UUID (correlate with audit/mcp.jsonl)
        tool                — "EvtxECmd"
        evtx_path           — echoed input
        event_ids_filter    — the Event IDs that were passed to --inc
        run_ts_utc          — when this function ran
        total_entries       — total events parsed
        entries_returned    — count in entries[] (may be capped)
        entries_capped      — True if total > 1000 and include_all=False
        entries             — list of EventEntry dicts sorted by timestamp_utc asc
        suspicious          — pre-flagged subset with suspicion_reasons (INFERRED)
        event_id_counts     — dict of {event_id: count} for quick overview
        output_dir          — where CSV was written
        duration_ms         — wall-clock time
        error               — null on success
        analyst_note        — CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. EvtxECmd does not modify .evtx files.
        Output CSV written to output_dir only.

    Performance note:
        Large event log directories (Security.evtx on busy DCs can be GB+)
        can take 60-120s. Use event_ids filter to reduce parse time.
        The --inc flag is always applied when event_ids are specified.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate input ────────────────────────────────────────────────────────
    evtx = Path(evtx_path)
    if not evtx.exists():
        return _error_result(
            invocation_id, evtx_path,
            f"EVTX path not found: {evtx_path}\n"
            "Extract event logs from the image first:\n"
            "  image_export.py --extension evtx -w /cases/.../evtx/ <image>"
        )

    # ── Resolve event IDs ─────────────────────────────────────────────────────
    ids_to_use = event_ids if event_ids is not None else DEFAULT_EVENT_IDS

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir)
    else:
        base = evtx if evtx.is_dir() else evtx.parent
        out_dir = base.parent / "evtx_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = evtx.stem if not evtx.is_dir() else "evtx"

    # ── Build EvtxECmd command ────────────────────────────────────────────────
    # EvtxECmd flags:
    #   -f   single .evtx file
    #   -d   directory of .evtx files
    #   --inc  comma-separated Event IDs to include (huge performance win)
    #   --csv  output directory
    #   --csvf filename prefix
    #   -q   quiet
    if evtx.is_dir():
        input_flag = f"-d {evtx}"
    else:
        input_flag = f"-f {evtx}"
        prefix = evtx.stem

    inc_flag = ""
    if ids_to_use:
        inc_flag = f"--inc {','.join(str(i) for i in ids_to_use)}"

    cmd = (
        f"{EVTXECMD_BIN} "
        f"{input_flag} "
        f"{inc_flag} "
        f"--csv {out_dir} "
        f"--csvf {prefix}.csv"
    ).strip()

    # ── Run EvtxECmd ──────────────────────────────────────────────────────────
    try:
        result = run_tool(cmd, timeout=300)
        stderr_excerpt = result.stderr[:500] if result.stderr else ""
    except RuntimeError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="EvtxECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, evtx_path, str(exc))
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="EvtxECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, evtx_path, f"Unexpected error: {exc}")

    # ── Find and parse CSV output ─────────────────────────────────────────────
    csv_files = list(out_dir.glob("*.csv"))

    if not csv_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="EvtxECmd",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=0,
            stdout_lines=result.stdout.count("\n"),
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"note": "No CSV output — no matching events or empty log files"},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "EvtxECmd",
            "evtx_path":        str(evtx),
            "event_ids_filter": ids_to_use,
            "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
            "total_entries":    0,
            "entries_returned": 0,
            "entries_capped":   False,
            "entries":          [],
            "suspicious":       [],
            "event_id_counts":  {},
            "output_dir":       str(out_dir),
            "duration_ms":      duration_ms,
            "error":            None,
            "analyst_note": (
                "EvtxECmd produced no output for the requested Event IDs. "
                "Either the logs contain no matching events, the log files are "
                "empty/corrupt, or audit policy was not configured to generate "
                "these events. Absence of 4688 events means process creation "
                "auditing was disabled — document this as a finding."
            ),
        }

    all_entries: list[dict[str, Any]] = []
    for csv_file in csv_files:
        raw = csv_file.read_text(encoding="utf-8-sig", errors="replace")
        all_entries.extend(_parse_evtx_csv(raw))

    # ── Sort by timestamp ascending (chronological timeline) ──────────────────
    all_entries.sort(
        key=lambda e: (e.get("timestamp_utc") or "0000"),
        reverse=False,
    )

    # ── Build event_id_counts summary ─────────────────────────────────────────
    event_id_counts: dict[str, int] = {}
    for e in all_entries:
        key = str(e["event_id"])
        event_id_counts[key] = event_id_counts.get(key, 0) + 1

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(all_entries)

    # ── Cap for context window safety ─────────────────────────────────────────
    # Event logs can have tens of thousands of events — 1000 cap for safety
    CAP = 1000
    total = len(all_entries)
    if not include_all and total > CAP:
        susp_keys = {(e["event_id"], e["record_number"]) for e in suspicious}
        non_susp = [
            e for e in all_entries
            if (e["event_id"], e["record_number"]) not in susp_keys
        ]
        cap = max(0, CAP - len(suspicious))
        entries_out = suspicious + non_susp[:cap]
        # Re-sort merged list chronologically
        entries_out.sort(key=lambda e: (e.get("timestamp_utc") or "0000"))
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="EvtxECmd",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n"),
        stderr_excerpt=stderr_excerpt,
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "evtx_path":        str(evtx),
            "event_ids_filter": ids_to_use,
            "output_dir":       str(out_dir),
            "csv_files":        [str(f) for f in csv_files],
            "suspicious_count": len(suspicious),
            "event_id_counts":  event_id_counts,
            "capped":           (not include_all and total > CAP),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "EvtxECmd",
        "evtx_path":        str(evtx),
        "event_ids_filter": ids_to_use,
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > CAP),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "event_id_counts":  event_id_counts,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note": (
            "Event log entries are CONFIRMED — they are recorded by the Windows kernel "
            "and are difficult to forge without leaving traces. "
            "4688 process creation CONFIRMS a process ran IF command-line auditing was enabled. "
            "4624 logon CONFIRMS authentication occurred. "
            "Absence of expected events (e.g. no 4688) may mean audit policy was disabled "
            "— document this explicitly. "
            "IOC matches in payload_data are CONFIRMED presence; intent is INFERRED."
        ),
    }
