"""
parse_volatility_netscan() — MCP tool wrapping Volatility 3 windows.netscan

Scans for network connections, sockets, and listeners from a Windows memory
image. Equivalent to `vol -f <image> windows.netscan`.

Why netscan matters for investigations:
  - Reveals active C2 connections at the time of memory capture
  - Shows listening backdoors (e.g. netcat, Metasploit Meterpreter)
  - Identifies lateral movement via SMB (port 445), RDP (3389), WinRM (5985/5986)
  - Detects data exfiltration (large outbound connections to unknown IPs)
  - Correlates network connections to specific process PIDs
  - CLOSED/CLOSE_WAIT states show historical connections
  - ESTABLISHED state shows live connections at capture time

This is a dedicated wrapper around parse_memory() with the plugin
hardcoded to "windows.netscan" for discoverability. Results are written
as CSV to output_dir so the Tier 2 grounding verifier can search them.

Inference Constraint Level: HIGH
  ESTABLISHED connections CONFIRM network activity at capture time.
  CLOSED/CLOSE_WAIT connections are historical — INFERRED without
  event log (EID 5156) corroboration. Foreign IPs are CONFIRMED;
  attribution of those IPs to specific threat actors is INFERRED.
"""

from __future__ import annotations

import csv
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_server.tools._shared import audit_log, PathConfinementError, _enforce_case_root
from mcp_server.tools.memory import MemoryToolError, parse_memory

_DEFAULT_CAP = 500

_ANALYST_NOTE = (
    "Network connections are CONFIRMED — they are extracted from the kernel's "
    "network structures in the memory image. ESTABLISHED state confirms an "
    "active connection at capture time. LISTENING state confirms a service "
    "was accepting connections. CLOSED and CLOSE_WAIT states are historical "
    "— the connection existed but was no longer active at capture time. "
    "Foreign IP addresses are CONFIRMED; attribution to specific threat "
    "actors or C2 infrastructure is INFERRED without threat intelligence "
    "corroboration. Corroborate with firewall logs and event logs (EID 5156) "
    "for connection timeline."
)

# Common attacker ports
_SUSPICIOUS_PORTS = frozenset({
    4444, 4443, 5555, 6666, 7777, 8080, 8443, 8888, 9000, 9001, 9002,
    31337, 12345, 23456, 27015,
})

# Common legitimate destination ports (filtered from suspicious flag)
_BENIGN_PORTS = frozenset({
    80, 443, 53, 445, 135, 139, 389, 636, 3389, 5985, 5986, 9389,
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private_ipv4(addr: str) -> bool:
    """Return True if *addr* is an RFC 1918 private IPv4 address."""
    if not addr:
        return False
    if addr.startswith("10.") or addr.startswith("192.168."):
        return True
    if addr.startswith("172."):
        parts = addr.split(".")
        try:
            second = int(parts[1])
        except (IndexError, ValueError):
            return False
        return 16 <= second <= 31
    return False


def _flag_suspicious(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag netscan entries that warrant analyst review."""
    suspicious: list[dict[str, Any]] = []
    for rec in records:
        reasons: list[str] = []
        local_port = _safe_int(rec.get("LocalPort", rec.get("Local Port", "")))
        foreign_port = _safe_int(rec.get("ForeignPort", rec.get("Foreign Port", "")))
        state = (rec.get("State", rec.get("Status", "")).strip().upper()
                 if isinstance(rec.get("State", rec.get("Status", "")), str)
                 else "")
        owner = (rec.get("Owner", rec.get("ImageFileName", "")).strip().lower()
                 if isinstance(rec.get("Owner", rec.get("ImageFileName", "")), str)
                 else "")
        foreign_addr = (rec.get("ForeignAddr", rec.get("ForeignAddress", "")).strip()
                        if isinstance(rec.get("ForeignAddr", rec.get("ForeignAddress", "")), str)
                        else "")

        # Listening on suspicious port
        if "LISTEN" in state and local_port in _SUSPICIOUS_PORTS:
            reasons.append(
                f"Listening on suspicious port {local_port} — possible backdoor"
            )

        # Outbound connection to suspicious port
        if foreign_port in _SUSPICIOUS_PORTS and foreign_port not in _BENIGN_PORTS:
            reasons.append(
                f"Connection to suspicious port {foreign_port} "
                f"({foreign_addr}) — possible C2"
            )

        # Listening service from unusual process
        if "LISTEN" in state and owner not in ("", "system", "svchost.exe",
                                                "lsass.exe", "services.exe",
                                                "spoolsv.exe", "wininit.exe"):
            reasons.append(
                f"Process '{rec.get('Owner', rec.get('ImageFileName', ''))}' "
                f"has a listening socket — verify if expected service"
            )

        # Non-RFC1918 foreign address (external connection)
        if foreign_addr and state == "ESTABLISHED":
            if (not _is_private_ipv4(foreign_addr) and
                foreign_addr not in ("0.0.0.0", "127.0.0.1", "::1", "::")):
                reasons.append(
                    f"Established connection to external IP {foreign_addr}:{foreign_port}"
                )

        # CLOSED connections — historical activity
        if "CLOSED" in state or "CLOSE_WAIT" in state:
            if foreign_addr and foreign_addr not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                reasons.append(
                    f"Historical connection to {foreign_addr}:{foreign_port} "
                    f"({state}) — review for past C2 or lateral movement"
                )

        if reasons:
            flagged = dict(rec)
            flagged["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged["confidence"] = "INFERRED"
            suspicious.append(flagged)

    return suspicious


def _safe_int(val: Any) -> Optional[int]:
    try:
        return int(str(val).strip())
    except (ValueError, AttributeError, TypeError):
        return None


def _write_csv(records: list[dict[str, Any]], out_dir: Path) -> list[Path]:
    """Write parsed records as CSV to out_dir. Returns list of CSV paths."""
    if not records:
        return []
    csv_path = out_dir / "netscan.csv"
    headers = list(records[0].keys())
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        writer.writerows(records)
    return [csv_path]


def _error_result(invocation_id: str, image_path: str, error_msg: str,
                  duration_ms: int = 0) -> dict[str, Any]:
    return {
        "invocation_id":    invocation_id,
        "tool":             "Volatility3-windows.netscan",
        "plugin":           "windows.netscan",
        "image_path":       image_path,
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

def parse_volatility_netscan(
    image_path: str,
    output_dir: Optional[str] = None,
    timeout_sec: int = 600,
    use_cache: bool = True,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Run Volatility 3 windows.netscan plugin against a memory image and return
    structured network connection evidence as typed JSON.

    This is a dedicated wrapper around parse_memory() with plugin hardcoded
    to "windows.netscan". Results are written as CSV to output_dir for
    grounding verification.

    Args:
        image_path:
            Absolute path to the memory image (.img / .raw / .mem / .vmem).
            Symlinks are rejected.
            Example: /cases/cr01/evidence/memory.img

        output_dir:
            Where parsed results are written as CSV.
            Defaults to analysis/vol_netscan_out/ under CASEFILE_CASE_DIR.

        timeout_sec:
            Subprocess timeout in seconds. Default 600.
            Netscan can take 2+ minutes on large Server images.

        use_cache:
            If True (default), reuse cached Volatility results for the same
            (sha256, plugin) pair.

    Returns a dict with:
        invocation_id     — UUID (correlate with audit/mcp.jsonl)
        tool              — "Volatility3-windows.netscan"
        plugin            — "windows.netscan"
        image_path        — echoed input
        image_sha256      — SHA-256 hash of the memory image
        run_ts_utc        — when this ran
        total_entries     — total network artifacts found
        entries_returned  — count in entries[] (may be capped)
        entries_capped    — True if capped
        entries           — list of network connection dicts
        suspicious        — pre-flagged entries with suspicion_reasons
        output_dir        — where CSV was written
        duration_ms       — wall-clock time
        cached            — True if Volatility results came from cache
        error             — null on success
        analyst_note      — CONFIRMED/INFERRED reminder

    Evidence integrity:
        READ-ONLY. Volatility does not modify the memory image.
        Output CSV written to output_dir only.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()

    # ── Validate image path exists ────────────────────────────────────────────
    img = Path(image_path).expanduser().resolve()
    try:
        _enforce_case_root(img)
    except PathConfinementError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        return _error_result(invocation_id, image_path, str(exc), duration_ms)

    if not img.exists():
        duration_ms = int((time.monotonic() - t_start) * 1000)
        err = f"Memory image not found: {image_path}"
        audit_log(
            tool="Volatility3-windows.netscan",
            invocation_id=invocation_id,
            cmd=f"parse_volatility_netscan(image_path={image_path!r})",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=err,
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, image_path, err, duration_ms)

    # ── Resolve output directory ──────────────────────────────────────────────
    if output_dir:
        out_dir = Path(output_dir).expanduser().resolve()
        try:
            _enforce_case_root(out_dir)
        except PathConfinementError as exc:
            duration_ms = int((time.monotonic() - t_start) * 1000)
            return _error_result(invocation_id, image_path, str(exc), duration_ms)
    else:
        root_var = os.environ.get("CASEFILE_CASE_ROOT")
        base = Path(root_var) if root_var else (Path.home() / "cases" / "active")
        out_dir = base / "analysis" / "vol_netscan_out" / invocation_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Run parse_memory with plugin hardcoded ────────────────────────────────
    try:
        mem_result = parse_memory(
            image_path=image_path,
            plugin="windows.netscan",
            timeout_sec=timeout_sec,
            use_cache=use_cache,
        )
    except MemoryToolError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="Volatility3-windows.netscan",
            invocation_id=invocation_id,
            cmd=f"parse_memory(image_path={image_path!r}, plugin='windows.netscan')",
            returncode=1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, image_path, str(exc), duration_ms)
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="Volatility3-windows.netscan",
            invocation_id=invocation_id,
            cmd=f"parse_memory(image_path={image_path!r}, plugin='windows.netscan')",
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(exc)[:500],
            parsed_record_count=0,
            duration_ms=duration_ms,
        )
        return _error_result(invocation_id, image_path,
                             f"Unexpected error: {exc}", duration_ms)

    if isinstance(mem_result, dict) and mem_result.get("error"):
        error_msg = mem_result["error"]
        duration_ms = int((time.monotonic() - t_start) * 1000)
        return _error_result(invocation_id, image_path, error_msg, duration_ms)

    records = mem_result.get("records", [])

    # ── Write CSV output for grounding ────────────────────────────────────────
    csv_files = _write_csv(records, out_dir)

    # ── Flag suspicious entries ───────────────────────────────────────────────
    suspicious = _flag_suspicious(records)

    # ── Cap for context window safety ─────────────────────────────────────────
    total = len(records)
    if not include_all and total > _DEFAULT_CAP:
        susp_keys = {
            (s.get("ForeignAddr", ""), s.get("ForeignPort", ""),
             s.get("LocalPort", ""), s.get("Owner", ""))
            for s in suspicious
        }
        non_susp = [
            r for r in records
            if (r.get("ForeignAddr", ""), r.get("ForeignPort", ""),
                r.get("LocalPort", ""), r.get("Owner", "")) not in susp_keys
        ]
        cap = max(0, _DEFAULT_CAP - len(suspicious))
        entries_out = suspicious + non_susp[:cap]
    else:
        entries_out = records

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="Volatility3-windows.netscan",
        invocation_id=invocation_id,
        cmd=f"parse_memory(image_path={image_path!r}, plugin='windows.netscan')",
        returncode=0,
        stdout_lines=total,
        stderr_excerpt="",
        parsed_record_count=total,
        duration_ms=duration_ms,
        extra={
            "image_path":       str(img),
            "output_dir":       str(out_dir),
            "csv_files":        [str(f) for f in csv_files],
            "suspicious_count": len(suspicious),
            "cached":           mem_result.get("cached", False),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "Volatility3-windows.netscan",
        "plugin":           "windows.netscan",
        "image_path":       str(img),
        "image_sha256":     mem_result.get("image_sha256", ""),
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > _DEFAULT_CAP),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "output_dir":       str(out_dir),
        "duration_ms":      duration_ms,
        "cached":           mem_result.get("cached", False),
        "error":            None,
        "analyst_note":     _ANALYST_NOTE,
    }
