"""
parse_volatility_pslist() — MCP tool wrapping Volatility 3 windows.pslist

Lists running processes from a Windows memory image. Equivalent to
`vol -f <image> windows.pslist`.

Why pslist matters for investigations:
  - Confirms a process WAS running at the time of memory capture
  - Reveals attacker tools, C2 implants, and persistence mechanisms
  - Shows process tree relationships (parent PID → child PID)
  - Identifies injected processes (unusual PPID or image path)
  - Detects process hollowing (mismatched name vs. path)
  - Absence does NOT confirm a process never ran — it may have exited

This is a dedicated wrapper around parse_memory() with the plugin
hardcoded to "windows.pslist" for discoverability. Results are written
as CSV to output_dir so the Tier 2 grounding verifier can search them.

Inference Constraint Level: HIGH
  Memory artifacts CONFIRM process presence at capture time.
  Parent PID / image path anomalies are INFERRED without corroboration.
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
    "Memory artifacts CONFIRM a process WAS RUNNING at the time of capture. "
    "Absence does NOT confirm a process never ran — it may have exited before "
    "capture. PIDs are reused by Windows; correlate by ImageFileName + "
    "CreateTime, not PID alone. Unusual parent-child relationships "
    "(e.g. svchost.exe spawned by cmd.exe) are INFERRED anomalies. "
    "Corroborate process presence with Amcache (for execution) and Prefetch "
    "(for execution count + last run time)."
)

# Suspicious process names commonly associated with attacker activity
_SUSPICIOUS_PROCESSES = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe", "schtasks.exe",
    "net.exe", "net1.exe", "psexec.exe", "psexesvc.exe",
    "mimikatz.exe", "procdump.exe", "wce.exe", "pwdump.exe",
    "ncat.exe", "nc.exe", "plink.exe", "putty.exe", "ssh.exe",
    "whoami.exe", "systeminfo.exe", "tasklist.exe", "ipconfig.exe",
    "nslookup.exe", "ping.exe", "tracert.exe", "arp.exe",
    "route.exe", "netstat.exe", "nbtstat.exe", "sc.exe",
    "reg.exe", "findstr.exe", "vssadmin.exe", "wmic.exe",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flag_suspicious(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag pslist entries that warrant analyst review."""
    suspicious: list[dict[str, Any]] = []
    for rec in records:
        reasons: list[str] = []
        name = (rec.get("ImageFileName") or "").strip().lower()

        # Suspicious process name
        if name in _SUSPICIOUS_PROCESSES:
            reasons.append(
                f"Suspicious process: {rec.get('ImageFileName')} — "
                f"common attacker tool or living-off-the-land binary"
            )

        # Blank / missing image name (process hollowing / injection artifact)
        if not name:
            reasons.append("Process with blank ImageFileName — possible injection")

        if reasons:
            flagged = dict(rec)
            flagged["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged["confidence"] = "INFERRED"
            suspicious.append(flagged)

    return suspicious


def _write_csv(records: list[dict[str, Any]], out_dir: Path) -> list[Path]:
    """Write parsed records as CSV to out_dir. Returns list of CSV paths."""
    if not records:
        return []
    csv_path = out_dir / "pslist.csv"
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
        "tool":             "Volatility3-windows.pslist",
        "plugin":           "windows.pslist",
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

def parse_volatility_pslist(
    image_path: str,
    output_dir: Optional[str] = None,
    timeout_sec: int = 600,
    use_cache: bool = True,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    Run Volatility 3 windows.pslist plugin against a memory image and return
    structured process listing as typed JSON.

    This is a dedicated wrapper around parse_memory() with plugin hardcoded
    to "windows.pslist". Results are written as CSV to output_dir for
    grounding verification.

    Args:
        image_path:
            Absolute path to the memory image (.img / .raw / .mem / .vmem).
            Symlinks are rejected.
            Example: /cases/cr01/evidence/memory.img

        output_dir:
            Where parsed results are written as CSV.
            Defaults to analysis/vol_pslist_out/ under CASEFILE_CASE_DIR.

        timeout_sec:
            Subprocess timeout in seconds. Default 600.

        use_cache:
            If True (default), reuse cached Volatility results for the same
            (sha256, plugin) pair.

    Returns a dict with:
        invocation_id     — UUID (correlate with audit/mcp.jsonl)
        tool              — "Volatility3-windows.pslist"
        plugin            — "windows.pslist"
        image_path        — echoed input
        image_sha256      — SHA-256 hash of the memory image
        run_ts_utc        — when this ran
        total_entries     — total processes found
        entries_returned  — count in entries[] (may be capped)
        entries_capped    — True if capped
        entries           — list of process entry dicts
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
            tool="Volatility3-windows.pslist",
            invocation_id=invocation_id,
            cmd=f"parse_volatility_pslist(image_path={image_path!r})",
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
        out_dir = base / "analysis" / "vol_pslist_out" / invocation_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Run parse_memory with plugin hardcoded ────────────────────────────────
    try:
        mem_result = parse_memory(
            image_path=image_path,
            plugin="windows.pslist",
            timeout_sec=timeout_sec,
            use_cache=use_cache,
        )
    except MemoryToolError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        # parse_memory already logs to audit; log our wrapper context
        audit_log(
            tool="Volatility3-windows.pslist",
            invocation_id=invocation_id,
            cmd=f"parse_memory(image_path={image_path!r}, plugin='windows.pslist')",
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
            tool="Volatility3-windows.pslist",
            invocation_id=invocation_id,
            cmd=f"parse_memory(image_path={image_path!r}, plugin='windows.pslist')",
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
        # Keep all suspicious + most recent non-suspicious
        susp_names = {s.get("ImageFileName", "") for s in suspicious}
        non_susp = [r for r in records
                     if r.get("ImageFileName", "") not in susp_names]
        cap = max(0, _DEFAULT_CAP - len(suspicious))
        entries_out = suspicious + non_susp[:cap]
    else:
        entries_out = records

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log(
        tool="Volatility3-windows.pslist",
        invocation_id=invocation_id,
        cmd=f"parse_memory(image_path={image_path!r}, plugin='windows.pslist')",
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
        "tool":             "Volatility3-windows.pslist",
        "plugin":           "windows.pslist",
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
