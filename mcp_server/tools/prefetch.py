r"""
parse_prefetch() — MCP tool using pyscca (libscca) for Linux-native Prefetch parsing

Bug #7 fix (April 29 2026): PECmd.dll refuses MAM-compressed Prefetch on Linux/WSL2
("Non-Windows platforms not supported due to the need to load decompression
specific Windows libraries"). Replaced with pyscca (libscca) which handles
all Prefetch format versions (17/23/26/30) natively on Linux.
pyscca is pre-installed on SIFT: apt package libscca-python3.

Inference Constraint Level: HIGH
  pyscca output is fully parsed server-side. LLM receives typed fields only.

Return schema is identical to PECmd version — all callers unchanged.
"""

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import re
try:
    import pyscca
except ImportError:  # not available outside SIFT
    pyscca = None

from mcp_server.tools._shared import audit_log

_SUSPICIOUS_PATHS = [
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\recycle",
    "\\$recycle",
    "\\downloads\\",
]

# High-confidence staging paths — almost never legitimate
_HIGH_CONFIDENCE_PATHS = [
    "\\windows\\temp\\perfmon\\",
    "\\windows\\temp\\perfmon\\",
]

# Volume device path prefix — filter out before suspicious path matching
# pyscca returns paths as \VOLUME{guid}\... which causes false positives
# against \programdata\ and \users\ fragments
_VOLUME_PREFIX_RE = __import__("re").compile(
    r"^\\?volume\{[0-9a-f\-]+\}", __import__("re").IGNORECASE
)

def _strip_volume_prefix(path: str) -> str:
    """Strip \VOLUME{guid} prefix so path matching works correctly."""
    return _VOLUME_PREFIX_RE.sub("", path)

_LOLBAS = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "msiexec.exe", "wscript.exe", "cscript.exe", "powershell.exe",
    "cmd.exe", "bitsadmin.exe", "wmic.exe", "net.exe", "net1.exe",
    "schtasks.exe", "at.exe", "psexec.exe", "psexesvc.exe",
}


def _dt_to_iso(dt: Any) -> Optional[str]:
    """Convert pyscca datetime object to ISO-8601 UTC string."""
    if dt is None:
        return None
    try:
        s = str(dt).strip()
        if not s or s.startswith("0001") or s.startswith("1601"):
            return None
        s = s.replace(" ", "T")
        if not s.endswith("Z") and "+" not in s:
            s += "Z"
        return s
    except Exception:
        return None


def _parse_pf_file(pf_path: Path) -> Optional[dict[str, Any]]:
    """Parse a single .pf file with pyscca. Returns typed dict or None."""
    try:
        scca = pyscca.open(str(pf_path))
    except Exception:
        return None

    try:
        exe_name = scca.executable_filename or pf_path.stem
        run_count = scca.run_count or 0

        last_run_utc = None
        previous_run_times = []
        for i in range(8):
            try:
                iso = _dt_to_iso(scca.get_last_run_time(i))
                if iso:
                    if last_run_utc is None:
                        last_run_utc = iso
                    else:
                        previous_run_times.append(iso)
            except Exception:
                break

        files_loaded = []
        try:
            for i in range(scca.number_of_file_metrics_entries):
                fn = scca.get_file_metrics_entry(i).filename
                if fn:
                    files_loaded.append(fn)
        except Exception:
            pass

        full_path = ""
        volume_name = ""
        volume_serial = ""
        volume_created = ""
        try:
            if scca.number_of_volumes > 0:
                vol = scca.get_volume_information(0)
                volume_name = vol.device_path or ""
                volume_serial = format(vol.serial_number, "08X") if vol.serial_number else ""
                volume_created = _dt_to_iso(vol.get_creation_time()) or ""
            exe_lower = exe_name.lower()
            for f in files_loaded:
                if f.lower().endswith(exe_lower):
                    full_path = f
                    break
            if not full_path and files_loaded:
                full_path = files_loaded[0]
        except Exception:
            pass

        directories = []
        try:
            for i in range(scca.number_of_directory_strings):
                d = scca.get_directory_string(i)
                if d:
                    directories.append(d)
        except Exception:
            pass

        return {
            "executable_name":        exe_name,
            "full_path":              full_path,
            "source_file":            pf_path.name,
            "run_count":              run_count,
            "last_run_utc":           last_run_utc,
            "previous_run_times":     previous_run_times,
            "files_loaded":           files_loaded,
            "files_loaded_count":     len(files_loaded),
            "directories_referenced": directories,
            "volume_name":            volume_name,
            "volume_serial":          volume_serial,
            "volume_created":         volume_created,
        }
    except Exception:
        return None
    finally:
        try:
            scca.close()
        except Exception:
            pass


_VOLUME_RE = re.compile(r"^\\?volume\{[^}]+\}", re.IGNORECASE)

def _strip_vol(path: str) -> str:
    """Strip \\VOLUME{guid} device prefix so path matching works correctly.
    pyscca returns paths as \\VOLUME{guid}\\... which causes false positives."""
    return _VOLUME_RE.sub("", path).lower()

def _flag_suspicious(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag entries warranting analyst review. All flags are INFERRED."""
    flagged = []
    for e in entries:
        reasons: list[str] = []
        name_lower = e["executable_name"].lower()
        path_lower = _strip_vol(e["full_path"])

        for frag in _SUSPICIOUS_PATHS:
            if frag in path_lower:
                reasons.append(f"Executed from suspicious path: {e['full_path']}")
                break

        if name_lower in _LOLBAS:
            reasons.append(
                f"LOLBAS / dual-use binary: {e['executable_name']} "
                f"(run count: {e['run_count']}, last run: {e['last_run_utc']})"
            )

        rc = e.get("run_count") or 0
        if rc > 20 and any(frag in path_lower for frag in _SUSPICIOUS_PATHS):
            reasons.append(
                f"High run count ({rc}) from suspicious path — possible persistence loop"
            )

        system_names = {
            "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
            "services.exe", "smss.exe", "wininit.exe",
        }
        if name_lower in system_names and "\\system32\\" not in path_lower:
            reasons.append(
                f"System binary name '{e['executable_name']}' ran from non-System32 path — "
                f"possible masquerading: {e['full_path']}"
            )

        for f in e.get("files_loaded", []):
            f_lower = _strip_vol(f)
            for frag in _SUSPICIOUS_PATHS:
                if frag in f_lower:
                    reasons.append(
                        f"Loaded file from suspicious path during execution: {f}"
                    )
                    break

        if reasons:
            flagged_entry = dict(e)
            flagged_entry["suspicion_reasons"] = list(dict.fromkeys(reasons))
            flagged.append(flagged_entry)

    return flagged


def _norm_ts(raw: Any) -> Optional[str]:
    """Compat shim used by tests."""
    if raw is None:
        return None
    if isinstance(raw, str) and raw.strip() in ("", "0", "N/A"):
        return None
    return _dt_to_iso(raw)


def _safe_int(val: str) -> Optional[int]:
    """Compat shim — used by tests."""
    try:
        return int(str(val).strip())
    except (ValueError, AttributeError):
        return None


def _parse_prefetch_csv(csv_text: str) -> list[dict[str, Any]]:
    """
    Compat shim — used by tests that feed CSV fixtures.
    Parses PECmd CSV format so existing test fixtures still work.
    """
    import csv, io
    entries = []
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        if not row:
            continue
        exe = row.get("ExecutableName", "").strip()
        if not exe:
            continue
        files_raw = row.get("FilesLoaded", "") or ""
        files_loaded = [f.strip() for f in files_raw.split("|") if f.strip()]
        prev_times = []
        for col in ("RunTime1", "RunTime2", "RunTime3", "RunTime4",
                    "RunTime5", "RunTime6", "RunTime7"):
            v = _norm_ts(row.get(col, ""))
            if v:
                prev_times.append(v)
        entries.append({
            "executable_name":        exe,
            "full_path":              row.get("SourceFilePath", "").strip(),
            "source_file":            row.get("SourceFileName", "").strip(),
            "run_count":              _safe_int(row.get("RunCount", "")) or 0,
            "last_run_utc":           _norm_ts(row.get("LastRun", "")),
            "previous_run_times":     prev_times,
            "files_loaded":           files_loaded,
            "files_loaded_count":     len(files_loaded),
            "directories_referenced": [d.strip() for d in
                                       (row.get("Directories", "") or "").split("|")
                                       if d.strip()],
            "volume_name":            row.get("VolumeName", "").strip(),
            "volume_serial":          row.get("VolumeSerial", "").strip(),
            "volume_created":         _norm_ts(row.get("VolumeCreated", "")),
        })
    return entries


def _error_result(invocation_id: str, prefetch_path: str, error_msg: str) -> dict:
    return {
        "invocation_id":    invocation_id,
        "tool":             "pyscca",
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
    Parse Prefetch files (.pf) using pyscca (libscca).

    Args:
        prefetch_path: Directory of .pf files OR single .pf file path.
        output_dir:    Ignored (API compat with PECmd version).
        include_all:   If False, cap entries at 500 to protect context window.

    Returns structured dict — schema identical to PECmd version.
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()
    pf_path = Path(prefetch_path)

    if not pf_path.exists():
        return _error_result(invocation_id, prefetch_path,
                             f"Path not found: {prefetch_path}")

    if pf_path.is_dir():
        pf_files = sorted(pf_path.glob("*.pf"))
        if not pf_files:
            pf_files = sorted(pf_path.glob("*.PF"))
    elif pf_path.is_file() and pf_path.suffix.lower() == ".pf":
        pf_files = [pf_path]
    else:
        return _error_result(invocation_id, prefetch_path,
                             f"Not a .pf file or directory: {prefetch_path}")

    if not pf_files:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="pyscca", invocation_id=invocation_id,
            cmd=f"pyscca({prefetch_path})", returncode=0,
            stdout_lines=0, stderr_excerpt="", parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"prefetch_path": str(pf_path), "pf_files": 0},
        )
        return {
            "invocation_id":    invocation_id,
            "tool":             "pyscca",
            "prefetch_path":    prefetch_path,
            "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
            "total_entries":    0,
            "entries_returned": 0,
            "entries_capped":   False,
            "entries":          [],
            "suspicious":       [],
            "output_dir":       None,
            "duration_ms":      duration_ms,
            "error":            None,
            "analyst_note": (
                "PECmd produced no output. Prefetch may be disabled (common on "
                "Windows Server or some SSD configurations) or the folder is empty. "
                "Document absence of Prefetch as a finding — it is not neutral."
            ),
        }

    all_entries: list[dict[str, Any]] = []
    parse_errors = 0
    for pf_file in pf_files:
        entry = _parse_pf_file(pf_file)
        if entry:
            all_entries.append(entry)
        else:
            parse_errors += 1

    all_entries.sort(key=lambda e: (e.get("last_run_utc") or "0000"), reverse=True)
    suspicious = _flag_suspicious(all_entries)

    total = len(all_entries)
    if not include_all and total > 500:
        susp_keys = {(e["executable_name"], e["source_file"]) for e in suspicious}
        non_susp = [e for e in all_entries
                    if (e["executable_name"], e["source_file"]) not in susp_keys]
        entries_out = suspicious + non_susp[:max(0, 500 - len(suspicious))]
    else:
        entries_out = all_entries

    duration_ms = int((time.monotonic() - t_start) * 1000)

    audit_log(
        tool="pyscca", invocation_id=invocation_id,
        cmd=f"pyscca({prefetch_path}) × {len(pf_files)}",
        returncode=0, stdout_lines=total,
        stderr_excerpt=f"{parse_errors} files failed to parse" if parse_errors else "",
        parsed_record_count=total, duration_ms=duration_ms,
        extra={
            "prefetch_path":    str(pf_path),
            "pf_files_found":   len(pf_files),
            "parse_errors":     parse_errors,
            "suspicious_count": len(suspicious),
            "capped":           (not include_all and total > 500),
        },
    )

    return {
        "invocation_id":    invocation_id,
        "tool":             "pyscca",
        "prefetch_path":    prefetch_path,
        "run_ts_utc":       datetime.now(timezone.utc).isoformat(),
        "total_entries":    total,
        "entries_returned": len(entries_out),
        "entries_capped":   (not include_all and total > 500),
        "entries":          entries_out,
        "suspicious":       suspicious,
        "output_dir":       None,
        "duration_ms":      duration_ms,
        "error":            None,
        "analyst_note": (
            "Prefetch CONFIRMS execution — run_count and last_run_utc are CONFIRMED. "
            f"Parsed {total} entries from {len(pf_files)} .pf files via pyscca/libscca "
            f"({parse_errors} parse errors). "
            "What the execution DID is INFERRED from files_loaded. "
            "Suspicious flags require analyst verification."
        ),
    }
