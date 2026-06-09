"""
timeline_contradiction.py — Disk-vs-Memory Timeline Contradiction Detector

This module implements Starter Idea #2 from the SANS Find Evil! brief:

  "Given a disk image and a memory capture from the same system, build an
   agent that cross-references findings between the two sources and flags
   discrepancies."

How it works:
  correlate_evidence() already calls four parsers and returns per-process
  verdict + detect_contradictions(). This module adds a *timeline-level*
  cross-source check: it takes a list of running memory processes and the
  full parsed disk artifacts, then flags cases where disk and memory
  tell contradictory stories.

Contradiction types detected:
  T1: PROCESS_MISSING_FROM_DISK   — running in memory, zero disk artifacts
      (fileless / process injection — T1055)
  T2: TIMESTAMP_PREDATES_INSTALL  — process last-run (Prefetch) predates
      when MFT says the binary was created (timestomping cover-up — T1070.006)
  T4: PATH_MISMATCH               — Amcache/Prefetch records one directory,
      MFT shows the same filename in a different path (T1574.001 sideloading)
  T5: DELETED_BUT_RUNNING         — MFT marks file as deleted (InUse=False)
      but memory shows it still running (T1036 masquerading / process hollowing)
  T6: USN_DELETED_WHILE_RUNNING   — USN Journal shows DELETE_FILE on the
      binary's path while it still appears in the memory pslist (anti-forensics
      in progress or timing gap — T1070.004)

Note: T3 (PREFETCH_LASTRUN_VS_MEMORY_PID_MISMATCH) is planned but not yet
implemented — it requires correlating Prefetch last-run timestamps with
process start times from multiple Volatility plugins (windows.psscan +
windows.cmdline), which needs further integration work.

MFT field names:
  This module consumes the NORMALIZED dict produced by mft.py, NOT raw CSV
  columns.  The parser normalizes FileName→"filename", InUse→"is_deleted",
  Created0x10→"si_created_utc", Created0x30→"fn_created_utc", and constructs
  "full_path" from ParentPath+FileName.  These are the same keys used by
  correlation.py and the rest of the codebase.

Usage:
  from mcp_server.tools.timeline_contradiction import detect_timeline_contradictions

  contradictions = detect_timeline_contradictions(
      memory_pslist=result_parse_memory["records"],      # from parse_memory()
      prefetch_entries=result_prefetch["entries"],        # from parse_prefetch()
      amcache_entries=result_amcache["entries"],          # from parse_amcache()
      mft_entries=result_mft["entries"],                  # from parse_mft()
      usn_entries=result_usn.get("deleted", []),         # from parse_usn_journal()
  )

  # Each contradiction dict:
  #   type          — T1..T6 code
  #   process_name  — the subject
  #   sources       — which sources are in conflict
  #   severity      — CRITICAL / HIGH / MEDIUM
  #   implication   — plain-English analyst note
  #   mitre         — ATT&CK technique
  #   details       — per-type evidence specifics
"""

from __future__ import annotations

import ntpath
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from mcp_server.tools._shared import canonical_dir


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _norm_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse a forensic timestamp string to aware UTC datetime or None.

    Handles the formats emitted by MFTECmd, AmcacheParser, and pyscca/PECmd
    (ISO-8601, M/D/Y space-separated, with or without fractional seconds).
    """
    if not raw:
        return None
    raw = raw.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Fallback: try ISO-8601 with Z / offset suffix
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _fname_lower(entry: dict, key: str = "name") -> str:
    return (entry.get(key) or entry.get("executable_name") or entry.get("ImageFileName") or "").lower()


def _extract_basename(path_str: Optional[str]) -> str:
    """Return lowercased filename from a Windows path string."""
    if not path_str:
        return ""
    return ntpath.basename(path_str).lower()


# ---------------------------------------------------------------------------
# Per-contradiction detectors (pure functions — no I/O, no LLM)
# ---------------------------------------------------------------------------

def _t1_process_missing_from_disk(
    memory_pslist: list[dict],
    prefetch_entries: list[dict],
    amcache_entries: list[dict],
    mft_entries: list[dict],
) -> list[dict]:
    """T1: Running in memory but absent from ALL disk artifacts."""
    results = []

    pf_names = {_fname_lower(e) for e in prefetch_entries}
    ac_names = {_fname_lower(e) for e in amcache_entries}
    mft_names = {_fname_lower(e, "filename") for e in mft_entries}
    all_disk_names = pf_names | ac_names | mft_names

    for proc in memory_pslist:
        pname = (proc.get("ImageFileName") or "").lower()
        if not pname:
            continue
        # Allow 14-char kernel truncation: symmetric prefix match
        # (memory name may be truncated OR disk record may be truncated).
        # Only activate when the name is exactly 14 chars — short names
        # like "cmd" would otherwise match "cmds.exe" or "cmd.exe",
        # producing false fileless-process alerts.
        kernel_trunc = len(pname) == 14
        on_disk = (
            pname in all_disk_names or
            (kernel_trunc and any(
                pname.startswith(d) or d.startswith(pname)
                for d in all_disk_names))
        )
        if not on_disk:
            results.append({
                "type": "T1_PROCESS_MISSING_FROM_DISK",
                "process_name": proc.get("ImageFileName"),
                "pid": proc.get("PID"),
                "ppid": proc.get("PPID"),
                "sources": ["memory"],
                "severity": "HIGH",
                "mitre": "T1055",
                "implication": (
                    f"Process '{proc.get('ImageFileName')}' (PID {proc.get('PID')}) "
                    f"is running in memory with NO corresponding Amcache, Prefetch, "
                    f"or MFT record. Possible fileless malware, process injection, "
                    f"or evidence of anti-forensic disk wiping."
                ),
                "details": {
                    "memory_pid": str(proc.get("PID", "")),
                    "memory_ppid": str(proc.get("PPID", "")),
                    "checked_sources": ["prefetch", "amcache", "mft"],
                },
            })

    return results


def _t2_timestamp_predates_install(
    prefetch_entries: list[dict],
    mft_entries: list[dict],
) -> list[dict]:
    """T2: Prefetch last-run predates MFT creation — timestomping cover-up.

    Matches Prefetch→MFT by (filename, directory) to avoid false positives
    when the same executable name appears in multiple directories (e.g. a
    system binary vs a malware copy in Temp).  Falls back to filename-only
    when directory information is unavailable from either source.
    """
    results = []

    # Build MFT lookup: (filename, dir) -> list of matching entries
    mft_by_name_path: dict[tuple[str, str], list[dict]] = defaultdict(list)
    mft_by_name_fallback: dict[str, list[dict]] = defaultdict(list)
    for e in mft_entries:
        name = (e.get("filename") or "").lower()
        if not name or e.get("is_deleted"):
            continue
        fp = (e.get("full_path") or "")
        dir_key = canonical_dir(fp) if fp else ""
        mft_by_name_path[(name, dir_key)].append(e)
        mft_by_name_fallback[name].append(e)

    for pf in prefetch_entries:
        pf_name = _fname_lower(pf)
        last_run = _norm_ts(pf.get("last_run_utc"))
        if not pf_name or not last_run:
            continue

        # Extract directory from Prefetch full_path (executable location)
        # for precise matching.  When full_path is absent, attempt to recover
        # the path from source_file (the .pf filename).  PECmd stores the
        # full executable path in SourceFileName; pyscca uses just the .pf
        # basename (e.g. "SVCHOST.EXE-A3F4B2C1.pf").  Strip the .pf extension
        # and hex hash suffix so canonical_dir() can extract a usable directory.
        # Prefer full_path (executable location from Prefetch internals).
        # Fall back to source_file (.pf filename) when full_path is absent
        # (common with pyscca/libscca).  canonical_dir() strips drive letters
        # and device prefixes; when the fallback is just a bare filename like
        # "SVCHOST.EXE-A3F4B2C1.pf" it will return "" (no directory), so the
        # caller falls through to filename-only matching — which is the
        # correct behaviour.
        src = pf.get("full_path") or pf.get("source_file") or ""
        src_dir = canonical_dir(src) if src else ""

        # Prefer directory-aware match; fall back to filename-only
        candidates = mft_by_name_path.get((pf_name, src_dir), [])
        used_fallback = not candidates
        if used_fallback:
            candidates = mft_by_name_fallback.get(pf_name, [])

        for mft_entry in candidates:
            mft_created = _norm_ts(mft_entry.get("si_created_utc"))
            if not mft_created:
                continue

            # Process ran before file was "created" on disk
            if last_run < mft_created:
                delta_s = int((mft_created - last_run).total_seconds())
                if used_fallback:
                    implication = (
                        f"Prefetch shows '{pf_name}' last ran at {pf.get('last_run_utc')}, "
                        f"but MFT $SI says the file was created at "
                        f"{mft_entry.get('si_created_utc')} — "
                        f"{delta_s}s LATER. The file cannot have run before it was "
                        f"created. Directory information unavailable; match by "
                        f"filename only — the MFT entry may belong to a different "
                        f"binary with the same name (e.g. a system binary vs a "
                        f"malware copy). Corroborate with full-path evidence before "
                        f"concluding timestomping (T1070.006)."
                    )
                    severity = "HIGH"
                else:
                    implication = (
                        f"Prefetch shows '{pf_name}' last ran at {pf.get('last_run_utc')}, "
                        f"but MFT $SI says the file was created at "
                        f"{mft_entry.get('si_created_utc')} — "
                        f"{delta_s}s LATER. The file cannot have run before it was "
                        f"created. This is strong evidence of timestomping (T1070.006): "
                        f"the attacker backdated $SI after placing the binary."
                    )
                    severity = "CRITICAL"
                results.append({
                    "type": "T2_EXECUTION_BEFORE_DISK_CREATION",
                    "process_name": pf.get("executable_name", pf_name),
                    "sources": ["prefetch", "mft"],
                    "severity": severity,
                    "mitre": "T1070.006",
                    "implication": implication,
                    "details": {
                        "prefetch_last_run": pf.get("last_run_utc"),
                        "mft_si_created": mft_entry.get("si_created_utc"),
                        "mft_fn_created": mft_entry.get("fn_created_utc"),
                        "delta_seconds": delta_s,
                        "mft_entry_number": mft_entry.get("mft_entry"),
                        "mft_full_path": mft_entry.get("full_path"),
                        "prefetch_source_file": pf.get("source_file"),
                        "match_quality": (
                            "filename_only"
                            if used_fallback
                            else "directory_aware"
                        ),
                    },
                })

    return results


def _t5_deleted_but_running(
    memory_pslist: list[dict],
    mft_entries: list[dict],
) -> list[dict]:
    """T5: MFT marks file deleted but memory shows it still running.

    Uses a list-valued dict to preserve all deleted MFT entries sharing a
    filename — avoids silently dropping duplicates when the same executable
    name appears in multiple deleted directories.
    """
    results = []

    deleted_names: dict[str, list[dict]] = defaultdict(list)
    for e in mft_entries:
        if e.get("is_deleted"):
            deleted_names[(e.get("filename") or "").lower()].append(e)

    for proc in memory_pslist:
        pname = (proc.get("ImageFileName") or "").lower()
        if not pname:
            continue
        for mft_del in deleted_names.get(pname, []):
            results.append({
                "type": "T5_DELETED_ON_DISK_BUT_RUNNING",
                "process_name": proc.get("ImageFileName"),
                "pid": proc.get("PID"),
                "sources": ["memory", "mft"],
                "severity": "CRITICAL",
                "mitre": "T1036",
                "implication": (
                    f"MFT shows '{pname}' is DELETED (InUse=False, "
                    f"entry {mft_del.get('mft_entry')}), but the process "
                    f"is still RUNNING in memory (PID {proc.get('PID')}). "
                    f"Possible process hollowing, masquerading, or live deletion "
                    f"of malware binary after launch."
                ),
                "details": {
                    "memory_pid": str(proc.get("PID", "")),
                    "mft_entry_number": mft_del.get("mft_entry"),
                    "mft_si_created": mft_del.get("si_created_utc"),
                    "mft_full_path": mft_del.get("full_path"),
                },
            })

    return results


def _t6_usn_deleted_while_running(
    memory_pslist: list[dict],
    usn_deleted_entries: list[dict],
) -> list[dict]:
    """T6: USN Journal shows DELETE on binary while it appears in memory pslist."""
    results = []

    # Collect all PIDs per process name (handles multi-instance: cmd.exe × N)
    pslist_pids: dict[str, list[str]] = defaultdict(list)
    for proc in memory_pslist:
        pname = (proc.get("ImageFileName") or "").lower()
        if not pname:
            continue
        pid_str = str(proc.get("PID", ""))
        if pid_str:
            pslist_pids[pname].append(pid_str)

    for usn in usn_deleted_entries:
        usn_name = (usn.get("name") or "").lower()
        if not usn_name:
            continue
        pids = pslist_pids.get(usn_name)
        if pids:
            results.append({
                "type": "T6_USN_DELETED_WHILE_RUNNING",
                "process_name": usn.get("name"),
                "pids": pids,
                "sources": ["usn_journal", "memory"],
                "severity": "HIGH",
                "mitre": "T1070.004",
                "implication": (
                    f"USN Journal records DELETE_FILE on '{usn_name}' at "
                    f"{usn.get('timestamp_utc')} (USN seq {usn.get('usn')}), "
                    f"but the process is still running in memory "
                    f"(PIDs: {', '.join(pids)}). Attacker may have deleted the "
                    f"binary while the process was live — anti-forensics in "
                    f"progress or timing gap between deletion and memory capture."
                ),
                "details": {
                    "usn_timestamp": usn.get("timestamp_utc"),
                    "usn_sequence": usn.get("usn"),
                    "usn_mft_entry": usn.get("mft_entry"),
                    "memory_pids": pids,
                },
            })

    return results


def _t4_path_mismatch(
    amcache_entries: list[dict],
    prefetch_entries: list[dict],
    mft_entries: list[dict],
) -> list[dict]:
    """T4: Amcache/Prefetch path vs MFT path mismatch — possible sideloading."""
    results = []

    # Build MFT name -> path list map (non-deleted only)
    mft_paths: dict[str, list[str]] = defaultdict(list)
    for e in mft_entries:
        if e.get("is_deleted"):
            continue
        name = (e.get("filename") or "").lower()
        fp = (e.get("full_path") or "").lower()
        if name and fp:
            mft_paths[name].append(fp)

    # Check Amcache paths
    for ac in amcache_entries:
        name = _extract_basename(ac.get("full_path") or ac.get("name") or "")
        ac_dir = canonical_dir(ac.get("full_path") or "")
        if not name or not ac_dir:
            continue

        mft_dirs = {canonical_dir(fp) for fp in mft_paths.get(name, [])}
        if ac_dir not in mft_dirs:
            results.append({
                "type": "T4_PATH_MISMATCH_AMCACHE_MFT",
                "process_name": name,
                "sources": ["amcache", "mft"],
                "severity": "HIGH",
                "mitre": "T1574.001",
                "implication": (
                    f"Amcache records '{name}' running from '{ac_dir}' but "
                    f"MFT does not show the same filename in that directory. "
                    f"Binary in different path may indicate DLL sideloading "
                    f"or binary replacement (T1574.001)."
                ),
                "details": {
                    "amcache_path": ac.get("full_path"),
                    "mft_directories": sorted(mft_dirs),
                },
            })

    # Check Prefetch executable paths (full_path, not source_file —
    # source_file is the .pf filename in \Windows\Prefetch\ and would
    # false-match every entry).
    for pf in prefetch_entries:
        exec_path = (pf.get("full_path") or "").lower()
        if not exec_path:
            continue
        name = _extract_basename(exec_path)
        pf_dir = canonical_dir(exec_path)
        if not name or not pf_dir:
            continue

        mft_dirs = {canonical_dir(fp) for fp in mft_paths.get(name, [])}
        if pf_dir not in mft_dirs:
            results.append({
                "type": "T4_PATH_MISMATCH_PREFETCH_MFT",
                "process_name": name,
                "sources": ["prefetch", "mft"],
                "severity": "HIGH",
                "mitre": "T1574.001",
                "implication": (
                    f"Prefetch records '{name}' running from '{pf_dir}' but "
                    f"MFT does not show the same filename in that directory. "
                    f"Binary in different path may indicate DLL sideloading "
                    f"or binary replacement (T1574.001)."
                ),
                "details": {
                    "prefetch_path": exec_path,
                    "mft_directories": sorted(mft_dirs),
                },
            })

    return results


# ---------------------------------------------------------------------------
# Public API — single entry point
# ---------------------------------------------------------------------------

def detect_timeline_contradictions(
    memory_pslist: Optional[list[dict]] = None,
    prefetch_entries: Optional[list[dict]] = None,
    amcache_entries: Optional[list[dict]] = None,
    mft_entries: Optional[list[dict]] = None,
    usn_entries: Optional[list[dict]] = None,
) -> list[dict]:
    """Run all cross-source contradiction detectors and return findings.

    All arguments are optional — pass only the sources you have.
    Detectors gracefully skip when their required sources are missing.

    Args:
        memory_pslist:    records from parse_memory(windows.pslist)["records"]
        prefetch_entries: entries from parse_prefetch()["entries"]
        amcache_entries:  entries from parse_amcache()["entries"]
        mft_entries:      entries from parse_mft()["entries"]
        usn_entries:      deleted entries from parse_usn_journal()["deleted"]

    Returns:
        List of contradiction dicts ordered by severity (CRITICAL first).
        Each dict has: type, process_name, sources, severity, mitre,
        implication, details.
    """
    mem = memory_pslist or []
    pf = prefetch_entries or []
    ac = amcache_entries or []
    mft = mft_entries or []
    usn = usn_entries or []

    contradictions: list[dict] = []

    if mem:
        contradictions.extend(_t1_process_missing_from_disk(mem, pf, ac, mft))
        if mft:
            contradictions.extend(_t5_deleted_but_running(mem, mft))
        if usn:
            contradictions.extend(_t6_usn_deleted_while_running(mem, usn))

    if pf and mft:
        contradictions.extend(_t2_timestamp_predates_install(pf, mft))

    if ac and mft:
        contradictions.extend(_t4_path_mismatch(ac, pf, mft))

    # Sort: CRITICAL → HIGH → MEDIUM → LOW
    _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    contradictions.sort(key=lambda c: _severity_order.get(c.get("severity", "LOW"), 99))

    return contradictions
