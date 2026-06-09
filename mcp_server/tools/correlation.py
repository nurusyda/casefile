"""Correlation tool — composition layer over existing parsers.

Block 8: correlate_evidence() calls parse_amcache, parse_prefetch,
parse_memory, and parse_mft to produce a cross-source verdict for a
given process_name.  This module NEVER duplicates parsing logic — it
only consumes the return values of existing parser tools.

Verdict logic is deterministic (no LLM):
  CONFIRMED_RUNNING    — present in memory pslist
  CONFIRMED_HISTORICAL — Amcache + Prefetch but not memory
  INSTALLED_NEVER_RAN  — MFT only, no execution evidence
  MEMORY_ONLY          — running but no disk artifact (injection?)
  NOT_FOUND            — no source has it
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime as _dt
from typing import Any

from pathlib import Path

from mcp_server.tools._shared import audit_log, PathConfinementError, MemoryImageNotFoundError, _enforce_case_root, _discover_memory_image
from mcp_server.tools.amcache import parse_amcache
from mcp_server.tools.prefetch import parse_prefetch
from mcp_server.tools.memory import parse_memory
from mcp_server.tools.mft_safe import parse_mft
from mcp_server.tools._shared import canonical_dir
from mcp_server.tools.timeline_contradiction import detect_timeline_contradictions


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class CorrelationToolError(Exception):
    """Typed error for the correlation tool."""


def _resolve_case_dir(case_dir: str) -> Path:
    """Resolve and confine case_dir to CASEFILE_CASE_ROOT.

    Prevents path traversal: case_dir='../../etc' is rejected before
    any filesystem access occurs.

    Raises:
        CorrelationToolError: if case_dir resolves outside CASEFILE_CASE_ROOT.
    """
    _case_root_env = os.environ.get("CASEFILE_CASE_ROOT")
    if _case_root_env:
        case_root = Path(_case_root_env).resolve()
        resolved = (case_root / case_dir).resolve()
        try:
            _enforce_case_root(resolved)
        except PathConfinementError as exc:
            raise CorrelationToolError(
                f"case_dir escapes case root: {case_dir!r} resolves to {resolved}"
            ) from exc
        return resolved
    # No CASEFILE_CASE_ROOT set — treat case_dir as absolute path (dev/test mode)
    return Path(case_dir).resolve()



# --------------------------------------------------------------------------- #
# Verdict enum (plain strings — no external dependency)
# --------------------------------------------------------------------------- #

VERDICTS = frozenset({
    "CONFIRMED_RUNNING",
    "CONFIRMED_HISTORICAL",
    "INSTALLED_NEVER_RAN",
    "MEMORY_ONLY",
    "NOT_FOUND",
    "ERROR",
})

_VERDICT_CONFIDENCE: dict[str, str] = {
    "CONFIRMED_RUNNING":    "CONFIRMED",
    "CONFIRMED_HISTORICAL": "CONFIRMED",
    "MEMORY_ONLY":          "CONFIRMED",
    "INSTALLED_NEVER_RAN":  "INFERRED",
    "NOT_FOUND":            "HYPOTHESIS",
    "ERROR":                "INFERRED",
}


# --------------------------------------------------------------------------- #
# SourceResult dataclass
# --------------------------------------------------------------------------- #

@dataclass
class SourceResult:
    """Normalised result from a single parser source."""

    source: str            # "amcache" | "prefetch" | "memory" | "mft"
    present: bool = False
    invocation_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    _raw_result: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the return schema."""
        d: dict[str, Any] = {"present": self.present}
        if self.invocation_id:
            d["invocation_id"] = self.invocation_id
        if self.details:
            reserved = {"present", "invocation_id", "error"} & set(self.details)
            if reserved:
                raise ValueError(f"Details collides with reserved key(s): {reserved}")
            d.update(self.details)
        if self.error is not None:
            d["error"] = self.error
        return d


# --------------------------------------------------------------------------- #
# Pure verdict function — deterministic, no I/O
# --------------------------------------------------------------------------- #

def _decide_verdict(
    amcache: SourceResult,
    prefetch: SourceResult,
    memory: SourceResult,
    mft: SourceResult,
) -> tuple[str, str]:
    """Return (verdict, verdict_reasoning) based on source presence.

    Decision tree (evaluated top-to-bottom, first match wins):
      1. memory.present -> CONFIRMED_RUNNING
         Sub-case: memory + no disk artifacts -> MEMORY_ONLY
      2. amcache.present AND prefetch.present -> CONFIRMED_HISTORICAL
      3. (amcache.present OR prefetch.present) only -> CONFIRMED_HISTORICAL
         (execution evidence exists even if only one source confirms)
      4. mft.present only -> INSTALLED_NEVER_RAN
      5. nothing -> NOT_FOUND

    Returns:
        Tuple of (verdict_string, human-readable reasoning).
    """
    # If any parser crashed, return ERROR so callers know the verdict is unreliable.
    # A tool crash must not silently degrade to NOT_FOUND or INSTALLED_NEVER_RAN.
    errored = [s for s in (amcache, prefetch, memory, mft) if s.error]
    if errored:
        error_summary = "; ".join(
            f"{s.source}: {s.error}" for s in errored
        )
        return (
            "ERROR",
            f"One or more parsers failed — verdict unreliable. "
            f"Errors: {error_summary}",
        )

    in_memory = memory.present
    has_execution = amcache.present or prefetch.present
    on_disk = mft.present

    if in_memory and has_execution:
        return (
            "CONFIRMED_RUNNING",
            "Process found in live memory AND has disk execution evidence "
            "(Amcache/Prefetch). Confirmed running at time of memory capture "
            "with historical execution artifacts on disk.",
        )

    if in_memory and on_disk and not has_execution:
        return (
            "CONFIRMED_RUNNING",
            "Process found in live memory and on-disk (MFT) but without "
            "Amcache/Prefetch records. Running at capture time; missing "
            "execution artifacts may indicate anti-forensics or artifact "
            "rollover.",
        )

    if in_memory and not has_execution and not on_disk:
        return (
            "MEMORY_ONLY",
            "Process found ONLY in live memory — no disk artifacts "
            "(no MFT, Amcache, or Prefetch). Possible process injection, "
            "fileless malware, or evidence of anti-forensic disk wiping.",
        )

    # Not in memory from here on
    if has_execution:
        sources: list[str] = []
        if amcache.present:
            sources.append("Amcache")
        if prefetch.present:
            sources.append("Prefetch")
        source_str = " and ".join(sources)
        return (
            "CONFIRMED_HISTORICAL",
            f"Process found in {source_str} but NOT in live memory. "
            "Historically executed on this system but not running at the "
            "time of memory capture.",
        )

    if on_disk:
        return (
            "INSTALLED_NEVER_RAN",
            "Process found in MFT (file exists on disk) but has NO "
            "execution evidence — not in Amcache, Prefetch, or memory. "
            "File was placed on disk but never executed (or execution "
            "artifacts were cleared).",
        )

    return (
        "NOT_FOUND",
        "Process not found in any source — not in Amcache, Prefetch, "
        "MFT, or memory. No evidence of this process on the analyzed "
        "system.",
    )


# --------------------------------------------------------------------------- #
# Parser call stubs — replaced in Commits 2 & 3 with real calls
# --------------------------------------------------------------------------- #

def _call_parse_amcache(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Call parse_amcache() and search entries for process_name (case-insensitive).

    Evidence file: {case_dir}/Amcache.hve
    Match field:   entry["name"]  (e.g. "subject_srv.exe")

    Returns SourceResult — never raises.
    """
    try:
        case_path = _resolve_case_dir(case_dir)
        hive_path = case_path / "Amcache.hve"
        if not hive_path.exists():
            return SourceResult(source="amcache", present=False)

        result = parse_amcache(str(hive_path))

        if result.get("error"):
            return SourceResult(
                source="amcache",
                present=False,
                invocation_id=result.get("invocation_id", ""),
                error=str(result["error"]),
                _raw_result=result,
            )

        target = process_name.lower()
        for entry in result.get("entries", []):
            if entry.get("name", "").lower() == target:
                return SourceResult(
                    source="amcache",
                    present=True,
                    invocation_id=result.get("invocation_id", ""),
                    details={
                        "sha1":          entry.get("sha1", ""),
                        "full_path":     entry.get("full_path", ""),
                        "first_run_utc": entry.get("first_run_utc", ""),
                    },
                    _raw_result=result,
                )

        return SourceResult(
            source="amcache",
            present=False,
            invocation_id=result.get("invocation_id", ""),
            _raw_result=result,
        )
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source="amcache", present=False, error=str(exc))


def _call_parse_prefetch(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Call parse_prefetch() and search entries for process_name (case-insensitive).

    Evidence directory: {case_dir}/Prefetch/
    Match field:        entry["executable_name"]  (e.g. "SUBJECT_SRV.EXE")

    Returns SourceResult — never raises.
    """
    try:
        case_path = _resolve_case_dir(case_dir)
        pf_dir = case_path / "Prefetch"
        if not pf_dir.exists():
            return SourceResult(source="prefetch", present=False)

        result = parse_prefetch(str(pf_dir))

        if result.get("error"):
            return SourceResult(
                source="prefetch",
                present=False,
                invocation_id=result.get("invocation_id", ""),
                error=str(result["error"]),
                _raw_result=result,
            )

        target = process_name.lower()
        for entry in result.get("entries", []):
            if entry.get("executable_name", "").lower() == target:
                return SourceResult(
                    source="prefetch",
                    present=True,
                    invocation_id=result.get("invocation_id", ""),
                    details={
                        "executable_name": entry.get("executable_name", ""),
                        "last_run_utc":    entry.get("last_run_utc", ""),
                        "run_count":       entry.get("run_count", 0),
                        "source_file":     entry.get("source_file", ""),
                    },
                    _raw_result=result,
                )

        return SourceResult(
            source="prefetch",
            present=False,
            invocation_id=result.get("invocation_id", ""),
            _raw_result=result,
        )
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source="prefetch", present=False, error=str(exc))


def _call_parse_memory(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Call parse_memory(windows.pslist) and search records for process_name.

    Memory image resolution (priority order):
      1. CASEFILE_MEMORY_IMAGE env var — absolute path to the image file,
         confined under CASEFILE_CASE_ROOT when that env var is set.
      2. First sorted *.img / *.mem / *.vmem / *.raw (case-insensitive) found
         in {case_dir}/.. — sibling of the analysis directory.

    Match field: record["ImageFileName"] (case-insensitive; honours the 14-char
    Windows kernel truncation of ImageFileName).

    Returns SourceResult — never raises (CorrelationToolError is caught and
    returned as SourceResult with present=False and error set).
    """
    try:
        # Memory image resolution — delegated to shared _discover_memory_image
        # which handles CASEFILE_MEMORY_IMAGE env var and parent-directory glob.
        case_path = _resolve_case_dir(case_dir)
        try:
            image_file = _discover_memory_image(case_path)
        except MemoryImageNotFoundError as exc:
            return SourceResult(
                source='memory', present=False,
                error=f"Memory image misconfigured: {exc}"
            )
        if image_file is None:
            return SourceResult(source='memory', present=False)
        image_path = str(image_file)
        result = parse_memory(image_path, plugin="windows.pslist")

        if result.get("error"):
            return SourceResult(
                source="memory",
                present=False,
                invocation_id=result.get("invocation_id", ""),
                error=str(result["error"]),
                _raw_result=result,
            )

        target = process_name.lower()
        for record in result.get("records", []):
            img_name = record.get("ImageFileName", "").lower()
            # Windows kernel truncates ImageFileName to 14 visible chars.
            # Match exact OR prefix (target starts with the truncated name).
            match = (img_name == target) or (
                img_name and target.startswith(img_name) and len(img_name) == 14
            )
            if match:
                return SourceResult(
                    source="memory",
                    present=True,
                    invocation_id=result.get("invocation_id", ""),
                    details={
                        "pid":            str(record.get("PID", "")),
                        "ppid":           str(record.get("PPID", "")),
                        "image_filename": record.get("ImageFileName", ""),
                    },
                    _raw_result=result,
                )

        return SourceResult(
            source="memory",
            present=False,
            invocation_id=result.get("invocation_id", ""),
            _raw_result=result,
        )
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source="memory", present=False, error=str(exc))


def _call_parse_mft(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Call parse_mft() with filename_filter=[process_name] and check for a match.

    Evidence file: {case_dir}/MFT
    Match field:   entry["FileName"]  (case-insensitive)

    Returns SourceResult — never raises.
    """
    try:
        case_path = _resolve_case_dir(case_dir)
        mft_path = case_path / "MFT"
        if not mft_path.exists():
            return SourceResult(source="mft", present=False)

        result = parse_mft(str(mft_path), filename_filter=[process_name])

        if result.get("error"):
            return SourceResult(
                source="mft",
                present=False,
                invocation_id=result.get("invocation_id", ""),
                error=str(result["error"]),
                _raw_result=result,
            )

        target = process_name.lower()
        for entry in result.get("entries", []):
            # parse_mft() normalises keys: FileName→filename, InUse→is_deleted,
            # Created0x10→si_created_utc, and constructs full_path.
            # Check both raw (FileName) and normalised (filename) key names
            # so that both real parse_mft output and mocked test data work.
            entry_name = (
                entry.get("filename", "")
                or entry.get("FileName", "")
            ).lower()
            if entry_name == target:
                # Resolve full_path: use normalised key first, then
                # construct from ParentPath+FileName (raw keys) or
                # parent_path+filename (normalised keys).
                _full_path = entry.get("full_path", "")
                if not _full_path:
                    _parent = entry.get("parent_path", "") or entry.get("ParentPath", "")
                    _fname = entry.get("filename", "") or entry.get("FileName", "")
                    if _parent and _fname:
                        _full_path = _parent.rstrip("\\/") + "\\" + _fname
                # Resolve SI/FN timestamps: normalised keys first, raw CSV
                # column names as fallback.
                _si_utc = entry.get("si_created_utc", "") or entry.get("Created0x10", "")
                _fn_utc = entry.get("fn_created_utc", "") or entry.get("Created0x30", "")
                # Resolve is_deleted: normalised key first, InUse as fallback
                # (InUse=="true" → not deleted; InUse missing/"false" → deleted).
                _is_del = entry.get("is_deleted")
                if _is_del is None:
                    _inuse = entry.get("InUse", "true")
                    _is_del = str(_inuse).lower() != "true"

                return SourceResult(
                    source="mft",
                    present=True,
                    invocation_id=result.get("invocation_id", ""),
                    details={
                        "file_path":      _full_path,
                        "full_path":      _full_path,
                        "si_created_utc": _si_utc,
                        "fn_created_utc": _fn_utc,
                        "is_deleted":     _is_del,
                    },
                    _raw_result=result,
                )

        return SourceResult(
            source="mft",
            present=False,
            invocation_id=result.get("invocation_id", ""),
            _raw_result=result,
        )
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source="mft", present=False, error=str(exc))


# --------------------------------------------------------------------------- #

def detect_contradictions(
    amcache: "SourceResult",
    prefetch: "SourceResult",
    memory: "SourceResult",
    mft: "SourceResult",
) -> list[dict]:
    """Detect cross-source contradictions. Deterministic -- zero LLM involvement.

    Returns list of contradiction dicts, each with:
      name, sources, implication, severity, details, mitre
    """
    contradictions: list[dict] = []

    # 1. Execution before creation -> timestomping indicator (T1070.006)
    pf_time = prefetch.details.get("last_run_utc") if prefetch.present and prefetch.details else None
    # si_created_utc is the canonical field; Created0x10 is the raw MFT column name fallback
    mft_si = (mft.details.get("si_created_utc") or mft.details.get("Created0x10")) if mft.present and mft.details else None
    if pf_time and mft_si:
        try:
            def _p(ts: str):
                return _dt.fromisoformat(str(ts).replace("Z", "+00:00"))
            pt, mc = _p(pf_time), _p(mft_si)
            if pt < mc:
                contradictions.append({
                    "name": "execution_before_creation",
                    "sources": ["prefetch", "mft"],
                    "implication": (
                        "Process executed before MFT $SI creation timestamp -- "
                        "possible timestomping (T1070.006)."
                    ),
                    "severity": "CRITICAL",
                    "details": {
                        "prefetch_last_run": str(pf_time),
                        "mft_si_created": str(mft_si),
                    },
                    "mitre": "T1070.006",
                })
        except (ValueError, TypeError, AttributeError):
            pass

    # 2. Memory only, no disk artifacts -> fileless / process injection (T1055)
    if memory.present and not amcache.present and not prefetch.present and not mft.present:
        contradictions.append({
            "name": "memory_only_no_amcache_prefetch_mft",
            "sources": ["memory"],
            "implication": (
                "Process found in memory with no Amcache/Prefetch/MFT artifacts -- "
                "possible fileless malware or process injection (T1055). "
                "Note: registry and event log sources not evaluated here."
            ),
            "severity": "HIGH",
            "details": {
                "pid": memory.details.get("pid") if memory.details else None,
                "image_filename": memory.details.get("image_filename") if memory.details else None,
            },
            "mitre": "T1055",
        })

    # 3. Amcache path vs MFT path mismatch -> DLL sideloading / binary replacement
    # Use canonical_dir to strip drive letters / device prefixes before comparing
    # so that c:\windows\... and \windows\... are treated as the same directory.
    ac_full = (amcache.details.get("full_path") or amcache.details.get("path", "")).lower() if amcache.present and amcache.details else ""
    mft_full = (mft.details.get("full_path") or "").lower() if mft.present and mft.details else ""
    ac_dir = canonical_dir(ac_full) if ac_full else ""
    mft_dir = canonical_dir(mft_full) if mft_full else ""
    if ac_dir and mft_dir and ac_dir != mft_dir:
        contradictions.append({
            "name": "path_mismatch_amcache_mft",
            "sources": ["amcache", "mft"],
            "implication": (
                "Executable path differs between Amcache and MFT -- "
                "possible DLL sideloading or binary replacement (T1574.001)."
            ),
            "severity": "HIGH",
            "details": {"amcache_path": ac_full, "mft_path": mft_full},
            "mitre": "T1574.001",
        })

    return contradictions


# Main entry point
# --------------------------------------------------------------------------- #

def correlate_evidence(
    process_name: str,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Cross-source correlation for a single process.

    Calls four parsers (amcache, prefetch, memory, mft), collects
    results, and produces a deterministic verdict.

    Args:
        process_name: Executable name to correlate (e.g. "subject_srv.exe").
        case_dir: Path to the case directory.  Falls back to
                  CASEFILE_CASE_DIR env var.

    Returns:
        Dict with keys: process_name, amcache, prefetch, memory, mft,
        verdict, verdict_reasoning, supporting_invocation_ids,
        invocation_id.

    Raises:
        CorrelationToolError: On invalid input or unrecoverable errors.
    """
    invocation_id = f"correlation_{uuid.uuid4().hex[:12]}"
    t_start = time.monotonic()
    _safe_name = repr(process_name)  # safe for logging even if None/invalid

    # --- Audit state (populated inside try, consumed in finally) ------------
    _verdict: str | None = None
    _sources_present: list[str] = []
    _resolved_case_dir: str = ""
    _returncode: int = 1
    try:
        # --- Input validation -----------------------------------------------
        if not process_name or not isinstance(process_name, str):
            raise CorrelationToolError(
                "process_name is required and must be a non-empty string"
            )
        process_name = process_name.strip()
        if not process_name:
            raise CorrelationToolError(
                "process_name must not be blank after stripping whitespace"
            )
        _resolved_case_dir = case_dir or os.environ.get("CASEFILE_CASE_DIR", "")
        if not _resolved_case_dir:
            raise CorrelationToolError(
                "case_dir must be provided or CASEFILE_CASE_DIR must be set"
            )
        # --- Call each parser ------------------------------------------------
        amcache = _call_parse_amcache(process_name, _resolved_case_dir)
        prefetch = _call_parse_prefetch(process_name, _resolved_case_dir)
        memory = _call_parse_memory(process_name, _resolved_case_dir)
        mft = _call_parse_mft(process_name, _resolved_case_dir)
        # --- Determine verdict ----------------------------------------------
        verdict, verdict_reasoning = _decide_verdict(amcache, prefetch, memory, mft)
        _verdict = verdict
        # --- Collect supporting invocation IDs ------------------------------
        supporting_invocation_ids: list[str] = [
            sr.invocation_id
            for sr in (amcache, prefetch, memory, mft)
            if sr.present and sr.invocation_id
        ]
        # --- Filter timeline contradictions to this process ----------------
        _all_tcs = detect_timeline_contradictions(
            memory_pslist=memory._raw_result.get("records", []) if not memory.error else [],
            prefetch_entries=prefetch._raw_result.get("entries", []) if not prefetch.error else [],
            amcache_entries=amcache._raw_result.get("entries", []) if not amcache.error else [],
            mft_entries=mft._raw_result.get("entries", []) if not mft.error else [],
        )
        _tc_for_process = [
            c for c in _all_tcs
            if (c.get("process_name") or "").lower() == process_name.lower()
        ]
        # Surface parser errors that caused empty _raw_result slices —
        # silent omission could hide anti-forensics evidence.
        _entry_keys = {"memory": "records", "amcache": "entries", "prefetch": "entries", "mft": "entries"}
        # --- Build return schema --------------------------------------------
        result: dict[str, Any] = {
            "process_name": process_name,
            "amcache": amcache.to_dict(),
            "prefetch": prefetch.to_dict(),
            "memory": memory.to_dict(),
            "mft": mft.to_dict(),
            "verdict": verdict,
            "verdict_reasoning": verdict_reasoning,
            "contradictions": detect_contradictions(amcache, prefetch, memory, mft),
            "timeline_contradictions": _tc_for_process,
            "tc_data_gaps": [
                f"{sr.source}: {sr.error}"
                for sr in (amcache, prefetch, memory, mft)
                if sr.error and not sr._raw_result.get(_entry_keys.get(sr.source, "entries"))
            ] or None,
            "confidence": _VERDICT_CONFIDENCE[verdict],
            "supporting_invocation_ids": supporting_invocation_ids,
            "invocation_id": invocation_id,
        }
        _sources_present = [
            sr.source for sr in (amcache, prefetch, memory, mft) if sr.present
        ]
        _returncode = 0
        return result
    finally:
        # --- Audit logging — always fires, even on validation error ---------
        elapsed_ms = (time.monotonic() - t_start) * 1000
        examiner = os.environ.get("CASEFILE_EXAMINER", "unknown")
        _extra: dict = {
            "params": {
                "process_name": process_name,
                "case_dir": _resolved_case_dir,
            },
            "sources_present": _sources_present,
            "sources_present_count": len(_sources_present),
        }
        if _verdict is not None:
            _extra["verdict"] = _verdict
        audit_log(
            tool="correlate_evidence",
            invocation_id=invocation_id,
            cmd=f"correlate_evidence(process_name={_safe_name})",
            returncode=_returncode,
            stdout_lines=0,
            stderr_excerpt="",
            parsed_record_count=len(_sources_present),
            duration_ms=round(elapsed_ms),
            examiner=examiner,
            extra=_extra,
        )


# ---------------------------------------------------------------------------
# Host-type detection — Phase 1 discovery before correlate_evidence()
# ---------------------------------------------------------------------------

#: Recognised host types returned by detect_host_type()
HOST_TYPES = frozenset({"WORKSTATION", "DOMAIN_CONTROLLER", "MEMORY_ONLY", "UNKNOWN"})


def detect_host_type(case_dir: str) -> dict:
    """Inspect artifact layout under *case_dir* and return the host type.

    The agent MUST call this before correlate_evidence() on any image it has
    not previously analysed.  The verdict determines which tools and verdict
    logic are appropriate:

    * WORKSTATION       — Amcache.hve or Prefetch/ present → full
                          correlate_evidence() pipeline applicable.
    * DOMAIN_CONTROLLER — Security.evtx >= 50 MB and no Amcache →
                          event-log correlation is the primary evidence source;
                          correlate_evidence() will have limited value.
    * MEMORY_ONLY       — memory image present but no disk artifacts →
                          use parse_memory() only.
    * UNKNOWN           — insufficient artifacts to classify; proceed with
                          caution and document the gap.

    Args:
        case_dir: Path to the case directory (same value passed to
                  correlate_evidence).

    Returns:
        dict with keys:
            host_type       — one of HOST_TYPES
            indicators      — list of detected artifact paths/sizes
            recommendation  — short string advising which tools to use
            invocation_id   — UUID for audit traceability
    """
    invocation_id = str(uuid.uuid4())
    t_start = time.monotonic()
    _returncode = 1
    host_type = "UNKNOWN"
    indicators: list[str] = []
    recommendation = ""

    try:
        if not case_dir or not str(case_dir).strip():
            raise ValueError("case_dir must be a non-empty string")

        case_path = _resolve_case_dir(case_dir)  # enforces CASEFILE_CASE_ROOT confinement
        if not case_path.is_dir():
            raise ValueError(f"case_dir is not a directory: {case_dir!r}")

        # ── artifact probes (case-insensitive on Linux) ─────────────────────
        # Build a lowercase name → Path map for all entries in case_dir
        try:
            _dir_entries = {f.name.lower(): f for f in case_path.iterdir()}
        except (PermissionError, OSError):
            host_type = "UNKNOWN"
            indicators.append(
                f"Cannot scan case_dir due to permission error — {case_path}"
            )
            recommendation = (
                "Proceed with caution. Unable to enumerate directory contents. "
                "Document artifact gaps explicitly."
            )
            _returncode = 0
            return {
                "host_type": host_type,
                "indicators": indicators,
                "recommendation": recommendation,
                "invocation_id": invocation_id,
            }

        # Workstation signals
        amcache_present = "amcache.hve" in _dir_entries
        prefetch_present = (
            ("prefetch" in _dir_entries and _dir_entries["prefetch"].is_dir())
            or bool(list(case_path.glob("*.[Pp][Ff]")))
        )

        # Domain controller signal — Security.evtx >= 50 MB
        sec_evtx_path: Path | None = None
        for candidate_name in ("security.evtx",):
            if candidate_name in _dir_entries:
                sec_evtx_path = _dir_entries[candidate_name]
                break
        # also check evtx/ subdirectory
        if sec_evtx_path is None and "evtx" in _dir_entries:
            evtx_sub = _dir_entries["evtx"]
            if evtx_sub.is_dir():
                try:
                    sub_entries = {f.name.lower(): f for f in evtx_sub.iterdir()}
                    if "security.evtx" in sub_entries:
                        sec_evtx_path = sub_entries["security.evtx"]
                except PermissionError:
                    pass
        dc_evtx_large = (
            sec_evtx_path is not None
            and sec_evtx_path.stat().st_size >= 50 * 1024 * 1024  # 50 MB
        )

        # Memory signal — only inside case_dir (no parent traversal)
        _mem_exts = {"vmem", "img", "mem", "raw", "dmp", "001"}
        memory_images: list[Path] = [
            f for f in _dir_entries.values()
            if f.is_file() and f.suffix.lstrip(".").lower() in _mem_exts
        ]

        # ── classification logic ────────────────────────────────────────────
        if amcache_present or prefetch_present:
            host_type = "WORKSTATION"
            if amcache_present:
                indicators.append(f"Amcache.hve found at {case_path / 'Amcache.hve'}")
            if prefetch_present:
                indicators.append(f"Prefetch artifacts found under {case_path}")
            recommendation = (
                "Use full correlate_evidence() pipeline. "
                "parse_amcache(), parse_prefetch(), parse_mft(), parse_memory() all applicable."
            )

        elif dc_evtx_large and not amcache_present:
            host_type = "DOMAIN_CONTROLLER"
            size_mb = round(sec_evtx_path.stat().st_size / (1024 * 1024), 1)
            indicators.append(
                f"Security.evtx at {sec_evtx_path} ({size_mb} MB >= 50 MB threshold)"
            )
            indicators.append("No Amcache.hve — consistent with domain controller role")
            recommendation = (
                "Primary evidence: parse_event_logs() on Security.evtx with "
                "EIDs [4624, 4625, 4648, 4768, 4769, 4771, 7045, 4720, 4728, 1102]. "
                "correlate_evidence() has limited value — DC rarely has Prefetch/Amcache. "
                "Use parse_registry() on SYSTEM/SECURITY hives for service installs."
            )

        elif memory_images and not amcache_present and not prefetch_present:
            host_type = "MEMORY_ONLY"
            for img in memory_images[:3]:
                indicators.append(f"Memory image: {img}")
            recommendation = (
                "Use parse_memory() only. "
                "No disk artifacts detected — confine claims to memory evidence."
            )

        else:
            host_type = "UNKNOWN"
            indicators.append(f"No definitive artifacts found under {case_path}")
            if sec_evtx_path:
                size_mb = round(sec_evtx_path.stat().st_size / (1024 * 1024), 1)
                indicators.append(
                    f"Security.evtx present but small ({size_mb} MB < 50 MB threshold)"
                )
            recommendation = (
                "Proceed with caution. Run parse_event_logs() if evtx files exist, "
                "parse_registry() if hives exist. Document artifact gaps explicitly."
            )

        _returncode = 0
        return {
            "host_type": host_type,
            "indicators": indicators,
            "recommendation": recommendation,
            "invocation_id": invocation_id,
        }

    finally:
        elapsed_ms = (time.monotonic() - t_start) * 1000
        examiner = os.environ.get("CASEFILE_EXAMINER", "unknown")
        try:
            audit_log(
                tool="detect_host_type",
                invocation_id=invocation_id,
                cmd=f"detect_host_type(case_dir={case_dir!r})",
                returncode=_returncode,
                stdout_lines=0,
                stderr_excerpt="",
                parsed_record_count=len(indicators),
                duration_ms=round(elapsed_ms),
                examiner=examiner,
                extra={"case_dir": str(case_dir), "host_type": host_type},
            )
        except Exception as _audit_exc:
            print(f"[detect_host_type] audit_log failed (ignored): {_audit_exc}",
                  file=sys.stderr)
