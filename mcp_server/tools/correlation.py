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
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from pathlib import Path

from mcp_server.tools._shared import audit_log
from mcp_server.tools.amcache import parse_amcache
from mcp_server.tools.prefetch import parse_prefetch
from mcp_server.tools.memory import parse_memory
from mcp_server.tools.mft import parse_mft


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class CorrelationToolError(Exception):
    """Typed error for the correlation tool."""

# --------------------------------------------------------------------------- #
# Path confinement helper
# --------------------------------------------------------------------------- #

def _enforce_case_root(path: Path) -> None:
    """Raise CorrelationToolError if path escapes CASEFILE_CASE_ROOT (when set).

    Single implementation of the confinement check — both _resolve_case_dir
    and _require_within_case_root delegate here to prevent divergence.
    Security-sensitive: any change to confinement logic must happen here only.
    """
    case_root_env = os.environ.get("CASEFILE_CASE_ROOT")
    if not case_root_env:
        if "CASEFILE_CASE_ROOT" in os.environ:
            raise CorrelationToolError(
                "CASEFILE_CASE_ROOT is set but empty — path confinement cannot be applied"
            )
        return
    root = Path(case_root_env).resolve()
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise CorrelationToolError(
            f"path escapes case root: {path}"
        ) from exc


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
        except CorrelationToolError as exc:
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
})

_VERDICT_CONFIDENCE: dict[str, str] = {
    "CONFIRMED_RUNNING":    "CONFIRMED",
    "CONFIRMED_HISTORICAL": "CONFIRMED",
    "MEMORY_ONLY":          "CONFIRMED",
    "INSTALLED_NEVER_RAN":  "INFERRED",
    "NOT_FOUND":            "HYPOTHESIS",
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
                )

        return SourceResult(
            source="amcache",
            present=False,
            invocation_id=result.get("invocation_id", ""),
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
                )

        return SourceResult(
            source="prefetch",
            present=False,
            invocation_id=result.get("invocation_id", ""),
        )
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source="prefetch", present=False, error=str(exc))


def _require_within_case_root(path: Path) -> None:
    """Raise CorrelationToolError if path escapes CASEFILE_CASE_ROOT (when set).

    Delegates to _enforce_case_root — single implementation of confinement check.
    """
    _enforce_case_root(path)


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
        # Memory image resolution -- explicit env var takes priority over glob.
        # Set CASEFILE_MEMORY_IMAGE to the absolute path of the .img file so
        # ralph.sh can point to the real image without relying on parent-dir layout.
        case_path = _resolve_case_dir(case_dir)
        explicit_image = os.environ.get('CASEFILE_MEMORY_IMAGE')
        if explicit_image:
            image_file = Path(os.path.expanduser(explicit_image)).resolve()
            _require_within_case_root(image_file)
            if not image_file.is_file():
                return SourceResult(
                    source='memory',
                    present=False,
                    error=f"Memory image not found or not a regular file: {image_file}",
                )
            image_path = str(image_file)
        else:
            # Fallback: glob parent directory (SRL-2018 layout)
            img_search_dir = case_path.parent
            _require_within_case_root(img_search_dir)
            images: list[Path] = []
            for _ext in ("img", "mem", "vmem", "raw"):
                images = sorted(
                    p for p in img_search_dir.iterdir()
                    if p.is_file() and p.suffix.lower() == f".{_ext}"
                )
                if images:
                    break
            if not images:
                return SourceResult(source='memory', present=False)
            image_file = images[0].resolve()
            _require_within_case_root(image_file)
            image_path = str(image_file)
        result = parse_memory(image_path, plugin="windows.pslist")

        if result.get("error"):
            return SourceResult(
                source="memory",
                present=False,
                invocation_id=result.get("invocation_id", ""),
                error=str(result["error"]),
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
                )

        return SourceResult(
            source="memory",
            present=False,
            invocation_id=result.get("invocation_id", ""),
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
            )

        target = process_name.lower()
        for entry in result.get("entries", []):
            if entry.get("FileName", "").lower() == target:
                return SourceResult(
                    source="mft",
                    present=True,
                    invocation_id=result.get("invocation_id", ""),
                    details={
                        "file_path":      entry.get("ParentPath", ""),
                        "si_created_utc": entry.get("Created0x10", ""),
                        "fn_created_utc": entry.get("Created0x30", ""),
                        "is_deleted":     str(entry.get("InUse", "true")).lower() == "false",
                    },
                )

        return SourceResult(
            source="mft",
            present=False,
            invocation_id=result.get("invocation_id", ""),
        )
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source="mft", present=False, error=str(exc))


# --------------------------------------------------------------------------- #
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
        # --- Build return schema --------------------------------------------
        result: dict[str, Any] = {
            "process_name": process_name,
            "amcache": amcache.to_dict(),
            "prefetch": prefetch.to_dict(),
            "memory": memory.to_dict(),
            "mft": mft.to_dict(),
            "verdict": verdict,
            "verdict_reasoning": verdict_reasoning,
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
            cmd=f"correlate_evidence(process_name={process_name!r})",
            returncode=_returncode,
            stdout_lines=0,
            stderr_excerpt="",
            parsed_record_count=len(_sources_present),
            duration_ms=round(elapsed_ms),
            examiner=examiner,
            extra=_extra,
        )
