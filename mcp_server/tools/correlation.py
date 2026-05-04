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

from mcp_server.tools._shared import audit_log


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class CorrelationToolError(Exception):
    """Typed error for the correlation tool."""


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
    """Stub: will call parse_amcache() in Commit 2."""
    return SourceResult(source="amcache", present=False, error="not_wired")


def _call_parse_prefetch(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Stub: will call parse_prefetch() in Commit 2."""
    return SourceResult(source="prefetch", present=False, error="not_wired")


def _call_parse_memory(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Stub: will call parse_memory() in Commit 3."""
    return SourceResult(source="memory", present=False, error="not_wired")


def _call_parse_mft(
    process_name: str, case_dir: str,
) -> SourceResult:
    """Stub: will call parse_mft() in Commit 3."""
    return SourceResult(source="mft", present=False, error="not_wired")


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

    # --- Input validation ---------------------------------------------------
    if not process_name or not isinstance(process_name, str):
        raise CorrelationToolError(
            "process_name is required and must be a non-empty string"
        )

    process_name = process_name.strip()
    if not process_name:
        raise CorrelationToolError(
            "process_name must not be blank after stripping whitespace"
        )

    resolved_case_dir = case_dir or os.environ.get("CASEFILE_CASE_DIR", "")
    if not resolved_case_dir:
        raise CorrelationToolError(
            "case_dir must be provided or CASEFILE_CASE_DIR must be set"
        )

    # --- Call each parser (stubs for Commit 1) ------------------------------
    amcache = _call_parse_amcache(process_name, resolved_case_dir)
    prefetch = _call_parse_prefetch(process_name, resolved_case_dir)
    memory = _call_parse_memory(process_name, resolved_case_dir)
    mft = _call_parse_mft(process_name, resolved_case_dir)

    # --- Determine verdict --------------------------------------------------
    verdict, verdict_reasoning = _decide_verdict(amcache, prefetch, memory, mft)

    # --- Collect supporting invocation IDs ----------------------------------
    supporting_invocation_ids: list[str] = [
        sr.invocation_id
        for sr in (amcache, prefetch, memory, mft)
        if sr.invocation_id
    ]

    # --- Build return schema ------------------------------------------------
    result: dict[str, Any] = {
        "process_name": process_name,
        "amcache": amcache.to_dict(),
        "prefetch": prefetch.to_dict(),
        "memory": memory.to_dict(),
        "mft": mft.to_dict(),
        "verdict": verdict,
        "verdict_reasoning": verdict_reasoning,
        "supporting_invocation_ids": supporting_invocation_ids,
        "invocation_id": invocation_id,
    }

    # --- Audit logging ------------------------------------------------------
    elapsed_ms = (time.monotonic() - t_start) * 1000
    examiner = os.environ.get("CASEFILE_EXAMINER", "unknown")
    sources_present = [
        sr.source for sr in (amcache, prefetch, memory, mft) if sr.present
    ]
    audit_log(
        tool="correlate_evidence",
        invocation_id=invocation_id,
        cmd=f"correlate_evidence(process_name={process_name!r})",
        returncode=0,
        stdout_lines=0,
        stderr_excerpt="",
        parsed_record_count=len(sources_present) or 1,
        duration_ms=round(elapsed_ms),
        examiner=examiner,
        extra={
            "params": {
                "process_name": process_name,
                "case_dir": resolved_case_dir,
            },
            "verdict": verdict,
            "sources_present": sources_present,
        },
    )

    return result
