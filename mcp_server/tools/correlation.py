"""Correlation tool — composition layer over existing parsers.

Block 8: correlate_evidence() calls parse_amcache, parse_prefetch,
parse_memory, and parse_mft to produce a cross-source verdict.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp_server.tools._shared import audit_log


class CorrelationToolError(Exception):
    """Typed error for the correlation tool."""


# Verdict Constants
VERDICTS = frozenset({
    "CONFIRMED_RUNNING",
    "CONFIRMED_HISTORICAL",
    "INSTALLED_NEVER_RAN",
    "MEMORY_ONLY",
    "NOT_FOUND",
})


@dataclass
class SourceResult:
    """Normalised result from a single parser source."""
    source: str  # "amcache" | "prefetch" | "memory" | "mft"
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
            d.update(self.details)
        if self.error is not None:
            d["error"] = self.error
        return d


def _decide_verdict(
    amcache: SourceResult,
    prefetch: SourceResult,
    memory: SourceResult,
    mft: SourceResult,
) -> tuple[str, str]:
    """Pure function to determine verdict based on source presence."""
    in_memory = memory.present
    has_execution = amcache.present or prefetch.present
    on_disk = mft.present

    if in_memory:
        if has_execution or on_disk:
            reason = (
                "Process found in live memory. Disk artifacts (MFT/Amcache/Prefetch) "
                "confirm the file exists or has historical execution data."
            )
            return "CONFIRMED_RUNNING", reason
        else:
            reason = (
                "Process found ONLY in live memory. No disk artifacts found. "
                "May indicate process injection or fileless execution."
            )
            return "MEMORY_ONLY", reason

    if has_execution:
        return (
            "CONFIRMED_HISTORICAL",
            "Process not in memory, but found in Amcache/Prefetch. Historically executed."
        )

    if on_disk:
        return (
            "INSTALLED_NEVER_RAN",
            "File exists in MFT but no evidence of execution in memory or registry/logs."
        )

    return "NOT_FOUND", "No evidence of this process across any analyzed source."


# Parser Stubs (To be wired in Commits 2 & 3)
def _call_parse_amcache(process_name: str, case_dir: str) -> SourceResult:
    return SourceResult(source="amcache", present=False, error="not_wired")

def _call_parse_prefetch(process_name: str, case_dir: str) -> SourceResult:
    return SourceResult(source="prefetch", present=False, error="not_wired")

def _call_parse_memory(process_name: str, case_dir: str) -> SourceResult:
    return SourceResult(source="memory", present=False, error="not_wired")

def _call_parse_mft(process_name: str, case_dir: str) -> SourceResult:
    return SourceResult(source="mft", present=False, error="not_wired")


def correlate_evidence(
    process_name: str,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Main entry point for cross-source correlation."""
    invocation_id = f"correlation_{uuid.uuid4().hex[:12]}"
    t_start = time.monotonic()

    # Validation
    if not process_name or not isinstance(process_name, str):
        raise CorrelationToolError("process_name must be a non-empty string")
    
    process_name = process_name.strip()
    resolved_case_dir = case_dir or os.environ.get("CASEFILE_CASE_DIR", "")
    if not resolved_case_dir:
        raise CorrelationToolError("case_dir must be provided or CASEFILE_CASE_DIR set")

    # Orchestration
    amcache = _call_parse_amcache(process_name, resolved_case_dir)
    prefetch = _call_parse_prefetch(process_name, resolved_case_dir)
    memory = _call_parse_memory(process_name, resolved_case_dir)
    mft = _call_parse_mft(process_name, resolved_case_dir)

    verdict, reasoning = _decide_verdict(amcache, prefetch, memory, mft)

    supporting_ids = [
        sr.invocation_id for sr in (amcache, prefetch, memory, mft) if sr.invocation_id
    ]

    result = {
        "process_name": process_name,
        "amcache": amcache.to_dict(),
        "prefetch": prefetch.to_dict(),
        "memory": memory.to_dict(),
        "mft": mft.to_dict(),
        "verdict": verdict,
        "verdict_reasoning": reasoning,
        "supporting_invocation_ids": supporting_ids,
        "invocation_id": invocation_id,
    }

    # Audit Logging
    audit_log(
        tool="correlate_evidence",
        invocation_id=invocation_id,
        cmd=f"correlate_evidence(process_name={process_name})",
        returncode=0,
        stdout_lines=0,
        stderr_excerpt="",
        parsed_record_count=1,
        duration_ms=round((time.monotonic() - t_start) * 1000),
        examiner=os.environ.get("CASEFILE_EXAMINER", "unknown"),
        extra={"verdict": verdict, "process_name": process_name}
    )

    return result
