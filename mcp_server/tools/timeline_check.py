"""
timeline_check.py — Standalone MCP tool for cross-source timeline contradiction detection.

Calls the four disk/memory parsers directly to get full (unfiltered) entries,
then runs the deterministic T1–T6 contradiction detectors from
timeline_contradiction.py.  Returns ALL system-wide timeline anomalies — this
is a case-level tool, not a per-process tool (use correlate_evidence for
per-process scoping).

Unlike correlate_evidence() which filters by process_name for per-process
verdicts, this tool retrieves ALL entries from each parser so that T1
(process missing from disk) can accurately cross-reference the full memory
pslist against the full disk artifact set.
"""

from __future__ import annotations

import os
import time as _time
import uuid as _uuid
from pathlib import Path
from typing import Any

from mcp_server.tools._shared import audit_log, PathConfinementError, MemoryImageNotFoundError, _enforce_case_root, _discover_memory_image
from mcp_server.tools.amcache import parse_amcache
from mcp_server.tools.prefetch import parse_prefetch
from mcp_server.tools.memory import parse_memory
from mcp_server.tools.mft_safe import parse_mft
from mcp_server.tools.usn import parse_usn_journal
from mcp_server.tools.timeline_contradiction import detect_timeline_contradictions


def check_timeline_contradictions(
    case_dir: str,
) -> dict[str, Any]:
    """Cross-source timeline contradiction check for the entire case.

    Calls the four disk/memory parsers with NO process-name filter,
    extracts ALL entries, and runs the deterministic T1–T6 contradiction
    detectors against the full artifact set.  Returns every timeline
    anomaly found — suitable for case-wide anti-forensics triage.

    For per-process contradiction scoping, use correlate_evidence() which
    returns a filtered subset.

    Args:
        case_dir: Path to the case directory containing artifacts.

    Returns:
        Dict with keys: contradictions, contradiction_count,
        sources_checked, invocation_id.
    """
    invocation_id = str(_uuid.uuid4())
    t_start = _time.monotonic()
    _returncode = 1
    _contradiction_count = 0

    # Initialized before try so finally block can safely reference them
    # even on early returns (e.g. PathConfinementError).
    amcache_entries: list = []
    prefetch_entries: list = []
    memory_records: list = []
    mft_entries: list = []
    usn_deleted_entries: list = []

    try:
        # Resolve and confine case directory
        case_root = os.environ.get("CASEFILE_CASE_ROOT")
        if case_root:
            case_path = (Path(case_root) / case_dir).resolve()
            try:
                _enforce_case_root(case_path)
            except PathConfinementError as exc:
                return {"error": str(exc), "invocation_id": invocation_id}
        else:
            case_path = Path(case_dir).resolve()

        parser_errors: list[str] = []

        # ── Amcache ──────────────────────────────────────────────────────
        amcache_hive: Path | None = None
        for candidate in case_path.iterdir():
            if candidate.is_file() and candidate.name.lower() == "amcache.hve":
                amcache_hive = candidate
                break
        if amcache_hive is not None:
            ac_result = parse_amcache(str(amcache_hive), include_all=True)
            if ac_result.get("error"):
                parser_errors.append(f"amcache: {ac_result['error']}")
            else:
                amcache_entries = ac_result.get("entries", [])
        else:
            parser_errors.append("amcache: Amcache.hve not found")

        # ── Prefetch ─────────────────────────────────────────────────────
        pf_dir = case_path / "Prefetch"
        if pf_dir.is_dir():
            pf_result = parse_prefetch(str(pf_dir), include_all=True)
            if pf_result.get("error"):
                parser_errors.append(f"prefetch: {pf_result['error']}")
            else:
                prefetch_entries = pf_result.get("entries", [])
        else:
            parser_errors.append("prefetch: Prefetch/ not found")

        # ── Memory ───────────────────────────────────────────────────────
        try:
            image_file = _discover_memory_image(case_path)
        except MemoryImageNotFoundError as exc:
            parser_errors.append(f"memory: {exc}")
        except PathConfinementError as exc:
            return {"error": str(exc), "invocation_id": invocation_id}
        else:
            if image_file is not None:
                mem_result = parse_memory(str(image_file), plugin="windows.pslist")
                if mem_result.get("error"):
                    parser_errors.append(f"memory: {mem_result['error']}")
                else:
                    memory_records = mem_result.get("records", [])
            else:
                parser_errors.append("memory: no image found")

        # ── MFT (include_all=True — T1 needs a broad name set, not just  ──
        # suspicious entries; max_parse_rows caps memory usage on
        # multi-million-record $MFT files.  For complete coverage a
        # name_index pass would be needed, but that requires
        # parser-interface changes.) ──────────────────────────────────────
        mft_file = case_path / "MFT"
        if mft_file.exists():
            mft_result = parse_mft(str(mft_file), include_all=True, max_parse_rows=10000)
            if mft_result.get("error"):
                parser_errors.append(f"mft: {mft_result['error']}")
            else:
                mft_entries = mft_result.get("entries", [])
        else:
            parser_errors.append("mft: MFT not found")

        # ── USN Journal ($J) ────────────────────────────────────────────
        for usn_name in ("$J", "J", "UsnJrnl"):
            usn_file = case_path / usn_name
            if usn_file.is_file():
                usn_result = parse_usn_journal(str(usn_file))
                if usn_result.get("error"):
                    parser_errors.append(f"usn: {usn_result['error']}")
                else:
                    usn_deleted_entries = usn_result.get("deleted", [])
                break
        else:
            parser_errors.append("usn: $J not found")

        # ── Detect contradictions ────────────────────────────────────────
        contradictions = detect_timeline_contradictions(
            memory_pslist=memory_records,
            prefetch_entries=prefetch_entries,
            amcache_entries=amcache_entries,
            mft_entries=mft_entries,
            usn_entries=usn_deleted_entries,
        )
        _contradiction_count = len(contradictions)
        _returncode = 0

        return {
            "contradictions": contradictions,
            "contradiction_count": _contradiction_count,
            "sources_checked": ["amcache", "prefetch", "memory", "mft", "usn"],
            "parser_errors": parser_errors if parser_errors else None,
            "invocation_id": invocation_id,
        }

    finally:
        elapsed_ms = (_time.monotonic() - t_start) * 1000
        examiner = os.environ.get("CASEFILE_EXAMINER", "unknown")
        _total_parsed = (
            len(amcache_entries)
            + len(prefetch_entries)
            + len(memory_records)
            + len(mft_entries)
            + len(usn_deleted_entries)
        )
        try:
            audit_log(
                tool="check_timeline_contradictions",
                invocation_id=invocation_id,
                cmd=f"check_timeline_contradictions(case_dir={case_dir!r})",
                returncode=_returncode,
                stdout_lines=0,
                stderr_excerpt="",
                parsed_record_count=_total_parsed,
                duration_ms=round(elapsed_ms),
                examiner=examiner,
                extra={
                    "case_dir": case_dir,
                    "contradiction_count": _contradiction_count,
                },
            )
        except Exception:
            pass  # audit failure must not break the return
