"""Hayabusa EVTX threat detection tool.

Runs hayabusa csv-timeline against an EVTX directory and returns
structured alert data with Tier 2 grounding support.

MCP tool: parse_hayabusa(evtx_dir, output_path, min_level, rule_title_filter)
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mcp_server.tools._shared import audit_log

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HAYABUSA_BIN = shutil.which("hayabusa") or "/usr/local/bin/hayabusa"
RULES_DIR = "/opt/hayabusa-rules"
RULES_CONFIG = "/opt/hayabusa-rules/config"

_LEVEL_ORDER = {
    "critical": 5,
    "crit": 5,
    "high": 4,
    "med": 3,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}

_LEVEL_CANONICAL = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}

# Hayabusa outputs abbreviated level names — map back to canonical
_HAYABUSA_LEVEL_MAP = {
    "crit": "critical",
    "high": "high",
    "med": "medium",
    "low": "low",
    "info": "informational",
}


class HayabusaToolError(Exception):
    """Raised when hayabusa execution or parsing fails."""


def _analysis_dir() -> Path:
    """Return the analysis output directory (monkeypatchable in tests)."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    return repo_root / "analysis"


def _default_output_path(analysis_dir: Path) -> Path:
    """Return a timestamped default CSV path under analysis/hayabusa/."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = analysis_dir / "hayabusa"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"hayabusa_{ts}.csv"


def _level_rank(level_str: str) -> int:
    """Return numeric rank for a level string (handles hayabusa abbreviations)."""
    return _LEVEL_ORDER.get(level_str.lower(), 0)


def _canonical_level(level_str: str) -> str:
    """Normalise hayabusa level abbreviation to canonical name."""
    return _HAYABUSA_LEVEL_MAP.get(level_str.lower(), level_str.lower())


def _run_hayabusa(evtx_dir: str, output_path: Path) -> tuple[int, str, str]:
    """Run hayabusa csv-timeline, return (returncode, stdout, stderr)."""
    cmd = [
        HAYABUSA_BIN,
        "csv-timeline",
        "--directory", evtx_dir,
        "--rules", RULES_DIR,
        "--rules-config", RULES_CONFIG,
        "--output", str(output_path),
        "--no-wizard",
        "--quiet",
        "--clobber",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError as exc:
        raise HayabusaToolError(
            f"hayabusa binary not found at {HAYABUSA_BIN}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HayabusaToolError("hayabusa timed out after 600s") from exc


def _parse_csv(
    csv_path: Path,
    min_level: str,
    rule_title_filter: Optional[str],
) -> dict:
    """Parse hayabusa CSV, filter by level and optional rule title substring.

    Returns a dict with keys:
        total_events, by_level, high_and_critical, top_rules
    """
    min_rank = _level_rank(min_level)
    by_level: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    high_and_critical: list[dict] = []
    rule_counts: dict[str, dict] = {}  # rule_title -> {count, level}
    total_events = 0

    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            total_events += 1
            raw_level = (row.get("Level") or "").strip().lower()
            canonical = _canonical_level(raw_level)
            by_level[canonical] = by_level.get(canonical, 0) + 1

            rule_title = (row.get("RuleTitle") or "").strip()

            # Track rule counts for top_rules (apply min_level filter here)
            if _level_rank(raw_level) >= min_rank:
                if rule_title_filter is None or rule_title_filter.lower() in rule_title.lower():
                    if rule_title not in rule_counts:
                        rule_counts[rule_title] = {"count": 0, "level": canonical}
                    rule_counts[rule_title]["count"] += 1

            # Collect all high + critical rows (regardless of min_level filter)
            if _level_rank(raw_level) >= _level_rank("high"):
                if rule_title_filter is None or rule_title_filter.lower() in rule_title.lower():
                    high_and_critical.append({
                        "timestamp": (row.get("Timestamp") or "").strip(),
                        "rule_title": rule_title,
                        "level": canonical,
                        "computer": (row.get("Computer") or "").strip(),
                        "channel": (row.get("Channel") or "").strip(),
                        "event_id": _safe_int(row.get("EventID")),
                        "record_id": _safe_int(row.get("RecordID")),
                        "details": (row.get("Details") or "").strip(),
                        "extra_field_info": (row.get("ExtraFieldInfo") or "").strip(),
                        "rule_id": (row.get("RuleID") or "").strip(),
                    })

    top_rules = sorted(
        [
            {"rule_title": k, "count": v["count"], "level": v["level"]}
            for k, v in rule_counts.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return {
        "total_events": total_events,
        "by_level": by_level,
        "high_and_critical": high_and_critical,
        "top_rules": top_rules,
    }


def _safe_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Public MCP tool
# ---------------------------------------------------------------------------

def parse_hayabusa(
    evtx_dir: str,
    output_path: Optional[str] = None,
    min_level: str = "low",
    rule_title_filter: Optional[str] = None,
) -> dict:
    """Run Hayabusa Sigma-rule detection against an EVTX directory.

    Args:
        evtx_dir: Path to directory containing .evtx files.
        output_path: Where to save the CSV timeline. Defaults to
            analysis/hayabusa/hayabusa_<timestamp>.csv
        min_level: Minimum alert level to include in top_rules summary.
            One of: informational, low, medium, high, critical.
            high_and_critical rows are always returned regardless of this setting.
        rule_title_filter: Optional substring to filter rule titles.

    Returns:
        dict with keys:
            csv_path, total_events, by_level, high_and_critical,
            top_rules, high_crit_count, invocation_id, analyst_note

    Raises:
        HayabusaToolError: If hayabusa binary is missing or returns non-zero.
        ValueError: If evtx_dir does not exist.
    """
    invocation_id = str(uuid.uuid4())
    examiner = os.environ.get("CASEFILE_EXAMINER", "casefile")
    t_start = time.monotonic()

    # --- Input validation ---
    evtx_path = Path(evtx_dir)
    if not evtx_path.exists():
        raise ValueError(f"evtx_dir does not exist: {evtx_dir}")
    if evtx_path.is_symlink():
        raise ValueError(f"evtx_dir must not be a symlink: {evtx_dir}")

    # Normalise min_level
    min_level_norm = _canonical_level(min_level)
    if min_level_norm not in _LEVEL_ORDER:
        raise ValueError(
            f"Invalid min_level '{min_level}'. "
            f"Choose from: informational, low, medium, high, critical"
        )

    # Resolve output path
    analysis_dir = _analysis_dir()
    csv_out = Path(output_path) if output_path else _default_output_path(analysis_dir)
    csv_out.parent.mkdir(parents=True, exist_ok=True)

    stderr_excerpt = ""
    returncode = -1
    result: dict = {}

    try:
        returncode, stdout, stderr = _run_hayabusa(evtx_dir, csv_out)
        stderr_excerpt = stderr[:500] if stderr else ""

        if returncode != 0 and not csv_out.exists():
            raise HayabusaToolError(
                f"hayabusa exited {returncode}. stderr: {stderr_excerpt}"
            )

        if not csv_out.exists():
            raise HayabusaToolError(
                f"hayabusa completed but output CSV not found at {csv_out}"
            )

        parsed = _parse_csv(csv_out, min_level_norm, rule_title_filter)
        high_crit_count = parsed["by_level"]["critical"] + parsed["by_level"]["high"]

        result = {
            "csv_path": str(csv_out),
            "total_events": parsed["total_events"],
            "by_level": parsed["by_level"],
            "high_and_critical": parsed["high_and_critical"],
            "top_rules": parsed["top_rules"],
            "high_crit_count": high_crit_count,
            "invocation_id": invocation_id,
            "analyst_note": (
                f"{high_crit_count} high/critical detections across "
                f"{parsed['total_events']} total events. "
                f"Tier 2 grounding: verify rule_title and timestamp "
                f"against {csv_out}."
            ),
        }

        duration_ms = int((time.monotonic() - t_start) * 1000)

        try:
            audit_log(
                tool="parse_hayabusa",
                invocation_id=invocation_id,
                cmd=f"hayabusa csv-timeline --directory {evtx_dir}",
                returncode=returncode,
                stdout_lines=parsed["total_events"],
                stderr_excerpt=stderr_excerpt,
                parsed_record_count=parsed["total_events"],
                duration_ms=duration_ms,
                examiner=examiner,
                extra={
                    "evtx_dir": evtx_dir,
                    "csv_path": str(csv_out),
                    "csv_files": [str(csv_out)],   # Tier 2 grounding key
                    "min_level": min_level_norm,
                    "high_crit_count": high_crit_count,
                    "by_level": parsed["by_level"],
                },
            )
        except Exception:
            pass  # Logging failure must never mask the real result

        return result

    except HayabusaToolError as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        try:
            audit_log(
                tool="parse_hayabusa",
                invocation_id=invocation_id,
                cmd=f"hayabusa csv-timeline --directory {evtx_dir}",
                returncode=returncode,
                stdout_lines=0,
                stderr_excerpt=stderr_excerpt[:200],
                parsed_record_count=0,
                duration_ms=duration_ms,
                examiner=examiner,
                extra={"error": str(exc)},
            )
        except Exception:
            pass
        raise
    except Exception as exc:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        try:
            audit_log(
                tool="parse_hayabusa",
                invocation_id=invocation_id,
                cmd=f"hayabusa csv-timeline --directory {evtx_dir}",
                returncode=returncode,
                stdout_lines=0,
                stderr_excerpt=stderr_excerpt[:200],
                parsed_record_count=0,
                duration_ms=duration_ms,
                examiner=examiner,
                extra={"error": str(exc)},
            )
        except Exception:
            pass
        raise HayabusaToolError(str(exc)) from exc
