"""
Shared utilities for casefile tool functions.

audit_log()   — Appends one JSONL record to audit/mcp.jsonl for every invocation.
run_tool()    — Runs a subprocess, captures stdout/stderr, logs the invocation,
                raises on non-zero exit. Never returns raw output to callers —
                callers must parse before surfacing to LLM.
"""

import json
import os
import subprocess
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Audit log location — follows CASEFILE_CASE_DIR if set, else repo root.
# This allows ralph.sh to direct audit output to the active case directory.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT_FILE  = _REPO_ROOT / "audit" / "mcp.jsonl"  # module-level fallback


def _audit_file() -> Path:
    """Resolve audit log path at call time.

    If AUDIT_FILE has been monkeypatched (e.g. in tests), use it directly.
    Otherwise read CASEFILE_CASE_DIR env var so the MCP server writes to
    the active case directory when invoked by ralph.sh, falling back to the
    repo-root audit/ dir for dev/test runs where CASEFILE_CASE_DIR is unset.
    """
    _default = _REPO_ROOT / "audit" / "mcp.jsonl"
    if AUDIT_FILE != _default:
        # Monkeypatched in tests — honour the override.
        return AUDIT_FILE
    case_dir = os.environ.get("CASEFILE_CASE_DIR", "")
    if case_dir:
        return Path(case_dir).resolve() / "audit" / "mcp.jsonl"
    return AUDIT_FILE

# Sentinel used when CASEFILE_EXAMINER env var is not set.
# Overridden at runtime — never hardcode examiner identity in tool calls.
_DEFAULT_EXAMINER = "casefile"


def audit_log(
    *,
    tool: str,
    invocation_id: str,
    cmd: str,
    returncode: int,
    stdout_lines: int,
    stderr_excerpt: str,
    parsed_record_count: int,
    duration_ms: int,
    examiner: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """Append one structured JSONL record to audit/mcp.jsonl.

    examiner is read from CASEFILE_EXAMINER env var, defaulting to "casefile".
    """
    if examiner is None:
        examiner = os.environ.get("CASEFILE_EXAMINER", _DEFAULT_EXAMINER)
    _af = _audit_file()
    _af.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "invocation_id": invocation_id,
        "tool": tool,
        "examiner": examiner,
        "cmd": cmd,
        "returncode": returncode,
        "stdout_lines": stdout_lines,
        "stderr_excerpt": stderr_excerpt[:500] if stderr_excerpt else "",
        "parsed_record_count": parsed_record_count,
        "duration_ms": duration_ms,
    }
    if extra:
        record.update(extra)
    with _af.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def run_tool(cmd: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Run cmd as a subprocess. Capture stdout and stderr.
    Raises RuntimeError if returncode != 0.
    Returns the CompletedProcess — caller must parse stdout themselves.
    """
    result = subprocess.run(
        shlex.split(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Tool exited {result.returncode}.\n"
            f"CMD: {cmd}\n"
            f"STDERR: {result.stderr[:1000]}"
        )
    return result
