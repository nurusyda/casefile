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

# Audit log location — relative to repo root regardless of CWD
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT_FILE  = _REPO_ROOT / "audit" / "mcp.jsonl"

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
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
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
    with AUDIT_FILE.open("a", encoding="utf-8") as fh:
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
