"""
memory.py — parse_memory() MCP tool

Wraps Volatility3 plugins against memory images and returns structured JSON.

Design contract (the "high ICL" rule):
  • LLM never sees raw subprocess stdout.
  • Plugin name is validated against a strict allowlist before any subprocess runs.
  • Image path is validated to exist, be a regular file, and not a symlink (forensic hygiene).
  • Results are cached on disk keyed by (sha256_short, plugin) — Volatility runs are slow.
  • Every invocation appends one record to audit/mcp.jsonl.

Inference Constraint Level: HIGH
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_server.tools._shared import audit_log


# ── Allowed plugins ─────────────────────────────────────────────────────────────
# Read-only plugins only. windows.dumpfiles, windows.memmap (with --dump),
# and any plugin that writes files are intentionally excluded.
ALLOWED_PLUGINS: frozenset[str] = frozenset({
    "windows.pslist",
    "windows.netscan",
    "windows.cmdline",
    "windows.malfind",
    "windows.dlllist",
    "windows.pstree",
    "windows.handles",
})

# Volatility binary location — overridable for tests
VOL_BIN = os.environ.get("CASEFILE_VOL_BIN", "/usr/local/bin/vol")

# Subprocess timeout. windows.netscan against a Windows Server image can take 2+ min.
DEFAULT_TIMEOUT_SEC = 600

# Cache schema version — bump if the structured output schema changes.
CACHE_SCHEMA_VERSION = 1


# ── Errors raised back to the caller (and logged) ───────────────────────────────
class MemoryToolError(RuntimeError):
    """Raised when parse_memory cannot complete safely. Always logged."""


# ── Path / fingerprint helpers ──────────────────────────────────────────────────

def _validate_image_path(image_path: str) -> Path:
    """
    Resolve and validate the memory image path.
    Must exist, be a regular file, not a symlink. Forensic hygiene rule.
    """
    p = Path(image_path).expanduser()
    if p.is_symlink():
        raise MemoryToolError(f"Image path is a symlink (not allowed): {image_path}")
    p = p.resolve(strict=False)
    if not p.exists():
        raise MemoryToolError(f"Memory image not found: {image_path}")
    if not p.is_file():
        raise MemoryToolError(f"Memory image is not a regular file: {image_path}")
    return p


def _sha256_of_file(path: Path, chunk: int = 1024 * 1024) -> str:
    """
    Stream sha256 — memory images can be multi-GB.
    Writes a .sha256 sidecar file next to the image after first hash so
    subsequent calls skip re-streaming (900MB image takes ~10s otherwise).
    """
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.exists():
        cached_hash = sidecar.read_text(encoding="utf-8").strip()
        if len(cached_hash) == 64 and all(c in "0123456789abcdef" for c in cached_hash):
            return cached_hash
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    digest = h.hexdigest()
    # Never write sidecar into evidence paths — forensic hygiene (CLAUDE.md Law 1)
    if not any(str(path).startswith(prefix) for prefix in _EVIDENCE_PREFIXES):
        try:
            sidecar.write_text(digest, encoding="utf-8")
        except OSError:
            pass  # sidecar is optional
    return digest


def _case_dir() -> Path:
    raw = os.environ.get("CASEFILE_CASE_DIR", str(Path.home() / "cases" / "active"))
    return Path(raw).expanduser().resolve()


def _cache_path(sha256_short: str, plugin: str) -> Path:
    return _case_dir() / "memory_cache" / sha256_short / f"{plugin}.json"


# Evidence paths that must remain read-only (matches CLAUDE.md Law 1)
_EVIDENCE_PREFIXES = ("/cases/", "/mnt/", "/media/", "/evidence/")


# ── Volatility output parsers ───────────────────────────────────────────────────

def _parse_volatility_text(stdout: str) -> list[dict[str, Any]]:
    """
    Volatility3 default output is TSV-like: header line, blank line, rows.
    We parse it ourselves rather than relying on `-r json` because some plugins
    omit fields under `-r json` and we want consistent structure.
    Each row becomes a dict keyed by header column name.
    """
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    # Skip Volatility framework banner lines
    while lines and not lines[0].startswith(("PID", "Offset", "Process", "PPID", "ImageFileName")):
        lines.pop(0)
    if not lines:
        return []

    header = [h.strip() for h in lines[0].split("\t")]
    if len(header) < 2:
        # Fallback: split on 2+ whitespace
        import re
        header = re.split(r"\s{2,}", lines[0].strip())

    records: list[dict[str, Any]] = []
    for raw in lines[1:]:
        cells = raw.split("\t")
        if len(cells) < 2:
            import re
            cells = re.split(r"\s{2,}", raw.strip())
        # Pad / truncate cells to header length
        cells = (cells + [""] * len(header))[: len(header)]
        rec = {header[i]: cells[i].strip() for i in range(len(header))}
        records.append(rec)
    return records


# ── Main entry point ────────────────────────────────────────────────────────────

def parse_memory(
    image_path: str,
    plugin: str = "windows.pslist",
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    use_cache: bool = True,
) -> dict[str, Any]:
    """
    Run a Volatility3 plugin against a memory image and return structured results.

    Parameters
    ----------
    image_path : str
        Absolute path to the memory image (.img / .raw / .mem / .vmem).
        Symlinks are rejected.
    plugin : str
        Volatility plugin name. Must be in ALLOWED_PLUGINS.
    timeout_sec : int
        Subprocess timeout. Default 600s.
    use_cache : bool
        If True (default), reuse cached results for the same (sha256, plugin) pair.

    Returns
    -------
    dict with keys:
        invocation_id, tool, plugin, image_path, image_sha256,
        run_ts_utc, total_records, records, output_dir,
        duration_ms, cached, error, analyst_note
    """
    invocation_id = f"mem-{uuid.uuid4().hex[:8]}"
    t_start = time.monotonic()

    # ── Validate plugin ──
    if plugin not in ALLOWED_PLUGINS:
        msg = (
            f"Plugin '{plugin}' is not in the allowlist. "
            f"Allowed: {sorted(ALLOWED_PLUGINS)}"
        )
        audit_log(
            tool="Volatility3",
            invocation_id=invocation_id,
            cmd=f"<rejected: invalid plugin {plugin!r}>",
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=msg,
            parsed_record_count=0,
            duration_ms=int((time.monotonic() - t_start) * 1000),
            extra={"plugin_requested": plugin, "rejection_reason": "plugin_not_allowed"},
        )
        raise MemoryToolError(msg)

    # ── Validate image path ──
    try:
        image = _validate_image_path(image_path)
    except MemoryToolError as e:
        audit_log(
            tool="Volatility3",
            invocation_id=invocation_id,
            cmd="<rejected: bad image path>",
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=str(e),
            parsed_record_count=0,
            duration_ms=int((time.monotonic() - t_start) * 1000),
            extra={"plugin": plugin, "image_path_input": image_path,
                   "rejection_reason": "invalid_image_path"},
        )
        raise

    image_sha256 = _sha256_of_file(image)
    sha_short = image_sha256[:16]
    cache_file = _cache_path(sha_short, plugin)

    # ── Cache hit ──
    if use_cache and cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if cached.get("schema_version") == CACHE_SCHEMA_VERSION:
                duration_ms = int((time.monotonic() - t_start) * 1000)
                audit_log(
                    tool="Volatility3",
                    invocation_id=invocation_id,
                    cmd=f"<cache_hit:{cache_file}>",
                    returncode=0,
                    stdout_lines=0,
                    stderr_excerpt="",
                    parsed_record_count=len(cached.get("records", [])),
                    duration_ms=duration_ms,
                    extra={
                        "plugin": plugin,
                        "image_sha256": image_sha256,
                        "cached": True,
                    },
                )
                cached["invocation_id"] = invocation_id
                cached["cached"] = True
                cached["duration_ms"] = duration_ms
                return cached
        except (json.JSONDecodeError, OSError):
            # Corrupt cache — ignore and re-run
            pass

    # ── Run Volatility ──
    cmd = f"{VOL_BIN} -f {shlex.quote(str(image))} {plugin}"
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as err:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="Volatility3",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=f"timeout after {timeout_sec}s",
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"plugin": plugin, "image_sha256": image_sha256, "timeout": True},
        )
        raise MemoryToolError(f"Volatility timed out after {timeout_sec}s") from err
    except FileNotFoundError as err:
        # vol binary missing — distinct error so callers can detect this case
        duration_ms = int((time.monotonic() - t_start) * 1000)
        audit_log(
            tool="Volatility3",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=-1,
            stdout_lines=0,
            stderr_excerpt=f"vol binary not found: {VOL_BIN}",
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"plugin": plugin, "image_sha256": image_sha256,
                   "rejection_reason": "vol_binary_missing"},
        )
        raise MemoryToolError(f"Volatility binary not found at {VOL_BIN}: {err}") from err

    if result.returncode != 0:
        duration_ms = int((time.monotonic() - t_start) * 1000)
        stderr_excerpt = (result.stderr or "")[:500]
        audit_log(
            tool="Volatility3",
            invocation_id=invocation_id,
            cmd=cmd,
            returncode=result.returncode,
            stdout_lines=result.stdout.count("\n") if result.stdout else 0,
            stderr_excerpt=stderr_excerpt,
            parsed_record_count=0,
            duration_ms=duration_ms,
            extra={"plugin": plugin, "image_sha256": image_sha256},
        )
        raise MemoryToolError(
            f"Volatility exited {result.returncode}: {stderr_excerpt}"
        )

    # ── Parse ──
    records = _parse_volatility_text(result.stdout)
    duration_ms = int((time.monotonic() - t_start) * 1000)

    payload: dict[str, Any] = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "invocation_id": invocation_id,
        "tool": "Volatility3",
        "plugin": plugin,
        "image_path": str(image),
        "image_sha256": image_sha256,
        "run_ts_utc": datetime.now(timezone.utc).isoformat(),
        "total_records": len(records),
        "records": records,
        "duration_ms": duration_ms,
        "cached": False,
        "error": None,
        "analyst_note": (
            "Memory artifacts confirm a process WAS RUNNING at the time of capture. "
            "Absence does NOT confirm a process never ran — it may have exited before capture. "
            "PIDs reused by Windows; correlate by ImageFileName + CreateTime, not PID alone. "
            "Network connections in CLOSED/CLOSE_WAIT state are historical, not live."
        ),
    }

    # ── Cache write ──
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as e:
        # Cache write failure is non-fatal
        payload["cache_write_error"] = str(e)

    # ── Audit ──
    audit_log(
        tool="Volatility3",
        invocation_id=invocation_id,
        cmd=cmd,
        returncode=0,
        stdout_lines=result.stdout.count("\n") if result.stdout else 0,
        stderr_excerpt=(result.stderr or "")[:500],
        parsed_record_count=len(records),
        duration_ms=duration_ms,
        extra={
            "plugin": plugin,
            "image_sha256": image_sha256,
            "image_path": str(image),
            "cached": False,
            "cache_file": str(cache_file),
        },
    )

    return payload
