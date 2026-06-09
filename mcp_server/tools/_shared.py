"""
Shared utilities for casefile tool functions.

audit_log()   — Appends one JSONL record to audit/mcp.jsonl for every invocation.
run_tool()    — Runs a subprocess, captures stdout/stderr, logs the invocation,
                raises on non-zero exit. Never returns raw output to callers —
                callers must parse before surfacing to LLM.
"""

import json
import ntpath
import os
import subprocess
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

#: Hashable key function for content-based entry deduplication.
#: Each tool module supplies its own key_fn based on its CSV schema.
EntryKeyFn = Callable[[dict[str, Any]], Any]


class PathConfinementError(ValueError):
    """Raised when a path escapes CASEFILE_CASE_ROOT."""


class MemoryImageNotFoundError(FileNotFoundError):
    """Raised when CASEFILE_MEMORY_IMAGE is set but the file does not exist.

    Distinct from the "no image configured" case so callers can differentiate
    between "not set" (benign) and "set but invalid" (misconfiguration).
    """


def _discover_memory_image(case_path: Path) -> Optional[Path]:
    """Discover the memory image file for a case directory.

    Resolution order:
      1. ``CASEFILE_MEMORY_IMAGE`` env var — absolute path, confined under
         ``CASEFILE_CASE_ROOT`` when set.
      2. First sorted ``*.img`` / ``*.mem`` / ``*.vmem`` / ``*.raw`` / ``*.dmp`` /
         ``*.001`` (case-insensitive) found in ``case_path.parent``.

    Returns:
        Resolved ``Path`` to the memory image, or ``None`` if no image found.

    Raises:
        PathConfinementError: if the resolved path escapes CASEFILE_CASE_ROOT.
    """
    explicit_image = os.environ.get("CASEFILE_MEMORY_IMAGE")
    if explicit_image:
        image_path = Path(os.path.expanduser(explicit_image)).resolve()
        _enforce_case_root(image_path)
        if not image_path.is_file():
            raise MemoryImageNotFoundError(
                f"CASEFILE_MEMORY_IMAGE is set but the file does not exist: "
                f"{image_path}"
            )
        return image_path

    # Auto-discover from parent directory
    _img_exts = (".img", ".mem", ".vmem", ".raw", ".dmp", ".001")
    img_search_dir = case_path.parent
    try:
        for ext in _img_exts:
            images = sorted(
                p for p in img_search_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ext
            )
            if images:
                _enforce_case_root(images[0])
                return images[0]
    except (PermissionError, OSError):
        pass
    return None


def _enforce_case_root(path: Path) -> None:
    """Raise PathConfinementError if path escapes CASEFILE_CASE_ROOT (when set).

    When CASEFILE_CASE_ROOT is unset the function is a no-op (dev/test mode).
    Security-sensitive: all parser tools delegate path confinement here.
    """
    case_root_env = os.environ.get("CASEFILE_CASE_ROOT")
    if not case_root_env:
        if "CASEFILE_CASE_ROOT" in os.environ:
            raise PathConfinementError(
                "CASEFILE_CASE_ROOT is set but empty — path confinement cannot be applied"
            )
        return
    root = Path(case_root_env).resolve()
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise PathConfinementError(f"path escapes case root: {path}") from exc

def canonical_dir(path: str) -> str:
    """Normalise a Windows path for directory comparison.

    Strips drive letters (``C:``), device prefixes
    (``\\\\Device\\\\HarddiskVolume\\\\d+\\\\``), and leading separators so that
    Amcache, Prefetch, and MFT paths are comparable.

        Amcache:   c:\\\\windows\\\\system32\\\\csrss.exe  → windows\\\\system32
        Prefetch:  \\\\Device\\\\HarddiskVolume1\\\\Windows\\\\System32\\\\csrss.exe
                   → windows\\\\system32
        MFT:       \\\\windows\\\\system32\\\\csrss.exe    → windows\\\\system32
    """
    if not path:
        return ""
    p = path.lower().replace("/", "\\")
    # Strip \\\\Device\\\\HarddiskVolume\\\\d+\\\\
    if p.startswith("\\device\\harddiskvolume"):
        parts = p.split("\\", 3)
        p = parts[3] if len(parts) > 3 else p
    # Strip drive letter
    if len(p) >= 2 and p[1] == ":":
        p = p[2:]
    # Extract parent directory and normalise
    return ntpath.dirname(p).rstrip("\\").lstrip("\\")


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
        target = Path(case_dir).resolve() / "audit" / "mcp.jsonl"
        # Prevent writes into the read-only evidence mount
        _evidence = Path("/mnt/evidence").resolve()
        if _evidence in target.parents or target == _evidence:
            raise ValueError(
                f"audit log path must not be inside /mnt/evidence: {target}"
            )
        return target
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
        collisions = set(record) & set(extra)
        if collisions:
            raise ValueError(
                f"audit_log extra dict collides with standard fields: {sorted(collisions)}"
            )
        record.update(extra)
    with _af.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
def _load_case_iocs() -> tuple[list[str], list[str]]:
    """Load case-specific IOC lists from prd.json in CASEFILE_CASE_DIR.

    Returns (known_iocs, suspicious_patterns). Both lists are empty when
    prd.json is absent or the keys are missing — parsers degrade gracefully
    to generic suspicious-path detection only.

    Keys expected in prd.json:
      "known_iocs"          — filenames / short strings for MFT IOC matching
      "suspicious_patterns" — substring patterns for registry value matching
    """
    case_dir = os.environ.get("CASEFILE_CASE_DIR", "")
    if not case_dir:
        return [], []
    prd = Path(case_dir) / "prd.json"
    if not prd.exists():
        return [], []
    try:
        data = json.loads(prd.read_text(encoding="utf-8"))
        known_iocs = [str(s) for s in data.get("known_iocs", [])]
        suspicious_patterns = [str(s) for s in data.get("suspicious_patterns", [])]
        return known_iocs, suspicious_patterns
    except (json.JSONDecodeError, OSError):
        return [], []


def _cap_entries_keep_suspicious(
    entries: list[dict[str, Any]],
    suspicious: list[dict[str, Any]],
    cap: int,
    key_fn: EntryKeyFn,
    sort_key_fn: Optional[Callable[[dict[str, Any]], Any]] = None,
    sort_reverse: bool = False,
) -> tuple[list[dict[str, Any]], bool]:
    """Cap entries to *cap*, keeping suspicious entries first.

    Uses a content-based key function to match suspicious entries against
    their counterparts in the main entries list.  This is the canonical
    capping implementation — every parser tool that produces a flat entry
    list should route through this function rather than duplicating the
    dedup/slice logic.

    **Design contract — why content keys, not id():**
    ``_flag_suspicious()`` returns **copies** of flagged entries with
    ``suspicion_reasons`` / ``confidence`` keys added.  Because these are
    copies, Python ``id()`` identity cannot be used for dedup.  Instead the
    caller passes a *key_fn* that extracts a stable, hashable identity from
    an entry dict (e.g. ``(timestamp_utc, event_id, record_number)`` for
    EvtxECmd entries).  The key MUST be unique-enough within one tool run
    to avoid false dedup collisions.

    Args:
        entries:     Full list of parsed entries (chronological / last-write order).
        suspicious:  Flagged entries — COPIES returned by ``_flag_suspicious()``.
        cap:         Maximum entries to return.
        key_fn:      ``entry -> hashable`` used to match suspicious entries to
                     their source entries in ``entries``.
        sort_key_fn: If provided, the output list is sorted by this key.
        sort_reverse: Passed to ``list.sort(reverse=...)``.

    Returns:
        ``(capped_entries, truncated_suspicious)`` where
        ``truncated_suspicious`` is ``True`` when the number of suspicious
        entries (including keyless entries force-appended in the third pass)
        exceeds *cap* (analyst note recommended).

        Suspicious entries whose *key_fn* raises are **not** silently
        dropped — they are appended directly to the suspicious partition
        so that ``suspicion_reasons`` / ``confidence`` metadata is preserved
        even when the entry cannot be matched by content key.
    """
    total = len(entries)
    if total <= cap:
        return entries, False

    # Build a content-key set from suspicious entries.
    # Entries whose key_fn raises cannot be matched by key, so we force them
    # directly into susp_out to avoid silently dropping flagged evidence.
    susp_keys: set[Any] = set()
    for se in suspicious:
        try:
            susp_keys.add(key_fn(se))
        except (KeyError, TypeError, IndexError):
            pass  # will be force-appended to susp_out in the third pass below

    # Partition into suspicious and non-suspicious using content keys
    susp_out: list[dict[str, Any]] = []
    non_susp: list[dict[str, Any]] = []
    seen_susp: set[Any] = set()
    for e in entries:
        try:
            k = key_fn(e)
        except (KeyError, TypeError, IndexError):
            non_susp.append(e)
            continue
        if k in susp_keys:
            susp_out.append(e)
            seen_susp.add(k)
        else:
            non_susp.append(e)

    # Build a key→copy map from *suspicious* entries (the copies that carry
    # suspicion_reasons/confidence metadata), then patch susp_out to replace
    # matched originals with their flagged copies so metadata is preserved.
    copy_map: dict[Any, dict[str, Any]] = {}
    for se in suspicious:
        try:
            k = key_fn(se)
            copy_map.setdefault(k, se)  # first copy wins
        except (KeyError, TypeError, IndexError):
            pass

    for i, e in enumerate(susp_out):
        try:
            k = key_fn(e)
            if k in copy_map:
                susp_out[i] = copy_map[k]
        except (KeyError, TypeError, IndexError):
            pass

    # Append suspicious entries whose keys could not be computed — these are
    # un-matchable copies; they carry suspicion_reasons / confidence metadata
    # that must not be silently dropped.
    for se in suspicious:
        try:
            k = key_fn(se)
        except (KeyError, TypeError, IndexError):
            susp_out.append(se)
            continue
        if k not in seen_susp:
            susp_out.append(se)

    truncated_suspicious = len(susp_out) > cap
    if truncated_suspicious:
        susp_out = susp_out[:cap]

    remaining = max(0, cap - len(susp_out))
    entries_out = susp_out + non_susp[:remaining]

    if sort_key_fn is not None:
        entries_out.sort(key=sort_key_fn, reverse=sort_reverse)

    return entries_out, truncated_suspicious


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
