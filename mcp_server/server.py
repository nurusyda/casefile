"""
find-evil-mcp — Custom MCP Server for SANS Find Evil! Hackathon
Wraps SIFT forensic tools as typed, structured Python functions.

Inference Constraint Level: HIGH
- All tool output is parsed server-side before returning to LLM
- LLM never receives raw shell output
- Every invocation is logged to audit/mcp.jsonl

Tool paths verified on Protocol SIFT (WSL2 Ubuntu 22.04), April 28 2026.
"""

import inspect
import os
from functools import wraps
from pathlib import Path
from typing import Any

# ── GAP-1 closure: network import startup check ────────────────────────────
# Static AST check — verifies at import time that no tool module contains
# blocked network imports (socket, urllib, requests, etc.).  This makes the
# "no network egress" claim architectural rather than environment-dependent.
# Dynamic importlib.import_module() calls are not caught; the OS-level sandbox
# remains the runtime backstop for those.
import ast as _ast
from pathlib import Path as _Path

_BLOCKED_IMPORTS: frozenset[str] = frozenset({
    "socket",
    "urllib",
    "urllib2",
    "urllib3",
    "requests",
    "httpx",
    "http.client",
    "aiohttp",
    "websockets",
    "paramiko",
    "ftplib",
    "smtplib",
    "imaplib",
})

# Submodules of blocked top-level packages that are safe (no network capability).
# e.g. urllib.parse is a pure URL parser — blocking it is a false positive.
_ALLOWED_IMPORTS: frozenset[str] = frozenset({
    "urllib.parse",
})


def _check_no_network_imports(tools_dir: _Path) -> None:
    """Parse every .py in mcp_server/tools/ and raise if a blocked network
    import is found.

    Uses AST parsing (not import execution) so it catches static imports
    without executing tool code twice.  Dynamic imports (importlib.import_module
    at runtime) are not caught — document this in SECURITY_MODEL.md GAP-1.

    Raises:
        RuntimeError: If any tool module contains a blocked import statement.
    """
    violations: list[str] = []
    for py_file in sorted(tools_dir.glob("*.py")):
        try:
            tree = _ast.parse(py_file.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.Import, _ast.ImportFrom)):
                if isinstance(node, _ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, _ast.ImportFrom):
                    names = [node.module or ""] + [alias.name for alias in node.names]
                for name in names:
                    if name in _ALLOWED_IMPORTS:
                        continue
                    top = name.split(".")[0]
                    if top in _BLOCKED_IMPORTS or name in _BLOCKED_IMPORTS:
                        violations.append(f"{py_file.name}: imports '{name}'")

    if violations:
        raise RuntimeError(
            "SECURITY VIOLATION — network import(s) found in tool modules:\n"
            + "\n".join(f"  {v}" for v in violations)
            + "\nCaseFile cannot start. Remove these imports."
        )


# Run at server startup — before mcp.run()
_tools_dir = _Path(__file__).parent / "tools"
_check_no_network_imports(_tools_dir)

# ── End GAP-1 ─────────────────────────────────────────────────────────────

from fastmcp import FastMCP
from mcp_server.tools.amcache import parse_amcache
from mcp_server.tools.prefetch import parse_prefetch
from mcp_server.tools.event_logs import parse_event_logs
from mcp_server.tools.registry import parse_registry
from mcp_server.tools.mft_safe import parse_mft
from mcp_server.tools.accuracy import generate_accuracy_report
from mcp_server.tools.memory import parse_memory
from mcp_server.tools.correlation import correlate_evidence, detect_host_type
from mcp_server.tools.forensic_rag import search_knowledge, get_knowledge_stats
from mcp_server.tools.shellbags import parse_shellbags
from mcp_server.tools.hayabusa import parse_hayabusa
from mcp_server.tools.export_findings import export_findings
from mcp_server.tools.lnk import parse_lnk
from mcp_server.tools.jumplists import parse_jumplists
from mcp_server.tools.usn import parse_usn_journal
from mcp_server.tools.vol_pslist import parse_volatility_pslist
from mcp_server.tools.vol_netscan import parse_volatility_netscan
from mcp_server.tools.timeline_check import check_timeline_contradictions
from mcp_server.tools.findings import (
    record_finding,
    get_findings,
    record_timeline_event,
)

# ── Default output_dir wrapper ────────────────────────────────────────────────

def _with_default_output_dir(tool_fn, subdir: str):
    """Inject default output_dir = $CASEFILE_CASE_ROOT/analysis/<subdir/>
    when caller does not provide one.  Composition wrapper — does not
    modify the parser tool itself.

    Prevents empty-output no-op runs when the agent calls a parser
    without output_dir, which produces empty audit entries and
    breaks Tier 2 grounding verification.

    Prefers CASEFILE_CASE_ROOT over CASEFILE_CASE_DIR for consistency
    with _enforce_case_root() path confinement.  No separate confinement
    is applied here: the output path is constructed from a trusted env
    var, and individual parser tools already enforce path confinement
    on their input arguments.

    Uses sig.bind_partial so output_dir can be supplied positionally
    (e.g. parse_event_logs('/path/to.evtx', '/custom/out')) without
    raising TypeError due to the bare *args expansion.
    """
    sig = inspect.signature(tool_fn)

    @wraps(tool_fn)
    def wrapper(*args, **kwargs):
        bound = sig.bind_partial(*args, **kwargs)
        if bound.arguments.get("output_dir") is None:
            case_dir_raw = (os.environ.get("CASEFILE_CASE_ROOT")
                            or os.environ.get("CASEFILE_CASE_DIR", ""))
            if case_dir_raw:
                case_dir = Path(case_dir_raw).resolve()
                out = str(case_dir / "analysis" / subdir)
                os.makedirs(out, exist_ok=True)
                bound.arguments["output_dir"] = out
        return tool_fn(**bound.arguments)

    wrapper.__signature__ = sig
    wrapper.__annotations__ = tool_fn.__annotations__
    return wrapper


# ── MCP Server ───────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="casefile",
    instructions="""
You are a forensic analysis assistant. This MCP server exposes SIFT Workstation
forensic tools as typed, structured functions. You MUST use these functions
instead of raw shell commands for all forensic analysis.

Rules:
- NEVER modify files in /mnt/evidence, /cases/*/evidence/, or /media/
- ALWAYS use MCP functions — never raw dotnet/vol/log2timeline shell commands
- ALWAYS distinguish CONFIRMED (direct tool output) from INFERRED (correlation)
- ALWAYS cite the specific MCP function call that produced each finding
- Emit <promise>TASK_COMPLETE: [N] confirmed, [M] inferred, [K] self-corrections</promise> when done

TOOL CALL REQUIREMENTS:
These tools require explicit input-path arguments. Calling them with
empty args produces empty audit entries and breaks Tier 2 grounding
verification. The output_dir argument has a sensible default
($CASEFILE_CASE_ROOT/analysis/<tool>_out/) but you should still pass
one explicitly when running multiple analyses on different inputs to
the same tool (e.g. parse_event_logs on Security vs System channels).

- parse_event_logs(evtx_path=..., output_dir=...)
    evtx_path REQUIRED — path to .evtx file or directory of .evtx files
    output_dir OPTIONAL — default: $CASEFILE_CASE_ROOT/analysis/evtx_out/
    For per-channel analysis use descriptive subdirs like evtx_kerberos_out,
    evtx_acct_out, evtx_proc_out.

- parse_amcache(amcache_path=..., output_dir=...)
    amcache_path REQUIRED — path to Amcache.hve
    output_dir OPTIONAL — default: $CASEFILE_CASE_ROOT/analysis/amcache_out/

- parse_mft(mft_path=..., output_dir=..., filename_filter=..., max_parse_rows=...)
    mft_path REQUIRED — path to $MFT
    output_dir OPTIONAL — default: $CASEFILE_CASE_ROOT/analysis/mft_out/
    filename_filter OPTIONAL — list of filenames to filter for
    max_parse_rows OPTIONAL — hard cap on entries read into memory (default 10 000)

- parse_prefetch(prefetch_dir=..., output_dir=...)
    prefetch_dir REQUIRED — directory containing .pf files
    output_dir OPTIONAL — default: $CASEFILE_CASE_ROOT/analysis/prefetch_csv/

- parse_registry(hive_path=..., output_dir=...)
    hive_path REQUIRED — path to registry hive
    output_dir OPTIONAL — default: $CASEFILE_CASE_ROOT/analysis/registry_out/

- parse_memory(image_path=..., plugin=..., timeout_sec=..., use_cache=...)
    image_path REQUIRED — path to memory image (.img, .raw, .mem, .vmem)
    plugin OPTIONAL — Volatility3 plugin name (default: windows.pslist)
    timeout_sec OPTIONAL — subprocess timeout in seconds (default: 600)
    use_cache OPTIONAL — reuse cached results for same (sha256, plugin) pair (default: true)
    No output_dir — uses internal SHA256-based cache directory.

GROUNDING DISCIPLINE:
When citing tool output in record_finding() evidence_quotes, the
exact_value MUST be ONE verbatim cell value from the parser CSV
output — not a composite "Field: Value" summary string. The grounding
verifier searches CSV cells for an exact match.

  CORRECT:   exact_value="9/5/2018 9:37:23 PM"
  CORRECT:   exact_value="LARIAT"
  CORRECT:   exact_value="172.16.5.21"
  WRONG:     exact_value="PasswordLastSet: 9/5/2018 9:37:23 PM"
  WRONG:     exact_value="ServiceName: LARIAT"
  WRONG:     exact_value="Source IP: 172.16.5.21"

If a single CSV cell cannot support the claim, do not invent a composite
string. Either find the supporting cell in a different CSV the tool
produced, or remove the claim and re-label the finding as INFERRED
with reasoning in the interpretation field.
""",
)

# ── Register tools ────────────────────────────────────────────────────────────
# ── Tool registration ──────────────────────────────────────────────────────
# Single source-of-truth for both mcp.tool() registration and the GAP-2
# startup check.  Adding a new tool here automatically includes it in the
# BLOCKED_COMMANDS verification — no separate list to forget.

_TOOL_DEFS: list[tuple[Any, str | None]] = [
    # (tool_fn, default_output_dir_subdir | None)
    (parse_amcache,              "amcache_out"),
    (parse_prefetch,             "prefetch_csv"),
    (parse_event_logs,           "evtx_out"),
    (parse_registry,             "registry_out"),
    (parse_mft,                  "mft_out"),
    (parse_memory,               None),  # uses internal SHA256 cache dir
    (record_finding,             None),
    (get_findings,               None),
    (record_timeline_event,      None),
    (generate_accuracy_report,   None),
    (correlate_evidence,         None),
    (detect_host_type,           None),
    (search_knowledge,           None),
    (get_knowledge_stats,        None),
    (parse_shellbags,            None),
    (parse_hayabusa,             None),
    (export_findings,            None),
    (parse_lnk,                  None),
    (parse_jumplists,            None),
    (parse_volatility_pslist,    None),
    (parse_volatility_netscan,   None),
    (parse_usn_journal,          None),
    (check_timeline_contradictions, None),
]

for _tool_fn, _subdir in _TOOL_DEFS:
    if _subdir is not None:
        mcp.tool()(_with_default_output_dir(_tool_fn, _subdir))
    else:
        mcp.tool()(_tool_fn)

# ── GAP-2 closure: enforce BLOCKED_COMMANDS at startup ────────────────────
# Derives registered tool names from the same _TOOL_DEFS list used for
# mcp.tool() registration above.  A new tool added to _TOOL_DEFS is
# automatically included in the check — no separate list to maintain.
from mcp_server.tools.findings import assert_blocked_commands_not_registered

_registered_tools = [_fn.__name__ for _fn, _ in _TOOL_DEFS]
assert_blocked_commands_not_registered(_registered_tools)
# ── End GAP-2 ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
