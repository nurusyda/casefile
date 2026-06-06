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

from fastmcp import FastMCP
from mcp_server.tools.amcache import parse_amcache
from mcp_server.tools.prefetch import parse_prefetch
from mcp_server.tools.event_logs import parse_event_logs
from mcp_server.tools.registry import parse_registry
from mcp_server.tools.mft import parse_mft
from mcp_server.tools.accuracy import generate_accuracy_report
from mcp_server.tools.memory import parse_memory
from mcp_server.tools.correlation import correlate_evidence, detect_host_type
from mcp_server.tools.forensic_rag import search_knowledge, get_knowledge_stats
from mcp_server.tools.shellbags import parse_shellbags
from mcp_server.tools.hayabusa import parse_hayabusa
from mcp_server.tools.export_findings import export_findings
from mcp_server.tools.findings import (
    record_finding,
    get_findings,
    record_timeline_event,
)

SRUM       = "dotnet /opt/zimmermantools/SrumECmd.dll"
SHELLBAGS  = "dotnet /opt/zimmermantools/SBECmd.dll"
REGRIPPER  = "/usr/share/regripper/rip.pl"
LOG2TIMELINE = "log2timeline.py"
PSORT      = "psort.py"
# NOT AVAILABLE: VSCMount (Windows-only), MemProcFS (Windows-only)

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
    """
    @wraps(tool_fn)
    def wrapper(*args, output_dir=None, **kwargs):
        if output_dir is None:
            case_dir = os.environ.get("CASEFILE_CASE_ROOT") or os.environ.get("CASEFILE_CASE_DIR", "")
            if case_dir:
                output_dir = str(Path(case_dir) / "analysis" / subdir)
                os.makedirs(output_dir, exist_ok=True)
        return tool_fn(*args, output_dir=output_dir, **kwargs)

    wrapper.__signature__ = inspect.signature(tool_fn)
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

- parse_mft(mft_path=..., output_dir=..., filename_filter=...)
    mft_path REQUIRED — path to $MFT
    output_dir OPTIONAL — default: $CASEFILE_CASE_ROOT/analysis/mft_out/
    filename_filter OPTIONAL — list of filenames to filter for

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
mcp.tool()(_with_default_output_dir(parse_amcache,    "amcache_out"))
mcp.tool()(_with_default_output_dir(parse_prefetch,   "prefetch_csv"))
mcp.tool()(_with_default_output_dir(parse_event_logs, "evtx_out"))
mcp.tool()(_with_default_output_dir(parse_registry,   "registry_out"))
mcp.tool()(_with_default_output_dir(parse_mft,        "mft_out"))
# parse_memory uses an internal SHA256-based cache dir — no output_dir param;
# wrapping it with _with_default_output_dir would raise TypeError.
mcp.tool()(parse_memory)

mcp.tool()(record_finding)
mcp.tool()(get_findings)
mcp.tool()(record_timeline_event)
mcp.tool()(generate_accuracy_report)
mcp.tool()(correlate_evidence)
mcp.tool()(detect_host_type)
mcp.tool()(search_knowledge)
mcp.tool()(get_knowledge_stats)
mcp.tool()(parse_shellbags)
mcp.tool()(parse_hayabusa)
mcp.tool()(export_findings)

if __name__ == "__main__":
    mcp.run()
