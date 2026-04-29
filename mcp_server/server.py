"""
find-evil-mcp — Custom MCP Server for SANS Find Evil! Hackathon
Wraps SIFT forensic tools as typed, structured Python functions.

Inference Constraint Level: HIGH
- All tool output is parsed server-side before returning to LLM
- LLM never receives raw shell output
- Every invocation is logged to audit/mcp.jsonl

Tool paths verified on Protocol SIFT (WSL2 Ubuntu 22.04), April 28 2026.
"""

from fastmcp import FastMCP
from mcp_server.tools.amcache import parse_amcache
from mcp_server.tools.prefetch import parse_prefetch
from mcp_server.tools.event_logs import parse_event_logs
from mcp_server.tools.registry import parse_registry
from mcp_server.tools.mft import parse_mft
from mcp_server.tools.findings import (
    record_finding,
    get_findings,
    record_timeline_event,
    BLOCKED_COMMANDS,
)

# ── Verified tool paths ──────────────────────────────────────────────────────
VOL        = "/usr/local/bin/vol"          # symlink → /opt/volatility3/bin/vol
MFTECMD    = "dotnet /opt/zimmermantools/MFTECmd.dll"
AMCACHE    = "dotnet /opt/zimmermantools/AmcacheParser.dll"
EVTXECMD   = "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"   # note subdirectory
RECMD      = "dotnet /opt/zimmermantools/RECmd/RECmd.dll"          # note subdirectory
SHIMCACHE  = "dotnet /opt/zimmermantools/AppCompatCacheParser.dll"
PREFETCH   = "dotnet /opt/zimmermantools/PECmd.dll"
SRUM       = "dotnet /opt/zimmermantools/SrumECmd.dll"
SHELLBAGS  = "dotnet /opt/zimmermantools/SBECmd.dll"
REGRIPPER  = "/usr/share/regripper/rip.pl"
LOG2TIMELINE = "log2timeline.py"
PSORT      = "psort.py"
# NOT AVAILABLE: VSCMount (Windows-only), MemProcFS (Windows-only)

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
""",
)

# ── Register tools ────────────────────────────────────────────────────────────
mcp.tool()(parse_amcache)
mcp.tool()(parse_prefetch)
mcp.tool()(parse_event_logs)
mcp.tool()(parse_registry)
mcp.tool()(parse_mft)

mcp.tool()(record_finding)
mcp.tool()(get_findings)
mcp.tool()(record_timeline_event)

if __name__ == "__main__":
    mcp.run()
