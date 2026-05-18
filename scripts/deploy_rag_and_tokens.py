#!/usr/bin/env python3
"""Deploy forensic RAG and token usage tracking into CaseFile.

Run from ~/casefile:
    python3 deploy_rag_and_tokens.py

Creates/copies:
    mcp_server/data/forensic_knowledge.json   — knowledge base
    mcp_server/tools/forensic_rag.py          — search MCP tool
    scripts/parse_token_usage.py              — token parser
    tests/test_forensic_rag.py                — RAG tests
    tests/test_parse_token_usage.py           — token parser tests

Patches:
    mcp_server/server.py                      — registers forensic_knowledge_search
    ralph.sh                                  — adds token tracking after each claude call
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(".")

# ---------------------------------------------------------------------------
# Verify we're in the right directory
# ---------------------------------------------------------------------------

if not (REPO / "mcp_server" / "server.py").exists():
    print("ERROR: Run this from ~/casefile (mcp_server/server.py not found)")
    sys.exit(1)

if not (REPO / "ralph.sh").exists():
    print("ERROR: ralph.sh not found in current directory")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Guard: verify forensic_rag.py source exists before patching server.py
# ---------------------------------------------------------------------------
if not (REPO / "mcp_server" / "tools" / "forensic_rag.py").exists():
    print("ERROR: mcp_server/tools/forensic_rag.py not found.")
    print("Copy the 5 required files first (see script header), then re-run.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 1. Create data directory and copy knowledge base
# ---------------------------------------------------------------------------

data_dir = REPO / "mcp_server" / "data"
data_dir.mkdir(exist_ok=True)

# Create __init__.py for the data package
init_file = data_dir / "__init__.py"
if not init_file.exists():
    init_file.write_text("")

print("OK: mcp_server/data/ directory ready")

# ---------------------------------------------------------------------------
# 2. Patch server.py — register forensic_knowledge_search + get_knowledge_stats
# ---------------------------------------------------------------------------

server_py = REPO / "mcp_server" / "server.py"
src = server_py.read_text(encoding="utf-8")

# Find import block — add forensic_rag import
IMPORT_ANCHOR = "from mcp_server.tools.grounding import"
if IMPORT_ANCHOR not in src:
    # Try alternative anchor
    IMPORT_ANCHOR = "from mcp_server.tools.findings import"

if IMPORT_ANCHOR not in src:
    print("ERROR: Could not find import anchor in server.py")
    print("  Looked for: 'from mcp_server.tools.grounding import' and")
    print("  'from mcp_server.tools.findings import'")
    print("  Add the import manually:")
    print("    from mcp_server.tools.forensic_rag import search_knowledge, get_knowledge_stats")
    sys.exit(1)

RAG_IMPORT = "from mcp_server.tools.forensic_rag import search_knowledge, get_knowledge_stats"

if RAG_IMPORT in src:
    print("OK: forensic_rag import already present in server.py")
else:
    # Insert after the anchor import line
    anchor_line_end = src.index(IMPORT_ANCHOR)
    # Find end of that line
    line_end = src.index("\n", anchor_line_end)
    new_src = src[:line_end + 1] + RAG_IMPORT + "\n" + src[line_end + 1:]
    src = new_src
    print("OK: Added forensic_rag import to server.py")

# Find tool registration block — add RAG tools
# Look for the last @mcp.tool() registration
TOOL_REG_MARKER = "@mcp.tool()"
last_tool_pos = src.rfind(TOOL_REG_MARKER)

if last_tool_pos < 0:
    print("ERROR: No @mcp.tool() found in server.py — cannot register RAG tools")
    sys.exit(1)

# Find the end of the last tool function (next function or end of file)
# We'll append after the last complete tool function
RAG_TOOL_MARKER = "def forensic_knowledge_search("

if RAG_TOOL_MARKER in src:
    print("OK: forensic_knowledge_search already registered in server.py")
else:
    # Find a good insertion point — after the last tool function
    # Look for the pattern of the last tool's function end
    # Strategy: find the last @mcp.tool() block, then find the next blank line
    # after its function body
    
    # Simpler approach: append before the final if __name__ block, or at end
    MAIN_GUARD = 'if __name__'
    if MAIN_GUARD in src:
        insert_pos = src.index(MAIN_GUARD)
    else:
        insert_pos = len(src)
    
    rag_registration = '''

# ---------------------------------------------------------------------------
# Forensic Knowledge RAG (Block 11)
# ---------------------------------------------------------------------------


@mcp.tool()
def forensic_knowledge_search(
    query: str,
    max_results: int = 5,
    category: str = "",
) -> dict:
    """Search the forensic knowledge base for MITRE ATT&CK techniques,
    artifact analysis guides, Sigma detection patterns, and DFIR methodology.

    Use this BEFORE analyzing evidence to understand what artifacts to look for
    and what specific Event IDs, registry keys, or file paths are relevant.

    Parameters
    ----------
    query : str
        Free-text search (e.g. "lateral movement", "T1543.003", "prefetch
        analysis", "event log 7045 service install", "timestomping detection").
    max_results : int
        Number of results (1-10, default 5).
    category : str
        Optional filter: "mitre_attack", "artifact_guide", "sigma_rule",
        "methodology".  Empty string = search all.

    Returns
    -------
    dict
        results: list of matching knowledge records with relevance scores.
        stats: knowledge base summary.
    """
    cat = category if category else None
    results = search_knowledge(query, max_results=max_results, category=cat)
    return {
        "results": results,
        "result_count": len(results),
        "query": query,
        "category_filter": category or "all",
    }


@mcp.tool()
def forensic_knowledge_stats() -> dict:
    """Return statistics about the forensic knowledge base.

    Shows total records, categories, and index status.  Useful for
    understanding what forensic knowledge is available for grounding analysis.
    """
    return get_knowledge_stats()


'''
    new_src = src[:insert_pos] + rag_registration + src[insert_pos:]
    src = new_src
    print("OK: Registered forensic_knowledge_search + forensic_knowledge_stats in server.py")

server_py.write_text(src, encoding="utf-8")
print("OK: server.py updated")

# ---------------------------------------------------------------------------
# 3. Patch ralph.sh — add token tracking
# ---------------------------------------------------------------------------

ralph = REPO / "ralph.sh"
ralph_src = ralph.read_text(encoding="utf-8")

TOKEN_TRACK_MARKER = "parse_token_usage.py"

if TOKEN_TRACK_MARKER in ralph_src:
    print("OK: Token tracking already present in ralph.sh")
else:
    # Insert token tracking after the main CLAUDE_OUTPUT length log line
    MAIN_LENGTH_LOG = 'log "Claude output length: ${#CLAUDE_OUTPUT} chars"'
    if MAIN_LENGTH_LOG not in ralph_src:
        print("WARNING: Could not find length log anchor in ralph.sh")
        print("  Add token tracking manually after the Claude output length log")
    else:
        token_block = '''
    # Track token usage
    CLAUDE_OUTPUT_FILE=$(mktemp)
    printf '%s' "${CLAUDE_OUTPUT}" > "${CLAUDE_OUTPUT_FILE}"
    PYTHONPATH="${SCRIPT_DIR}" python3 "${SCRIPT_DIR}/scripts/parse_token_usage.py" \\
        --output "@${CLAUDE_OUTPUT_FILE}" \\
        --iteration "${ITER}" \\
        --case-dir "${CASE_DIR}" \\
        --phase "main" || true
    rm -f "${CLAUDE_OUTPUT_FILE}"'''
        
        anchor_end = ralph_src.index(MAIN_LENGTH_LOG) + len(MAIN_LENGTH_LOG)
        new_ralph = ralph_src[:anchor_end] + "\n" + token_block + ralph_src[anchor_end:]
        ralph_src = new_ralph
        print("OK: Added main iteration token tracking to ralph.sh")

    # Also add tracking after correction iterations
    CORRECTION_LENGTH_LOG = 'log "Correction ${CORRECTION_ITER} output length: ${#CLAUDE_OUTPUT} chars"'
    if CORRECTION_LENGTH_LOG in ralph_src and "correction-token-track" not in ralph_src:
        correction_block = '''
                # correction-token-track
                CORR_OUTPUT_FILE=$(mktemp)
                printf '%s' "${CLAUDE_OUTPUT}" > "${CORR_OUTPUT_FILE}"
                PYTHONPATH="${SCRIPT_DIR}" python3 "${SCRIPT_DIR}/scripts/parse_token_usage.py" \\
                    --output "@${CORR_OUTPUT_FILE}" \\
                    --iteration "${ITER}" \\
                    --case-dir "${CASE_DIR}" \\
                    --phase "correction-${CORRECTION_ITER}" || true
                rm -f "${CORR_OUTPUT_FILE}"'''
        
        corr_anchor_end = ralph_src.index(CORRECTION_LENGTH_LOG) + len(CORRECTION_LENGTH_LOG)
        new_ralph = ralph_src[:corr_anchor_end] + "\n" + correction_block + ralph_src[corr_anchor_end:]
        ralph_src = new_ralph
        print("OK: Added correction iteration token tracking to ralph.sh")

    ralph.write_text(ralph_src, encoding="utf-8")
    print("OK: ralph.sh updated")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("\n=== DEPLOYMENT COMPLETE ===")
print("Files to create (copy from download):")
print("  mcp_server/data/forensic_knowledge.json  <- forensic_knowledge.json")
print("  mcp_server/tools/forensic_rag.py          <- forensic_rag.py")
print("  scripts/parse_token_usage.py              <- parse_token_usage.py")
print("  tests/test_forensic_rag.py                <- test_forensic_rag.py")
print("  tests/test_parse_token_usage.py           <- test_parse_token_usage.py")
print("\nFiles patched in place:")
print("  mcp_server/server.py  (import + 2 tool registrations)")
print("  ralph.sh              (token tracking after each claude call)")
print("\nNext steps:")
print("  1. Copy the 5 files listed above")
print("  2. pytest tests/ -q 2>&1 | tail -5")
print("  3. python3 scripts/monster_check.py")
print("  4. git add -A && git commit")
