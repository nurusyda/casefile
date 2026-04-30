"""casefile — Anti-hallucination MCP server for DFIR.

Wraps SIFT forensic tools as typed, structured Python functions.
All tool output is parsed server-side before returning to the LLM.
Every invocation is logged to audit/mcp.jsonl.
"""
