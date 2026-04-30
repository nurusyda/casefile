"""casefile MCP tool implementations.

Each module wraps one SIFT forensic tool:
  amcache.py    — AmcacheParser (execution evidence + SHA1)
  prefetch.py   — pyscca/libscca (execution history, LOLBAS detection)
  event_logs.py — EvtxECmd (Windows Event Logs)
  registry.py   — RECmd + Kroll batch (persistence, run keys, USB)
  mft.py        — MFTECmd --at (filesystem timeline, timestomping)
  findings.py   — Investigation state machine (DRAFT/APPROVED findings)
  _shared.py    — audit_log(), run_tool() shared utilities
"""
