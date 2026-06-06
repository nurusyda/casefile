"""casefile MCP tool implementations.

Each module wraps one SIFT forensic tool:
  amcache.py      — AmcacheParser (execution evidence + SHA1)
  prefetch.py     — pyscca/libscca (execution history, LOLBAS detection)
  event_logs.py   — EvtxECmd (Windows Event Logs)
  registry.py     — RECmd + Kroll batch (persistence, run keys, USB)
  mft.py          — MFTECmd --at (filesystem timeline, timestomping)
  memory.py       — Volatility 3 (process listing, network connections)
  shellbags.py    — SBECmd (folder access history, deleted directory recovery)
  lnk.py          — LECmd (shortcut file analysis, network share targets)
  jumplists.py    — JLECmd (application file-access history, RDP targets)
  vol_pslist.py   — Volatility 3 windows.pslist (dedicated process listing)
  vol_netscan.py  — Volatility 3 windows.netscan (dedicated network scan)
  hayabusa.py     — Hayabusa (Sigma rule-based event log threat detection)
  correlation.py  — Cross-source evidence correlation + verdict logic
  findings.py     — Investigation state machine (DRAFT/APPROVED findings)
  grounding.py    — Anti-hallucination evidence quote verification
  accuracy.py     — Ground-truth comparison and accuracy reporting
  forensic_rag.py — Forensic knowledge base search and retrieval
  export_findings.py — SIEM-compatible finding export (ECS/OCSF)
  _shared.py      — audit_log(), run_tool() shared utilities
"""
