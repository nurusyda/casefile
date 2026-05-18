# CaseFile Documentation

CaseFile is an autonomous forensic investigation system for Claude Code on SIFT
Workstation. It provides structured MCP tools for Windows artifact analysis, a
deterministic cross-source correlation engine, and an 11-layer anti-hallucination
stack that verifies every claim against actual tool output.

## Quick Navigation

- [Getting Started](getting-started.md) -- Installation and first investigation
- [User Guide](user-guide.md) -- Complete investigation workflow
- [Guardrails](guardrails.md) -- Anti-hallucination architecture
- [Dataset](dataset.md) -- Evidence tested against and results

## What CaseFile Does

CaseFile gives Claude Code structured access to:

- **6 artifact parsers** -- Amcache, Prefetch, Event Logs, Registry, MFT, Memory (Volatility 3)
- **Correlation engine** -- Deterministic 4-source verdict, no LLM in decision path
- **Grounding verification** -- Two-tier claim verification against tool output
- **Forensic RAG** -- 260 curated records covering ATT&CK techniques, artifact guides, detection rules
- **Self-correction loop** -- Detects and corrects hallucinations automatically

## Key Properties

| Property | Value |
|---|---|
| Tests passing | 485 |
| Accuracy checkpoints | 8/8 (self-assessed, CFA-Bench methodology) |
| Hallucination rate | 0.0% (post-correction) |
| Self-corrections in live run | 19 contradicted claims corrected in 1 iteration |
| Guardrail layers | 11 (9 architectural, 2 process) |
| Forensic RAG records | 260 |

## Source Code

[github.com/nurusyda/casefile](https://github.com/nurusyda/casefile)
