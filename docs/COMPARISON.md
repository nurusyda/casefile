# Comparison: CaseFile vs Valhuntir

An honest, non-adversarial comparison of two Find Evil Hackathon 2026 submissions
that take fundamentally different approaches to LLM-assisted DFIR.

---

## Positioning Statement

CaseFile and [Valhuntir](https://github.com/forensicmike1/Valhuntir) are different
shapes of solution to the same problem: how do you use an LLM for forensic
investigation without hallucination destroying trust?

**CaseFile** compresses the examiner loop by running autonomously with post-hoc
verification of every claim against actual tool output. It measures its accuracy
and publishes the numbers. Its strength is depth of verification on a focused
tool set.

**Valhuntir** provides a comprehensive investigation platform with human-in-the-loop
discipline, broad tool coverage, and production features (OpenSearch, browser portal,
multi-VM architecture). Its strength is breadth and production readiness.

They are not head-to-head competitors. They solve different parts of the problem.

---

## Feature Matrix

| Dimension | CaseFile | Valhuntir |
|---|---|---|
| **Approach** | Autonomous investigation + post-hoc grounding verification | Human-in-the-loop with agentic triage |
| **LLM role** | Primary investigator (reads evidence, writes findings) | Triage assistant (flags artifacts for human review) |

### Anti-Hallucination

| Capability | CaseFile | Valhuntir |
|---|---|---|
| Structured tool output (never raw shell) | ✓ — All parsers return typed JSON | — (LLM sees raw tool output) |
| Per-claim grounding verification | ✓ — Tier 1 (invocation ID) + Tier 2 (CSV value) | — |
| Published hallucination rate | ✓ — 0.0% across 3 datasets | — |
| Automatic self-correction loop | ✓ — correction prompt → Claude → re-verify (max 3×) | — |
| CONFIRMED/INFERRED labeling law | ✓ — enforced in CLAUDE.md | — |
| Human approve gate (TTY + password) | ✓ — AI cannot self-approve | — |

**Where CaseFile leads**: measured accuracy with published numbers, automatic
self-correction, architectural enforcement of grounding at two tiers.

**Where Valhuntir leads**: N/A — anti-hallucination architecture is CaseFile's
primary differentiator. Valhuntir relies on human-in-the-loop review rather than
automated verification.

### Tool Coverage

| Capability | CaseFile | Valhuntir |
|---|---|---|
| Total registered tools | 21 (MCP) | 15 parsers + Hayabusa + RAG + OpenSearch |
| Amcache parsing | ✓ AmcacheParser.dll | ✓ |
| Prefetch parsing | ✓ pyscca (libscca) | ✓ |
| Event Log parsing | ✓ EvtxECmd.dll | ✓ |
| Registry parsing | ✓ RECmd.dll | ✓ |
| MFT parsing | ✓ MFTECmd.dll | ✓ |
| Memory forensics | ✓ Volatility 3 (6 plugins) | ✓ Volatility 3 |
| Shellbags | ✓ SBECmd.dll | ✓ |
| Hayabusa (Sigma rules) | ✓ | ✓ |
| LNK parsing | ✓ LECmd.dll | ✓ |
| Jump Lists | ✓ JLECmd.dll | ✓ |
| SRUM | — | ✓ |
| Amcache (AppCompatCache) | — | ✓ |
| WMI Repository | — | ✓ |
| BAM/DAM | — | ✓ |
| Scheduled Tasks | — | ✓ |
| ActivitiesCache | — | ✓ |
| RDP Cache | — | ✓ |
| USB Detective | — | ✓ |
| Browser artifacts (SQLite) | — | ✓ |

**Where CaseFile leads**: Deep integration of each tool into the grounding
pipeline — every tool call is audit-logged and every CSV-producing tool gets
Tier 2 verification. Dedicated MCP wrappers for correlate_evidence,
detect_host_type, and export_findings that go beyond raw parser invocation.

**Where Valhuntir leads**: Broader artifact coverage (15 parsers vs. CaseFile's
12 parser types). SRUM, WMI Repository, BAM/DAM, Scheduled Tasks, RDP Cache,
USB Detective, and browser artifact parsing are absent from CaseFile.

### Knowledge & Detection

| Capability | CaseFile | Valhuntir |
|---|---|---|
| Forensic knowledge base | 260 records (TF-IDF) | 22,000+ records (RAG) |
| Sigma rule detection | Hayabusa (3,700+ rules) | Hayabusa (3,700+ rules) |
| IOC cross-referencing | prd.json + iocs.md | — |
| MITRE ATT&CK mapping | ✓ (per finding) | ✓ |
| LOLBAS detection | ✓ (in search_knowledge) | — |

**Where CaseFile leads**: LOLBAS detection entries in the knowledge base.

**Where Valhuntir leads**: Knowledge base size (22,000 vs 260 records) — 85× larger.
RAG implementation provides richer context retrieval.

### Workflow & UI

| Capability | CaseFile | Valhuntir |
|---|---|---|
| Investigation automation | ✓ — Ralph loop (autonomous) | — (human-in-the-loop) |
| Browser-based Examiner Portal | — | ✓ |
| Multi-VM architecture | — | ✓ (separate VMs per component) |
| Case management UI | — | ✓ |
| Task tracking | prd.json (text-based) | Portal-based |
| HTML report generation | ✓ (dark theme) | ✓ |

**Where CaseFile leads**: Fully autonomous investigation loop with progress
tracking via prd.json tasks.

**Where Valhuntir leads**: Production-grade UI with browser-based Examiner
Portal, multi-VM deployment architecture, and visual case management.

### Search & Indexing

| Capability | CaseFile | Valhuntir |
|---|---|---|
| Full-text search of findings | — (jq/grep on JSON) | OpenSearch |
| Cross-case correlation | — | OpenSearch dashboards |
| Timeline view | Manual (record_timeline_event) | Portal-based |
| Dashboard | — | ✓ |

**Where CaseFile leads**: N/A — has no indexing or dashboard layer.

**Where Valhuntir leads**: OpenSearch integration for indexed search, dashboards,
and cross-case correlation.

### Audit & Integrity

| Capability | CaseFile | Valhuntir |
|---|---|---|
| Append-only audit log | ✓ (audit/mcp.jsonl) | ✓ |
| Evidence hash at ingest | ✓ (SHA-256 → source.sha256) | — |
| Approval hash | ✓ (SHA-256 at approval time) | — |
| Per-claim traceability | ✓ (invocation_id → CSV cell) | — |
| Path confinement | ✓ (CASEFILE_CASE_ROOT) | — |
| Symlink rejection | ✓ | — |

**Where they tie**: Both maintain audit trails. CaseFile adds per-claim
traceability through invocation IDs and CSV cell verification; Valhuntir
maintains traditional forensic tool logging.

---

## Where CaseFile Leads

1. **Measured accuracy** — Published hallucination rate (0.0% across 3 datasets)
   with per-claim verification reports. No other LLM-DFIR tool publishes these numbers.

2. **Tier 2 verification** — Opens actual parser CSV files and checks cited values
   as literal cells. Catches the "correct tool, wrong value" hallucination mode.

3. **Automatic self-correction** — CONTRADICTED claims trigger a correction prompt
   back to the LLM. The loop runs up to 3 iterations without human intervention.

4. **Deterministic correlation engine** — Zero LLM involvement in verdict logic.
   Pure Boolean rules on artifact presence.

5. **Architectural guardrails** — Evidence integrity, path confinement, symlink
   rejection, append-only audit, and human approve gate are enforced in code, not prompt.

## Where Valhuntir Leads

1. **Tool coverage** — 15 parsers covering SRUM, WMI Repository, BAM/DAM,
   Scheduled Tasks, RDP Cache, USB Detective, and browser artifacts that CaseFile
   does not parse.

2. **Knowledge base** — 22,000+ RAG records vs. CaseFile's 260. Production-scale
   forensic knowledge retrieval.

3. **OpenSearch integration** — Indexed search, dashboards, cross-case correlation.
   CaseFile findings live in flat JSON files.

4. **Browser-based Examiner Portal** — Visual case management, timeline views,
   and task tracking. CaseFile is CLI + Claude Code terminal only.

5. **Multi-VM architecture** — Separated components for isolation and scalability.
   CaseFile runs in a single Python process on the SIFT workstation.

6. **Production readiness** — Designed for operational DFIR workflows with
   human-in-the-loop discipline. CaseFile is a research prototype demonstrating
   anti-hallucination architecture.

## Where They Tie

1. **Audit trail** — Both maintain tool call logs. CaseFile's is auto-generated
   per MCP invocation; Valhuntir logs traditional forensic tool execution.

2. **Hayabusa integration** — Both run Sigma rules against EVTX.

3. **Memory forensics** — Both use Volatility 3.

4. **MITRE ATT&CK mapping** — Both map findings to ATT&CK techniques.

5. **SIFT Workstation target** — Both designed for the SIFT environment.

---

## Architecture Shape Comparison

```
CaseFile (autonomous verification):
  Claude Code ──MCP──> Parser Tools ──> audit log
       │                                      │
       └──> record_finding() ──> findings.json │
                                     │         │
                              grounding_verify.py
                                     │
                              GROUNDED / CONTRADICTED

Valhuntir (human-in-the-loop triage):
  LLM Agent ──> Parser Tools ──> OpenSearch Index
       │                              │
       └──> Triage Flags ──> Examiner Portal
                                  │
                          Human Review → Report
```

CaseFile invests its complexity budget in the verification path.
Valhuntir invests its complexity budget in the tool coverage and UI path.

---

## When to Use Which

**Use CaseFile when:**
- You want measured, published accuracy numbers for LLM forensic claims
- You need autonomous triage with automatic self-correction
- You're researching anti-hallucination architecture for DFIR
- You're running on a single SIFT workstation with limited resources

**Use Valhuntir when:**
- You need broad artifact coverage (SRUM, WMI, BAM, browser artifacts)
- You want a browser-based Examiner Portal for case management
- You need OpenSearch indexing and cross-case search
- You're deploying a production DFIR workflow with multiple examiners
- You prefer human-in-the-loop discipline over autonomous analysis

**They complement each other**: CaseFile's grounding verification could in
principle be applied to Valhuntir's broader tool set. Valhuntir's portal and
indexing could wrap around CaseFile's verified findings.

---

*Both projects are Find Evil Hackathon 2026 submissions. This comparison is
based on publicly available code and documentation as of June 2026. Valhuntir
features are sourced from its public repository and documentation.*
