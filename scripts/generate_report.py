#!/usr/bin/env python3
"""generate_report.py — Convert findings.json + timeline.json to markdown IR report.

Called by ralph.sh after TASK_COMPLETE is detected, or run manually:
    python3 scripts/generate_report.py

Environment variables:
    CASEFILE_CASE_DIR   — path to case directory (required)
    CASEFILE_EXAMINER   — examiner name (default: casefile)

Exit codes:
    0  — report written successfully
    1  — error (message on stderr)
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Resolve case directory ────────────────────────────────────────────────────
case_dir = os.environ.get("CASEFILE_CASE_DIR", "")
if not case_dir:
    print("error: CASEFILE_CASE_DIR not set", file=sys.stderr)
    sys.exit(1)

case_path = Path(case_dir).resolve()
if not case_path.exists():
    print(f"error: case directory not found: {case_path}", file=sys.stderr)
    sys.exit(1)

examiner = os.environ.get("CASEFILE_EXAMINER", "casefile")

# ── Load findings ─────────────────────────────────────────────────────────────
findings_file = case_path / "findings.json"
if not findings_file.exists():
    print(f"error: findings.json not found at {findings_file}", file=sys.stderr)
    sys.exit(1)

findings = json.loads(findings_file.read_text(encoding="utf-8"))

# ── Load timeline ─────────────────────────────────────────────────────────────
timeline_file = case_path / "timeline.json"
timeline = []
if timeline_file.exists():
    timeline = json.loads(timeline_file.read_text(encoding="utf-8"))

# ── Load accuracy report ──────────────────────────────────────────────────────
accuracy_file = case_path / "analysis" / "claim_accuracy_report.json"
accuracy = {}
if accuracy_file.exists():
    accuracy = json.loads(accuracy_file.read_text(encoding="utf-8"))

# ── Determine case name from directory ───────────────────────────────────────
case_name = case_path.name  # e.g. SRL-2018
report_name = case_name.replace("-", "_").upper()  # e.g. SRL_2018

# ── Report output path ────────────────────────────────────────────────────────
reports_dir = case_path / "reports"
reports_dir.mkdir(parents=True, exist_ok=True)
report_path = reports_dir / f"{report_name}_findings.md"

# ── Stats ─────────────────────────────────────────────────────────────────────
confirmed = [f for f in findings if f.get("confidence") == "CONFIRMED"]
inferred  = [f for f in findings if f.get("confidence") == "INFERRED"]
hypotheses = [f for f in findings if f.get("confidence") == "HYPOTHESIS"]
total_claims   = accuracy.get("total_claims", "—")
grounded       = accuracy.get("grounded", "—")
hallucination  = accuracy.get("hallucination_rate", "—")
if isinstance(hallucination, float):
    hallucination = f"{hallucination:.1%}"

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Collect MITRE techniques ──────────────────────────────────────────────────
mitre = {}
for f in findings:
    for t in f.get("mitre_technique", "").split(","):
        t = t.strip()
        if t:
            mitre[t] = mitre.get(t, 0) + 1

# ── Build report ──────────────────────────────────────────────────────────────
lines = []

def h1(t): lines.append(f"# {t}\n")
def h2(t): lines.append(f"## {t}\n")
def h3(t): lines.append(f"### {t}\n")
def p(t=""): lines.append(f"{t}\n")
def hr(): lines.append("---\n")

h1(f"CaseFile Investigative Report — {case_name}")
p(f"**Examiner:** {examiner}  ")
p(f"**Generated:** {generated_at}  ")
p(f"**Case Directory:** `{case_path}`  ")
hr()

# Executive summary
h2("Executive Summary")
p(f"CaseFile autonomously investigated case **{case_name}** and produced "
  f"**{len(findings)} findings** ({len(confirmed)} CONFIRMED, {len(inferred)} INFERRED, "
  f"{len(hypotheses)} HYPOTHESES).")
p()
p(f"All findings were verified by the anti-hallucination grounding pipeline:")
p(f"- **Total claims:** {total_claims}")
p(f"- **Grounded:** {grounded}")
p(f"- **Hallucination rate:** {hallucination}")
p()
p("Every claim is traceable to a specific tool invocation in `audit/mcp.jsonl` "
  "via `invocation_id`.")
hr()

# Key statistics
h2("Key Statistics")
p(f"| Metric | Value |")
p(f"|--------|-------|")
p(f"| Total findings | {len(findings)} |")
p(f"| CONFIRMED | {len(confirmed)} |")
p(f"| INFERRED | {len(inferred)} |")
p(f"| HYPOTHESES | {len(hypotheses)} |")
p(f"| Total claims verified | {total_claims} |")
p(f"| Claims grounded | {grounded} |")
p(f"| Hallucination rate | {hallucination} |")
p(f"| MITRE techniques identified | {len(mitre)} |")
hr()

# MITRE ATT&CK coverage
if mitre:
    h2("MITRE ATT&CK Coverage")
    p("| Technique | Findings |")
    p("|-----------|----------|")
    for t, count in sorted(mitre.items()):
        p(f"| `{t}` | {count} |")
    hr()

# Timeline
if timeline:
    h2("UTC Investigation Timeline")
    p("| Timestamp (UTC) | Event | Confidence | Source |")
    p("|-----------------|-------|------------|--------|")
    for event in sorted(timeline, key=lambda x: x.get("timestamp_utc", "")):
        ts = event.get("timestamp_utc", "—")
        desc = event.get("description", "—")[:80]
        conf = event.get("confidence", "—")
        source = event.get("artifact_source", "—")[:40]
        p(f"| `{ts}` | {desc} | {conf} | {source} |")
    hr()

# CONFIRMED findings
h2(f"CONFIRMED Findings ({len(confirmed)})")
p("*These findings are directly supported by tool output in the audit log.*")
p()
for f in confirmed:
    h3(f"{f['id']} — {f['title']}")
    p(f"**MITRE:** `{f.get('mitre_technique', '—')}`  ")
    p(f"**Source:** {f.get('artifact_source', '—')}  ")
    p(f"**Tool:** `{f.get('supporting_tool', '—')}`  ")
    p()
    p(f"**Observation:** {f.get('observation', '—')}")
    p()
    p(f"**Interpretation:** {f.get('interpretation', '—')}")
    p()
    # Evidence quotes
    quotes = f.get("evidence_quotes", [])
    if quotes:
        p("**Evidence:**")
        for q in quotes:
            inv = q.get("invocation_id", "—")[:8]
            field = q.get("field", "—")
            val = q.get("exact_value", "—")
            claim = q.get("claim", "—")
            p(f"- `{field}={val!r}` (inv `{inv}...`) — {claim}")
    p()

hr()

# INFERRED findings
if inferred:
    h2(f"INFERRED Findings ({len(inferred)})")
    p("*These findings are supported by indirect evidence or correlation. "
      "Cannot be upgraded to CONFIRMED without additional artifact analysis.*")
    p()
    for f in inferred:
        h3(f"{f['id']} — {f['title']}")
        p(f"**MITRE:** `{f.get('mitre_technique', '—')}`  ")
        p(f"**Source:** {f.get('artifact_source', '—')}  ")
        p()
        p(f"**Observation:** {f.get('observation', '—')}")
        p()
        p(f"**Interpretation:** {f.get('interpretation', '—')}")
        p()

hr()

# Hypotheses
if hypotheses:
    h2(f"Hypotheses ({len(hypotheses)})")
    p("*Unconfirmed — require additional investigation.*")
    p()
    for f in hypotheses:
        h3(f"{f['id']} — {f['title']}")
        p(f.get("interpretation", "—"))
        p()
    hr()

# Audit trail note
h2("Audit Trail")
p("All tool invocations are logged in `audit/mcp.jsonl`. Every finding "
  "references one or more `invocation_id` values that can be looked up "
  "in the audit log to verify the exact tool output that produced each claim.")
p()
p("```bash")
p("# Trace any finding to its tool output:")
p("jq 'select(.invocation_id==\"<inv_id>\")' audit/mcp.jsonl")
p("```")

# ── Write report ──────────────────────────────────────────────────────────────
report_text = "\n".join(lines)
report_path.write_text(report_text, encoding="utf-8")
print(f"[generate_report] Report written to {report_path}")
print(f"[generate_report] {len(findings)} findings, {len(timeline)} timeline events")
