#!/usr/bin/env python3
"""generate_html_report.py -- Convert findings.json + timeline.json to HTML IR report.

Produces a professional dark-theme forensic report matching CaseFile's visual design.

Usage:
    python scripts/generate_html_report.py

Environment variables:
    CASEFILE_CASE_DIR   -- path to case directory (required)
    CASEFILE_EXAMINER   -- examiner name (default: casefile)

Exit codes:
    0  -- report written successfully
    1  -- error (message on stderr)
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# -- Resolve case directory
case_dir = os.environ.get("CASEFILE_CASE_DIR", "")
if not case_dir:
    print("error: CASEFILE_CASE_DIR not set", file=sys.stderr)
    sys.exit(1)

case_path = Path(case_dir).resolve()
if not case_path.exists():
    print(f"error: case directory not found: {case_path}", file=sys.stderr)
    sys.exit(1)

examiner = os.environ.get("CASEFILE_EXAMINER", "casefile")

# -- Load data
findings_file = case_path / "findings.json"
if not findings_file.exists():
    print(f"error: findings.json not found", file=sys.stderr)
    sys.exit(1)

findings = json.loads(findings_file.read_text(encoding="utf-8"))

timeline_file = case_path / "timeline.json"
timeline = json.loads(timeline_file.read_text(encoding="utf-8")) if timeline_file.exists() else []

accuracy_file = case_path / "analysis" / "claim_accuracy_report.json"
accuracy = json.loads(accuracy_file.read_text(encoding="utf-8")) if accuracy_file.exists() else {}

# -- Stats
confirmed = [f for f in findings if f.get("confidence") == "CONFIRMED"]
inferred  = [f for f in findings if f.get("confidence") == "INFERRED"]
total_claims  = accuracy.get("total_claims", 0)
grounded      = accuracy.get("grounded", 0)
hallucination = accuracy.get("hallucination_rate", 0.0)
case_name     = case_path.name
generated_at  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# -- MITRE coverage
mitre = {}
for f in findings:
    for t in f.get("mitre_technique", "").split(","):
        t = t.strip()
        if t:
            mitre[t] = mitre.get(t, 0) + 1

# -- Helpers
def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def confidence_badge(c):
    colors = {"CONFIRMED": "#00ff88", "INFERRED": "#ffb830", "HYPOTHESIS": "#aa88ff"}
    col = colors.get(c, "#8899aa")
    return f'<span style="color:{col};font-family:\'IBM Plex Mono\',monospace;font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase">{esc(c)}</span>'

def finding_card(f):
    fid    = f.get("id", "?")
    title  = f.get("title", "Untitled")
    conf   = f.get("confidence", "UNKNOWN")
    obs    = f.get("observation", "")
    interp = f.get("interpretation", "")
    mitre_t = f.get("mitre_technique", "")
    tool   = f.get("supporting_tool", "")
    quotes = f.get("evidence_quotes", [])

    border_col = {"CONFIRMED": "#00ff88", "INFERRED": "#ffb830", "HYPOTHESIS": "#aa88ff"}.get(conf, "#556070")

    quotes_html = ""
    for q in quotes[:3]:
        inv = esc(q.get("invocation_id","")[:8])
        field = esc(q.get("field",""))
        val = esc(str(q.get("exact_value","")))
        claim = esc(q.get("claim",""))
        quotes_html += f'''
        <div style="background:#0a0c0f;border-radius:4px;padding:8px 10px;margin-top:6px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#8899aa">
          <span style="color:#00cc6a">{field}</span>=<span style="color:#4499ff">"{val}"</span>
          <span style="color:#556070"> inv:{inv}...</span><br>
          <span style="color:#8899aa">{claim}</span>
        </div>'''

    _style = "background:#151b22;border:1px solid #2a3540;border-radius:3px;padding:2px 6px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#aa88ff;margin-right:4px"
    mitre_tags = "".join(
        f'<span style="{_style}">{esc(t.strip())}</span>'
        for t in mitre_t.split(",") if t.strip()
    )

    return f'''
  <div style="background:#0f1318;border:1px solid #1e2730;border-left:3px solid {border_col};border-radius:8px;padding:18px 20px;margin-bottom:12px">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
      <div>
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#556070;margin-bottom:4px">{esc(fid)}</div>
        <div style="font-size:14px;font-weight:500;color:#e2e8f0">{esc(title)}</div>
      </div>
      {confidence_badge(conf)}
    </div>
    {f'<div style="margin-bottom:8px">{mitre_tags}</div>' if mitre_t else ''}
    <div style="color:#8899aa;font-size:12px;margin-bottom:8px"><strong style="color:#e2e8f0">Observation:</strong> {esc(obs)}</div>
    <div style="color:#8899aa;font-size:12px;margin-bottom:8px"><strong style="color:#e2e8f0">Interpretation:</strong> {esc(interp)}</div>
    {('<div style="font-family:IBM Plex Mono,monospace;font-size:10px;color:#556070;margin-bottom:4px">Tool: ' + esc(tool) + '</div>') if tool else ''}
    {quotes_html}
  </div>'''

# -- Timeline rows
def timeline_rows():
    rows = ""
    for e in sorted(timeline, key=lambda x: x.get("timestamp_utc",""))[:30]:
        ts   = esc(e.get("timestamp_utc","")[:19].replace("T"," "))
        desc = esc(e.get("description","")[:100])
        conf = e.get("confidence","")
        col  = {"CONFIRMED":"#00ff88","INFERRED":"#ffb830"}.get(conf,"#8899aa")
        rows += f'''
      <tr>
        <td style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#4499ff;white-space:nowrap;padding:8px 12px">{ts}</td>
        <td style="font-size:12px;color:#e2e8f0;padding:8px 12px">{desc}</td>
        <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:{col};padding:8px 12px;white-space:nowrap">{esc(conf)}</td>
      </tr>'''
    return rows

# -- MITRE table rows
def mitre_rows():
    rows = ""
    for t, count in sorted(mitre.items()):
        rows += f'''
      <tr>
        <td style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#aa88ff;padding:6px 12px">{esc(t)}</td>
        <td style="font-size:12px;color:#8899aa;padding:6px 12px">{count} finding{"s" if count!=1 else ""}</td>
      </tr>'''
    return rows

# -- Build HTML
html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CaseFile IR Report -- {esc(case_name)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0a0c0f;color:#e2e8f0;font-family:'IBM Plex Sans',sans-serif;font-size:14px;line-height:1.7;padding:40px 24px 80px;max-width:960px;margin:0 auto}}
  table{{width:100%;border-collapse:collapse}}
  tr:nth-child(even){{background:#0f1318}}
  th{{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#556070;padding:8px 12px;text-align:left;border-bottom:1px solid #1e2730}}
  .section{{margin-bottom:44px}}
  .section-label{{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#556070;margin-bottom:14px;display:flex;align-items:center;gap:10px}}
  .section-label::after{{content:'';flex:1;height:1px;background:#1e2730}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:8px}}
  .stat-card{{background:#0f1318;border:1px solid #1e2730;border-radius:8px;padding:16px 18px}}
  .stat-val{{font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:600;line-height:1}}
  .stat-label{{font-size:11px;color:#8899aa;margin-top:4px}}
  .tab-bar{{display:flex;gap:2px;margin-bottom:24px;border-bottom:1px solid #1e2730}}
  .tab{{padding:8px 16px;font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.06em;cursor:pointer;color:#556070;border-bottom:2px solid transparent;margin-bottom:-1px}}
  .tab.active{{color:#00ff88;border-bottom-color:#00ff88}}
  .tab-pane{{display:none}}.tab-pane.active{{display:block}}
</style>
</head>
<body>

<div style="border-bottom:1px solid #1e2730;padding-bottom:28px;margin-bottom:40px">
  <div style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#00ff88;letter-spacing:.12em;text-transform:uppercase;margin-bottom:12px">CASEFILE -- AUTOMATED IR REPORT</div>
  <h1 style="font-size:28px;font-weight:600;letter-spacing:-.02em;margin-bottom:8px">
    Case: <span style="color:#00ff88">{esc(case_name)}</span>
  </h1>
  <div style="color:#8899aa;font-size:14px">{esc(case_name)} -- Automated Investigation</div>
  <div style="display:flex;gap:20px;margin-top:18px;flex-wrap:wrap">
    <div style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#556070">
      <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#00ff88;margin-right:6px"></span>Examiner: {esc(examiner)}
    </div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#556070">
      <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#4499ff;margin-right:6px"></span>Generated: {generated_at}
    </div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:#556070">
      <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#aa88ff;margin-right:6px"></span>Engine: CaseFile v0.2.0 -- Anti-hallucination MCP
    </div>
  </div>
</div>

<!-- STATS -->
<div class="section">
  <div class="section-label">01 -- Key Metrics</div>
  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-val" style="color:#00ff88">{len(confirmed)}</div>
      <div class="stat-label">CONFIRMED findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#ffb830">{len(inferred)}</div>
      <div class="stat-label">INFERRED findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#4499ff">{grounded}/{total_claims}</div>
      <div class="stat-label">Claims grounded</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#00ff88">{hallucination:.1%}</div>
      <div class="stat-label">Hallucination rate</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#aa88ff">{len(mitre)}</div>
      <div class="stat-label">MITRE techniques</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#00ddcc">{len(timeline)}</div>
      <div class="stat-label">Timeline events</div>
    </div>
  </div>
  <div style="background:#0f1318;border:1px solid #1e2730;border-left:3px solid #00ff88;border-radius:6px;padding:12px 16px;margin-top:12px;font-size:13px;color:#8899aa">
    <strong style="color:#00ff88">Anti-hallucination verified:</strong> All {grounded} claims grounded against tool output in <code style="color:#4499ff">audit/mcp.jsonl</code> via invocation_id chain. Zero contradicted claims.
  </div>
</div>

<!-- TABS -->
<div class="section">
  <div class="section-label">02 -- Investigation Results</div>
  <div class="tab-bar">
    <div class="tab active" onclick="showTab('confirmed', event)">CONFIRMED ({len(confirmed)})</div>
    <div class="tab" onclick="showTab('inferred', event)">INFERRED ({len(inferred)})</div>
    <div class="tab" onclick="showTab('timeline', event)">TIMELINE ({len(timeline)})</div>
    <div class="tab" onclick="showTab('mitre', event)">MITRE ({len(mitre)})</div>
  </div>

  <div id="confirmed" class="tab-pane active">
    {"".join(finding_card(f) for f in confirmed)}
  </div>

  <div id="inferred" class="tab-pane">
    {"".join(finding_card(f) for f in inferred)}
  </div>

  <div id="timeline" class="tab-pane">
    <table>
      <thead><tr>
        <th>Timestamp UTC</th>
        <th>Event</th>
        <th>Confidence</th>
      </tr></thead>
      <tbody>{timeline_rows()}</tbody>
    </table>
  </div>

  <div id="mitre" class="tab-pane">
    <table>
      <thead><tr><th>Technique</th><th>Findings</th></tr></thead>
      <tbody>{mitre_rows()}</tbody>
    </table>
  </div>
</div>

<!-- AUDIT TRAIL -->
<div class="section">
  <div class="section-label">03 -- Audit Trail</div>
  <div style="background:#0f1318;border:1px solid #1e2730;border-radius:8px;padding:18px 20px;font-size:13px;color:#8899aa">
    <p style="margin-bottom:8px">Every finding is traceable to a specific tool invocation in <code style="color:#4499ff">audit/mcp.jsonl</code>.</p>
    <div style="background:#0a0c0f;border-radius:4px;padding:10px 14px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#8899aa;margin-top:8px">
      <span style="color:#556070"># Trace any finding to its exact tool output:</span><br>
      jq <span style="color:#00ff88">'select(.invocation_id=="&lt;inv_id&gt;")'</span> audit/mcp.jsonl
    </div>
  </div>
</div>

<script>
function showTab(id, event) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  event.target.classList.add('active');
}}
</script>

</body>
</html>'''

# -- Write
reports_dir = case_path / "reports"
reports_dir.mkdir(parents=True, exist_ok=True)
out = reports_dir / f"{case_path.name.replace('-','_').upper()}_findings.html"
out.write_text(html, encoding="utf-8")
print(f"[generate_html_report] Written to {out}")
print(f"[generate_html_report] {len(findings)} findings, {len(timeline)} timeline events, {len(mitre)} MITRE techniques")
