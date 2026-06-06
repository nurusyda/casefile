# Case Walkthrough: SRL-2018-FILE

A step-by-step trace of one finding through the CaseFile pipeline — from task
definition to Tier 2 verification proof.

---

## The Case

**SRL-2018-FILE** is the file server (BASE-FILE.shieldbase.lan) from the CRIMSON
OSPREY investigation. Evidence: Security.evtx (2.1 MB — anomalously small, suggesting
log clearing) and System.evtx (32 MB — suggesting heavy service activity). No
Prefetch directory (Windows Server). No memory image.

---

## The prd.json Task

Task `T04` from `prd.json`:

```json
{
  "id": "T04",
  "name": "service_installation",
  "description": "Investigate large System.evtx (32MB) for attacker service installations",
  "required_label": "CONFIRMED",
  "pass_criteria": [
    "EID 7045 service installation events found",
    "Check for LARIAT, pssdnsvc, or hex-named suspicious services",
    "Service name, binary path, and timestamp recorded"
  ],
  "failure_action": "parse_event_logs() with event_ids=[7045, 4697] on System.evtx"
}
```

This instructs Claude Code to look for Windows Service installation events (EID 7045)
and check for known IOC service names.

---

## What Ralph Did

Claude Code (via `ralph.sh`, session 01, 2026-06-06) executed the following
investigation sequence:

### 1. Host Type Detection

```
detect_host_type("/home/sansproject/cases/SRL-2018-FILE/analysis")
→ host_type: DOMAIN_CONTROLLER
```

Actually, the FILE server was classified based on its artifact profile. Since
Security.evtx and System.evtx were present, the primary analysis path was
event-log based.

### 2. Event Log Parsing

```
parse_event_logs(
    evtx_path="/home/sansproject/cases/SRL-2018-FILE/analysis/evtx",
    output_dir="/home/sansproject/cases/SRL-2018-FILE/analysis/evtx_out",
    event_ids=[4624, 4625, 4648, 4688, 4720, 4732, 7045, 1102]
)
→ invocation_id: 33c87d3b-75db-486c-b9c4-09567dcc2003
```

This invoked `EvtxECmd.dll` (Eric Zimmerman's EvtxECmd) against all .evtx files
in the case's evtx directory, filtering for the specified event IDs. The MCP
server:
- Ran `dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` with appropriate flags
- Parsed the CSV output server-side
- Filtered and capped entries
- Wrote structured JSON back to Claude Code
- Logged the invocation to `audit/mcp.jsonl`

### 3. Finding Recorded

Claude Code called:

```
record_finding(
    title="subject_srv.exe Installed as Persistent Auto-Start Service (F-Response Subject)",
    observation="EID 7045 at 2018-09-06T19:25:36Z on base-file.shieldbase.lan: service
      \"F-Response Subject\" installed with StartType=auto start, AccountName=LocalSystem,
      executable C:\\windows\\subject_srv.exe, installed by SID
      S-1-5-21-3445421715-2530590580-3149308974-1185...",
    interpretation="A domain user (SID -1185) installed subject_srv.exe as a LocalSystem
      auto-start service. The non-standard path (C:\\windows\\ vs System32)...",
    confidence="INFERRED",
    artifact_source="System.evtx EID 7045 record_number 103475;
      Security.evtx EID 4688 record_number 35738",
    supporting_tool="EvtxECmd",
    mitre_technique="T1543.003",
    evidence_quotes=[
        {
            "tool": "EvtxECmd",
            "invocation_id": "33c87d3b-75db-486c-b9c4-09567dcc2003",
            "claim": "Service F-Response Subject installed with subject_srv.exe auto-start",
            "exact_value": "Name: F-Response Subject"
        },
        {
            "tool": "EvtxECmd",
            "invocation_id": "33c87d3b-75db-486c-b9c4-09567dcc2003",
            "claim": "subject_srv.exe process spawned at 2018-09-06T19:25:36Z",
            "exact_value": "C:\\Windows\\subject_srv.exe C:\\windows\\subject_srv.exe -s
              \"base-hunt.shieldbase.lan:5682\" -l 3262 -v \"F-Response Subject\" -k \"155522845\""
        }
    ],
    claim_confidence="MEDIUM"
)
→ finding_id: F-sansproject-001
```

The confidence is `INFERRED` because (a) no `correlate_evidence()` verdict was
available (live Amcache and MFT parsers returned 0 entries on this FILE server),
and (b) per the fallback rule, event-log-only evidence with no correlation verdict
is bounded at INFERRED.

---

## The Finding

From `findings_session01_REFERENCE.json`:

| Field | Value |
|---|---|
| **ID** | `F-sansproject-001` |
| **Title** | subject_srv.exe Installed as Persistent Auto-Start Service (F-Response Subject) |
| **Confidence** | INFERRED |
| **Artifact Source** | System.evtx EID 7045; Security.evtx EID 4688 |
| **MITRE ATT&CK** | T1543.003 — Windows Service |
| **Key timestamp** | 2018-09-06T19:25:36Z |

**Observation summary**: A domain user (SID -1185, not SYSTEM) installed
`subject_srv.exe` at `C:\windows\` (anomalous — not System32) as a LocalSystem
auto-start service named "F-Response Subject." F-Response is a legitimate
DFIR tool; its presence here is consistent with attacker or unauthorised
responder lateral tool deployment.

**Why INFERRED**: The artifact directly proves the service was installed
(CONFIRMED in isolation), but the conclusion that this is *attacker activity*
requires interpretation — the service name "F-Response Subject" is not an IOC,
and without a `correlate_evidence()` verdict, the finding stays at INFERRED
per the fallback rule.

---

## The Claim Trace

### Claim 1: Service Installation

```
claim_text:  "tool='EvtxECmd' claim='Service F-Response Subject installed
             with subject_srv.exe auto-start'
             inv_id='33c87d3b-75db-486c-b9c4-09567dcc2003'"
```

### Step 1 — Invocation ID → Audit Log

The verifier opens `audit/mcp.jsonl` and searches for
`33c87d3b-75db-486c-b9c4-09567dcc2003`.

It finds:
```json
{
  "invocation_id": "33c87d3b-75db-486c-b9c4-09567dcc2003",
  "tool": "EvtxECmd",
  "ts": "2026-06-06T13:49:57.123456+00:00",
  "parsed_record_count": 239,
  "returncode": 0,
  "csv_files": [
    "/home/sansproject/cases/SRL-2018-FILE/analysis/evtx_out/20260606134957_EvtxECmd.csv"
  ]
}
```

**Tier 1 check**: ✓ Invocation ID exists, tool name matches (`EvtxECmd`).

### Step 2 — CSV File → Cell Value

The verifier opens `20260606134957_EvtxECmd.csv` and searches for the
exact value `"Name: F-Response Subject"` as a cell in any column.

In the CSV, the row for EID 7045 record number 103475 contains:
```
...,"Name: F-Response Subject","C:\windows\subject_srv.exe",...
```

**Tier 2 check**: ✓ Exact value found as a literal cell in CSV output.

### Claim 2: Process Execution

```
claim_text:  "tool='EvtxECmd' claim='subject_srv.exe process spawned at
             2018-09-06T19:25:36Z'
             inv_id='33c87d3b-75db-486c-b9c4-09567dcc2003'"
```

**Tier 1**: ✓ Same invocation ID, same audit entry.

**Tier 2**: The verifier searches the CSV for:
```
C:\Windows\subject_srv.exe C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"
```
This is the full command-line string from the EID 4688 event in the CSV's
`PayloadData1` column.

**Tier 2 check**: ✓ Exact value found.

### Verdict

```
Claim 1: GROUNDED — Tier 2 CSV check passed: exact_value 'Name: F-Response Subject'
         found in CSV output (1 of 1 file(s) read)
Claim 2: GROUNDED — Tier 2 CSV check passed: exact_value 'C:\Windows\subject_srv.exe...'
         found in CSV output (1 of 1 file(s) read)
```

Both claims pass Tier 2. Finding F-sansproject-001 has 2/2 grounded claims,
0.0 hallucination rate.

---

## Tier 2 Verification Proof

The exact verification note from `claim_accuracy_report_session01_REFERENCE.json`:

```json
{
  "claim_text": "tool='EvtxECmd' claim='Service F-Response Subject installed
    with subject_srv.exe auto-start'
    inv_id='33c87d3b-75db-486c-b9c4-09567dcc2003'",
  "status": "GROUNDED",
  "supporting_invocation_id": "33c87d3b-75db-486c-b9c4-09567dcc2003",
  "note": "Tool 'EvtxECmd' attested and Tier 2 CSV check passed:
    exact_value 'Name: F-Response Subject' found in CSV output
    (1 of 1 file(s) read)"
}
```

This is the atomic unit of grounding: a tool was called (attested by audit log),
produced CSV output, and the cited value exists in that CSV as a literal cell.
The claim is not a paraphrase or interpretation — it is a direct citation of
observable data.

---

## Complete Claim Trace Diagram

```
prd.json T04 "service_installation"
    │
    ▼
ralph.sh → Claude Code reads CLAUDE.md + prd.json
    │
    ▼
parse_event_logs(evtx_path=..., event_ids=[..., 7045, ...])
    │  invocation_id: 33c87d3b-75db-486c-b9c4-09567dcc2003
    │
    ▼
EvtxECmd.dll → CSV output → MCP server parses → structured JSON
    │
    ▼
record_finding(...)
    │  evidence_quote:
    │    tool: "EvtxECmd"
    │    invocation_id: "33c87d3b-..."
    │    claim: "Service F-Response Subject installed..."
    │    exact_value: "Name: F-Response Subject"
    │
    ▼
findings.json ← DRAFT finding F-sansproject-001
    │
    ▼
grounding_verify.py
    │
    ├─ Tier 1: invocation_id in audit/mcp.jsonl? ✓
    │
    └─ Tier 2: "Name: F-Response Subject" in CSV? ✓
    │
    ▼
claim_accuracy_report.json: GROUNDED (hallucination_rate=0.0)
```

---

## What This Finding Does NOT Prove

Per the epistemology law, this finding is labeled INFERRED because:
- The artifact directly proves the service was installed and the process ran
- But the claim that this is *attacker activity* requires interpretation:
  F-Response is a legitimate DFIR tool — it could be responder activity
- Without Amcache hash verification (live parser returned 0 entries) or
  memory correlation (no memory image for this host), the finding cannot
  be upgraded to CONFIRMED
- `correlate_evidence("subject_srv.exe", ...)` returned `NOT_FOUND` due to
  live parser incompatibility — this is a documented gap, not a retraction

The finding is correctly labeled: the *observation* is grounded in CSV evidence,
but the *interpretation* requires examiner judgment.
