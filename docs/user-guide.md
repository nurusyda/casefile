# User Guide

## Investigation Workflow

A complete CaseFile investigation follows this sequence:

```
Evidence (E01)
    ↓  ingest.sh (~2 min)
Artifacts in analysis/
    ↓  ralph.sh
Autonomous investigation
    ↓  grounding_verify.py
Verified findings
    ↓  casefile-approve
Approved findings
    ↓  generate_report.py
IR Report
```

## Understanding Findings

Every finding has a confidence level:

| Level | Meaning | Requirement |
|---|---|---|
| **CONFIRMED** | Corroborated by 2+ independent artifact sources | Must include `evidence_quotes` |
| **INFERRED** | Supported by 1 source, plausible but not cross-confirmed | evidence_quotes recommended |
| **SPECULATIVE** | Hypothesis with no direct artifact support | Flagged for human review |

### Evidence Quotes

CONFIRMED findings must cite exact values from tool output:

```json
{
  "evidence_quotes": [
    {
      "tool": "AmcacheParser",
      "invocation_id": "inv_abc123",
      "field": "FullPath",
      "exact_value": "C:\\Windows\\Temp\\Perfmon\\CSRSS.EXE"
    }
  ]
}
```

The grounding verifier checks:
- **Tier 1**: Does `invocation_id` exist in `audit/mcp.jsonl` with matching tool name?
- **Tier 2**: Does `exact_value` appear as a field value in the tool's CSV output?

## MCP Tools Reference

### Artifact Parsers

**`parse_amcache(amcache_path, output_dir)`**
Parses Amcache.hve. Returns execution history with SHA1 hashes.
Requires LOG1/LOG2 transaction files alongside hive.

**`parse_prefetch(prefetch_dir, output_dir)`**
Parses .pf files via pyscca. Returns execution counts and last run times.

**`parse_event_logs(evtx_path, output_dir, event_ids)`**
Parses .evtx files via EvtxECmd. Common event IDs: 4624, 4625, 4648, 4688, 7045, 1102.

**`parse_registry(hive_path, output_dir)`**
Parses registry hives via RECmd. Covers Run keys, services, UserAssist, BAM.

**`parse_mft(mft_path, output_dir, filename_filter)`**
Parses $MFT via MFTECmd. Returns timestamps with SI<FN flag for timestomping detection.

**`parse_memory(memory_path, output_dir, plugin)`**
Runs Volatility 3 plugins: pslist, psscan, netscan, cmdline, dlllist, malfind.

### Analysis Tools

**`correlate_evidence(process_name, case_dir)`**
Cross-references 4 artifact sources and returns a deterministic verdict:
`CONFIRMED_RUNNING`, `CONFIRMED_HISTORICAL`, `MEMORY_ONLY`, `INSTALLED_NEVER_RAN`, `NOT_FOUND`.
Also returns `contradictions` array with timestomping, fileless, and path-mismatch detections.

**`search_knowledge(query, top_k, category)`**
Searches 260-record forensic knowledge base. Categories: `mitre_attack`, `artifact_guide`,
`sigma`, `methodology`, `lolbas`, `windows_events`, `threat_intel`, `tool_reference`.

### Finding Management

**`record_finding(title, observation, interpretation, confidence, artifact_source, supporting_tool, mitre_technique, evidence_quotes)`**
Stages a finding as DRAFT. Validates evidence_quotes schema. Runs grounding on write.

**`get_findings(status, limit)`**
Retrieves findings filtered by status: DRAFT, APPROVED, REJECTED.

**`record_timeline_event(timestamp, event_type, description, artifact_source, confidence)`**
Adds event to investigation timeline.

**`generate_accuracy_report()`**
Scores investigation against CFA-Bench checkpoints.

## Grounding Verification

After ralph completes, `grounding_verify.py` runs automatically:

```
Exit 0: All claims grounded -- investigation clean
Exit 1: Fatal error (import failure) -- investigation halted
Exit 2: CONTRADICTED claims found -- self-correction loop fires
```

The self-correction prompt is specific:
> "Finding F-001: claim '[exact text]' is CONTRADICTED -- tool output shows '[exact value]'.
> Rewrite using ONLY the grounded claims. Do not add new claims without running a tool."

Up to 3 correction iterations before escalating to human review.

Results written to `analysis/claim_accuracy_report.json`:

```json
{
  "total_claims": 19,
  "grounded": 19,
  "contradicted": 0,
  "hallucination_rate": 0.0,
  "tier2_verified": 8
}
```

## Cross-Host Investigation

When the primary host is investigated, extract IOCs for hunting on other hosts:

```bash
# Extract IOCs from confirmed findings on first host
python3 scripts/propagate_iocs.py \
  --source ~/cases/RD01 \
  --target ~/cases/DC01

# iocs.md is written to target case directory
# Ralph reads iocs.md and hunts for those IOCs on the new host
bash ralph.sh ~/cases/DC01
```

IOC types extracted: IPv4 addresses, internal hostnames, executable names, SHA1/SHA256 hashes.

## Approval Workflow

`casefile-approve` presents each DRAFT finding for review:

```
Finding F-sansproject-001: CSRSS.EXE masquerading
Confidence: CONFIRMED
Evidence: parse_amcache + parse_mft + parse_memory

[a]pprove  [r]eject  [n]ote  [s]kip  [q]uit
```

**Important:** `casefile-approve` is not an MCP tool. Claude cannot call it.
It requires an interactive TTY and password confirmation. This is an architectural
constraint, not a prompt-based restriction.

## Audit Trail

Every action is recorded to `audit/mcp.jsonl`:

```json
{
  "ts": "2026-05-18T08:02:14Z",
  "invocation_id": "amcache-abc123",
  "tool": "AmcacheParser",
  "examiner": "sansproject",
  "cmd": "AmcacheParser.exe -f Amcache.hve --csv analysis/",
  "returncode": 0,
  "parsed_record_count": 223,
  "duration_ms": 4521,
  "csv_files": ["analysis/Amcache_UnassociatedFileEntries.csv"]
}
```

Every finding can be traced back to the exact tool invocation that produced its evidence,
with timestamp, return code, and output file path.
