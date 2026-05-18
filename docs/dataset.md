# CaseFile -- Dataset Documentation

*Auto-generated 2026-05-18 05:16 UTC by `scripts/generate_dataset_doc.py`.*
*Do not edit manually -- re-run after each ralph.sh investigation.*

---

## 1. Evidence Dataset

### Source Image

| Field | Value |
|---|---|
| Case | CRIMSON OSPREY (SRL-2018, BASE-RD-01) |
| File | `base-rd-01-cdrive.E01` |
| SHA-256 | `12a622aa3f0ac78b73f4d4e29c34e0ddb0d0ab40e4b0de6d12f7e7af3ff5fde1` |
| Case root | `~/cases/SRL-2018` |
| Source | SANS FOR508 SRL-2018 (real forensic challenge image) |

### Evidence Provenance

The source disk image is a forensically acquired Windows system from the
SANS FOR508 SRL-2018 challenge dataset. Chain of custody is maintained by:

- SHA-256 hash verified at ingest (`scripts/ingest.sh`)
- All analysis performed on extracted copies in `analysis/`, never the original
- Evidence directory is write-blocked via `.claude/settings.json` deny rules
- Every tool invocation recorded to `audit/mcp.jsonl` with timestamps

---

## 2. Artifact Inventory

Artifacts extracted from the disk image by `scripts/ingest.sh`:

| Artifact | Tool Used | Format |
|---|---|---|
| Windows Registry hives (SYSTEM, SOFTWARE, SECURITY, SAM) | RECmd (EZ Tools) | CSV |
| Amcache.hve + transaction logs | RECmd (EZ Tools) | CSV |
| Prefetch files (`*.pf`) | pyscca library | Parsed JSON |
| Windows Event Logs (`*.evtx`) | EvtxECmd (EZ Tools) | CSV |
| Master File Table (`$MFT`) | MFTECmd (EZ Tools) | CSV |
| Memory image (`*.img`) | Volatility 3 | JSON per plugin |

---

## 3. Investigation Results

### Findings Summary

| Metric | Value |
|---|---|
| Total findings recorded | 6 |
| CONFIRMED (multi-source corroboration) | 5 |
| INFERRED (single-source) | 1 |
| SPECULATIVE | 0 |

---

## 4. Grounding & Hallucination Metrics

*As of: 2026-05-18*

| Metric | Value |
|---|---|
| Total claims analyzed | 25 |
| Tier 1 grounded (tool-attested) | 25 |
| Ungrounded | 0 |
| Contradicted (value mismatch) | 0 |
| **Hallucination rate** | **0.0%** |
| Tier 2 verified (CSV value confirmed) | 0 |
| Tier 2 failed | 0 |

**Tier 1** -- every claim must be traceable to a specific tool invocation
ID in `audit/mcp.jsonl`.

**Tier 2** -- opens the actual CSV output and confirms the exact value
cited in the claim exists in the data. Fires when `csv_files` is present
in the audit entry (Amcache, Registry, Event Logs, MFT).

---

## 5. Accuracy Benchmarks (CFA-Bench Methodology)

*Accuracy report dated: 2026-05-18*

| System | Checkpoints Passed | Score |
|---|---|---|
| **CaseFile** | 8 / 8 | **100%** |
| Protocol SIFT (baseline) | 2 / 8 | 25% |

### Checkpoint Detail

| # | Checkpoint | CaseFile | Baseline |
|---|---|---|---|
| 1 | Identify primary persistence mechanism (fake Microsoft service) with artifact source | PASS | PASS |
| 2 | Identify masquerading process (CSRSS.EXE in Temp\Perfmon) with parent process | PASS | FAIL |
| 3 | Identify credential dumping tool with evidence of execution | PASS | FAIL |
| 4 | Identify C2 beaconing (IP + port + interval) from memory analysis | PASS | FAIL |
| 5 | Detect timestomping ($STANDARD_INFORMATION < $FILE_NAME) on attacker binary | PASS | FAIL |
| 6 | Detect anti-forensics (log clearing + secure deletion) | PASS | PASS |
| 7 | Cross-source process correlation (4 artifact sources for key process) | PASS | FAIL |
| 8 | Identify hex-named Cobalt Strike payload | PASS | FAIL |

---

## 6. Tool Invocation Statistics

| Metric | Value |
|---|---|
| Total MCP tool invocations | 26 |
| Total artifact records parsed | 30,933 |
| Total analysis time (tool execution only) | 76.3s |

### Invocations by Tool

| Tool | Invocations |
|---|---|
| `record_timeline_event` | 9 |
| `record_finding` | 6 |
| `AmcacheParser` | 2 |
| `pyscca` | 2 |
| `MFTECmd` | 2 |
| `Volatility3` | 2 |
| `EvtxECmd` | 1 |
| `RECmd` | 1 |
| `correlate_evidence` | 1 |

---

## 7. Known Attacker TTPs Found

| TTP | ATT&CK ID | Evidence Sources |
|---|---|---|
| Masquerading -- fake CSRSS.EXE in Temp\\Perfmon | T1036.005 | Amcache, MFT, Memory |
| Fake signed Microsoft services (msadvapi2_*.exe) | T1036.004 | Amcache |
| Credential dumping via procdump.exe | T1003.001 | Prefetch, Amcache, MFT |
| Timestomping (SI creation date < FN creation date) | T1070.006 | MFT SI<FN flag |
| Log clearing (wevtutil cl) | T1070.001 | Prefetch |
| Secure deletion (sdelete64) | T1070.004 | Amcache, Prefetch |
| C2 beaconing 172.16.6.12:445 every 12 min | T1071.002 | Memory netscan |
| Lateral movement via Dashlane cover path | T1021 | Prefetch (tdungan path) |
| Hex-named Cobalt Strike payload | T1027 | Amcache (40-char hex filename) |

---

## 8. Reproducibility

```bash
# 1. Extract artifacts from E01 disk image
bash scripts/ingest.sh /path/to/base-rd-01-cdrive.E01 SRL-2018

# 2. Set environment
export CASEFILE_CASE_ROOT=~/cases/SRL-2018
export CASEFILE_CASE_DIR=~/cases/SRL-2018
export CASEFILE_EXAMINER=sansproject

# 3. Run autonomous investigation
bash ralph.sh ~/cases/SRL-2018 2>&1 | tee /tmp/ralph_run.log

# 4. Regenerate this document
python3 scripts/generate_dataset_doc.py
```

Expected runtime: 45-90 minutes depending on image size and memory analysis.
