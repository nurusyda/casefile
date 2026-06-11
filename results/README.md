# CaseFile — Validation Results

This directory contains the raw output from four independent ralph.sh investigation runs
against the SRL-2018 CRIMSON OSPREY case. These files are the primary evidence for the
0.0% hallucination rate claimed in the project README.

## Accuracy Reports

| File | Dataset | Run |
|---|---|---|
| `SRL-2018_workstation_session20.json` | BASE-RD-01 (workstation) | Session 20, 2026-06-06 |
| `SRL-2018-DC_session19.json` | BASE-DC (domain controller) | Session 19, 2026-06-06 |
| `SRL-2018-FILE_session01.json` | BASE-FILE (file server) | Session 01, 2026-06-06 |
| `SRL-2018-WKSTN_audit_sample.jsonl` | Workstation memory-only (base-wkstn-01) | 2026-06-11 |

Each file is produced by `scripts/grounding_verify.py` after ralph.sh completes.
It records every claim, whether it was grounded via Tier 1 (audit log match) or
Tier 2 (CSV cell-value match), and whether any claim was CONTRADICTED (fabricated).

**Hallucination rate** = `contradicted / total_claims`. Zero contradicted claims across
all four runs = 0.0% hallucination rate.

**Ungrounded** (2 claims in SRL-2018-FILE) means the audit entry lacked a csv_files
field — the value was not fabricated, but cannot be traced to a specific CSV cell.
This is a traceability gap, not a fabrication. The framework flags it transparently.

## Findings Files

| File | Contents |
|---|---|
| `SRL-2018_workstation_findings.json` | 5 findings from BASE-RD-01 investigation |
| `SRL-2018-DC_findings.json` | 6 findings from BASE-DC investigation |
| `SRL-2018-FILE_findings.json` | 6 findings from BASE-FILE investigation |
| `fixtures/reproducibility/SRL-2018-WKSTN/findings.json` | 8 findings from workstation re-run (live OVA) |

Each finding carries: label (CONFIRMED/INFERRED), evidence quotes, invocation IDs
linking back to `audit/mcp.jsonl`, and MITRE ATT&CK technique references.

## Reproducing Results

Follow `docs/DEPLOY.md` to set up the environment, then:

```bash
export CASEFILE_CASE_ROOT=~/cases/<your-case>
export CASEFILE_CASE_DIR=~/cases/<your-case>
export CASEFILE_EXAMINER=yourname
bash ralph.sh ~/cases/<your-case> 2>&1 | tee /tmp/ralph-run.log
```

The grounding report is written to `<case-dir>/analysis/claim_accuracy_report.json`
on completion.
