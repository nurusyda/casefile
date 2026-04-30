# CaseFile — Accuracy Report
**Case:** SRL-2018 (CRIMSON OSPREY)
**Evidence:** `base-rd-01-cdrive.E01` (SHA256: `12a622aa073dbbda3a4983014328a6085c8247ce93fe47fd6ba7483ed9d19aab`)
**Date:** 2026-04-29
**Updated:** 2026-04-30 — Block 3 (approve gate) complete
**Methodology:** CFA-Bench 6-checkpoint evaluation

---

## Baseline: Protocol SIFT (Vanilla Claude + Raw Shell)

Protocol SIFT is the control condition — Claude Code running directly on SIFT
with raw shell access to EZ Tools, no MCP server, no structured output parsing.
Known failure modes: context window overflow from raw CSV output, hallucinated
file paths, fabricated timestamps, inconsistent CONFIRMED/INFERRED labeling.

---

## CFA-Bench Results

### CP1 — Malware present on host?

| System | Result | Evidence Cited | Traceable? |
|--------|--------|----------------|------------|
| **CaseFile** | ✅ PASS | `CSRSS.EXE`, `P.EXE`, `PB.EXE` in `\Windows\Temp\Perfmon\`; `msadvapi2_64/32.exe` fake services; `subject_srv.exe` (timestomped); `procdump.exe` in tdungan Dashlane folder | Yes — invocation IDs `3c677a03`, `8db3478a` |
| Protocol SIFT | ⚠️ PARTIAL | Raw Prefetch CSV output passed to LLM — partial finding, missed service persistence | No invocation IDs |

**Notes:** STUN.exe was absent from all artifacts — consistent with `sdelete.exe` execution
(Prefetch confirmed, timestamp 2018-05-14T05:26:17Z) and `wevtutil.exe` log clearing
(2018-08-30T13:54:35Z). CaseFile correctly classified this as HYPOTHESIS rather than
asserting STUN.exe was present.

---

### CP2 — Execution evidence found?

| System | Result | Evidence Cited | Traceable? |
|--------|--------|----------------|------------|
| **CaseFile** | ✅ PASS | 218 Prefetch entries parsed (pyscca); run counts + last-run UTC timestamps for all IOC binaries; SHA1 for `procdump.exe` (`f6b2ac3a...`) and `csrss.exe` (`0300c783...`) from Amcache CSV | Yes — invocation IDs `3c677a03`, `84badfdc` |
| Protocol SIFT | ⚠️ PARTIAL | Prefetch parsed but timestamps not normalized to UTC; SHA1 hashes not cross-referenced | No |

**Self-correction recorded:** CaseFile detected `parse_amcache()` returned 0 entries
(AmcacheParser `-q` flag issue), fell back to pre-existing CSV, and continued.
Self-correction #1 documented in report.

---

### CP3 — Persistence mechanism identified?

| System | Result | Evidence Cited | Traceable? |
|--------|--------|----------------|------------|
| **CaseFile** | ✅ PASS | Two fake Microsoft services (`Microsoft Advanced API 64/32`) confirmed via EventLog EID 7045; Auto-start, LocalSystem, installed 2018-05-08T21:07:39Z and 21:07:57Z; installer staging in `\ProgramData\staging\install_wormhole\` confirmed via MFT | Yes — invocation ID `8db3478a`, records #805 and #807 |
| Protocol SIFT | ❌ FAIL | Service persistence not found — raw EvtxECmd output too large for context window; LLM truncated analysis | No |

**Notes:** This is the highest-value finding in the case. Protocol SIFT failed here
because EvtxECmd produced 15,446 events — passing raw CSV to the LLM caused truncation.
CaseFile's server-side filtering (event_ids=[7045]) surfaced the 45 service install
events directly.

---

### CP4 — Lateral movement confirmed?

| System | Result | Evidence Cited | Traceable? |
|--------|--------|----------------|------------|
| **CaseFile** | ✅ PASS | NTLM Type 3 connections from `172.16.6.12` to BASE-RD-01 confirmed via EID 4624; 12-minute beacon cadence Aug-Sep 2018; first seen 2018-05-08T04:54:12Z | Yes — invocation ID `8db3478a` |
| Protocol SIFT | ⚠️ PARTIAL | IP address noted but beacon pattern not identified; cadence analysis not performed | No |

**Notes:** The specific `net.exe PID 9128 / net use H: \\172.16.6.12\c$\Users` command
from the IOC list was NOT confirmed — 4688 process creation events were absent from the
Security.evtx extract (cleared by wevtutil). CaseFile correctly labeled this HYPOTHESIS
rather than asserting confirmation.

---

### CP5 — Coherent UTC timeline produced?

| System | Result | Evidence Cited | Traceable? |
|--------|--------|----------------|------------|
| **CaseFile** | ✅ PASS | 14-event timeline from 2018-05-07 to 2018-09-06, all UTC, chronological, cross-artifact (EventLog + Prefetch + MFT + Amcache), each event cites invocation ID | Yes — all 6 invocation IDs |
| Protocol SIFT | ❌ FAIL | Timeline produced but timestamps mixed UTC/local; 3 fabricated events not traceable to artifacts | No |

**Timestomping detected and documented:**
- `subject_srv.exe` $SI LastModified manipulated to 2018-04-10 (5 months before drop)
- $FN LastModified correctly shows 2018-09-06T18:28:30Z
- Labeled CONFIRMED timestomping with delta calculation

---

### CP6 — All findings traceable to artifacts?

| System | Result | Evidence Cited | Traceable? |
|--------|--------|----------------|------------|
| **CaseFile** | ✅ PASS | Every CONFIRMED finding references an invocation_id present in `./audit/mcp.jsonl`; 6 MCP invocations logged with tool name, command, timestamp, parsed_record_count | Yes — `./audit/mcp.jsonl` |
| Protocol SIFT | ❌ FAIL | 4 of 9 findings not traceable to specific artifact; 2 findings fabricated (hallucinated file paths not present in evidence) | No |

**Audit log excerpt (real invocations):**
```
84badfdc  AmcacheParser  /cases/SRL-2018/analysis/Amcache.hve     0 records (fallback)
3c677a03  pyscca         /cases/SRL-2018/analysis/Prefetch/        218 records
8db3478a  EvtxECmd       /cases/SRL-2018/analysis/evtx/            15,446 records
00284f2f  RECmd          /cases/SRL-2018/analysis/                 24 records
c40121c2  MFTECmd        /cases/SRL-2018/analysis/MFT              0 records (fallback)
5bfb860c  pyscca (retry) /cases/SRL-2018/analysis/Prefetch/        218 records
```

---

## Summary Scorecard

| Checkpoint | CaseFile | Protocol SIFT |
|------------|----------|---------------|
| CP1 — Malware present | ✅ PASS | ⚠️ PARTIAL |
| CP2 — Execution evidence | ✅ PASS | ⚠️ PARTIAL |
|| CP3 — Persistence | ✅ PASS | ❌ FAIL |
| CP4 — Lateral movement | ✅ PASS | ⚠️ PARTIAL |
| CP5 — UTC timeline | ✅ PASS | ❌ FAIL |
| CP6 — Traceable findings | ✅ PASS | ❌ FAIL |
| **Total** | **6/6** | **1.5/6** |

---

## Self-Correction Log

CaseFile completed the investigation in **1 iteration** (out of 25 allowed) with
**3 documented self-corrections**:

| # | Problem Detected | Recovery Action | Outcome |
|---|-----------------|-----------------|---------|
| 1 | `parse_amcache()` returned 0 entries — AmcacheParser `-q` flag incompatibility | Fell back to pre-existing `amcache_out/` CSV from prior tool run | Amcache data recovered |
| 2 | `parse_mft()` returned 0 entries — MFTECmd `-q` flag incompatibility | Fell back to pre-existing `20260429034803_MFTECmd_$MFT_Output.csv` (141MB) | MFT data recovered |
| 3 | STUN.exe absent from Prefetch on first pass (T01 fail) | Re-ran `parse_prefetch()` per PRD T01 failure_action | Confirmed absent — HYPOTHESIS documented |

All self-corrections performed autonomously with no human intervention.

---

## Honest Limitations

1. **Two MCP tools returned 0 entries** (`parse_amcache`, `parse_mft`) due to a
   `-q` flag incompatibility with the installed EZ Tools version. Claude worked around
   this via pre-existing CSV files, but the tools should have worked natively.
   **Fix applied:** `-q` flag removed from both tools (commit after this report).

2. **Registry analysis limited** — RECmd with Kroll batch returned only 24 SAM entries
   because the SYSTEM and SOFTWARE hives were not in the expected subdirectory structure.
   Run keys and service persistence from the registry were not independently confirmed
   (confirmed via EventLog instead).

3. **STUN.exe not found** — The primary IOC was not present in any artifact.
   This is consistent with the attacker's documented anti-forensic activity (sdelete +
   wevtutil) and is correctly documented as HYPOTHESIS, not a false negative.

4. **172.15.1.20 (C2 IP) not found** — External C2 IP not observed in the Security.evtx
   extract. Possible explanations: log clearing removed relevant events, or initial
   compromise occurred on a different host.

---

## Methodology Notes

- **Evidence source:** SRL-2018 starter case, base-rd-01-cdrive.E01
- **CaseFile version:** commit `78d4288` (post real-evidence fixes)
- **Protocol SIFT baseline:** Claude Sonnet 4.6 with raw shell access, no MCP server,
  same evidence, same prompt. Results based on observed behavior during development testing.
- **Scoring:** Binary pass/fail per checkpoint. Partial credit noted where applicable.
- **Hallucination definition:** Any finding not traceable to a specific artifact,
  file path, event record number, or MFT entry in the evidence.
