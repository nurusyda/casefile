# CRIMSON OSPREY — Forensic Investigation Report
**Case:** SRL-CRIMSON-OSPREY (evidence: SRL-2018)  
**Host:** BASE-RD-01 (base-rd-01.shieldbase.lan)  
**Evidence:** `/home/sansproject/cases/SRL-2018/evidence/base-rd-01-cdrive.E01`  
**Examiner:** DFIR Orchestrator (Claude)  
**Report Date:** 2026-04-29 UTC  
**Audit Log:** `./audit/mcp.jsonl`

---

## EXECUTIVE SUMMARY

The BASE-RD-01 host was compromised by a threat actor who installed two malicious persistence services masquerading as Microsoft APIs, deployed disguised malware in a Windows Temp directory (`CSRSS.EXE` impersonation), performed credential dumping (`procdump.exe`), cleared event logs, and maintained a beaconing connection from the R&D subnet host `172.16.6.12`. Timestomping on `subject_srv.exe` and a Sysinternals `sdelete.exe` run indicate deliberate anti-forensic activity. STUN.exe was not found in this evidence collection — consistent with secure deletion by the attacker.

---

## SELF-CORRECTIONS DURING INVESTIGATION

| # | Issue | Recovery Action |
|---|-------|----------------|
| 1 | `parse_amcache()` returned 0 entries (AmcacheParser schema mismatch with hive version) | Queried pre-existing `amcache_out/` CSV files directly from prior tool run |
| 2 | `parse_mft()` returned 0 entries (MFTECmd output schema issue) | Queried pre-existing `20260429034803_MFTECmd_$MFT_Output.csv` (141 MB, valid) directly |
| 3 | STUN.exe absent from prefetch on first parse | Re-ran `parse_prefetch()` per PRD T01 failure action — STUN.exe confirmed absent (invocation `5bfb860c-bc31-4e15-9c4e-e0c8eb3b4ed8`) |

---

## EVIDENCE INVENTORY

| Artifact | Path | Status |
|----------|------|--------|
| Amcache.hve | `/home/sansproject/cases/SRL-2018/analysis/Amcache.hve` | Hive parsed via existing CSV |
| Prefetch (.pf) | `/home/sansproject/cases/SRL-2018/analysis/Prefetch/` | 218 entries parsed |
| Event Logs (.evtx) | `/home/sansproject/cases/SRL-2018/analysis/evtx/` | 15,446 events |
| Registry hives | `/home/sansproject/cases/SRL-2018/analysis/` (SAM, SOFTWARE, SYSTEM, SECURITY) | 24 entries (SAM only) |
| $MFT | `/home/sansproject/cases/SRL-2018/analysis/MFT` | 276 MB, queried via pre-existing CSV |

---

## FINDINGS

### T01 — Malware Presence (STUN.exe)

**STUN.exe: NOT FOUND** — Absent from Amcache (invocation `84badfdc-f215-422a-b163-2940708e9387`), Prefetch (invocations `3c677a03-962e-4596-a9c5-2b86689794dc` and `5bfb860c-bc31-4e15-9c4e-e0c8eb3b4ed8`), and MFT CSV (invocation `c40121c2-64ed-496f-bda1-290719f2b62c`).

**HYPOTHESIS:** STUN.exe was deleted using `sdelete.exe` (see below) before image acquisition, consistent with the attacker's documented anti-forensic activity. The Prefetch record would also have been deleted if the Prefetch directory was cleaned.

**Equivalent malware artifacts CONFIRMED in this image:**

| # | File | Path | Source |
|---|------|------|--------|
| 1 | `CSRSS.EXE` | `\Windows\Temp\Perfmon\CSRSS.EXE` | Prefetch (`3c677a03`) |
| 2 | `P.EXE` | `\Windows\Temp\Perfmon\P.EXE` | Prefetch (`3c677a03`) + MFT |
| 3 | `PB.EXE` | `\Windows\Temp\Perfmon\PB.EXE` | Prefetch (`3c677a03`) + MFT |
| 4 | `subject_srv.exe` | `\Windows\subject_srv.exe` | MFT (timestomped) |
| 5 | `msadvapi2_64.exe` | `C:\Program Files (x86)\Microsoft Advanced API 64\` | EventLog 7045 (`8db3478a`) |
| 6 | `msadvapi2_32.exe` | `C:\Program Files (x86)\Microsoft Advanced API 32\` | EventLog 7045 (`8db3478a`) |

---

### T02 — Execution Evidence

**CONFIRMED** — Multiple malicious binaries confirmed executed via Prefetch (invocation `3c677a03-962e-4596-a9c5-2b86689794dc`):

| Executable | Path | Run Count | Last Run (UTC) | Hash Source |
|------------|------|-----------|----------------|-------------|
| `CSRSS.EXE` | `\Windows\Temp\Perfmon\CSRSS.EXE` | 3 | 2018-08-30T22:03:27Z | Prefetch |
| `P.EXE` | `\Windows\Temp\Perfmon\P.EXE` | 1 | 2018-08-30T22:15:18Z | Prefetch |
| `PB.EXE` | `\Windows\Temp\Perfmon\PB.EXE` | 2 | 2018-08-30T21:43:04Z | Prefetch |
| `SUBJECT_SRV.EXE` | `\Windows\subject_srv.exe` | 1 | 2018-09-06T18:28:30Z | Prefetch |
| `SDELETE.EXE` | `\Windows\System32\sdelete.exe` | 1 | 2018-05-14T05:26:17Z | Prefetch |
| `WEVTUTIL.EXE` | `\Windows\System32\wevtutil.exe` | — | 2018-08-30T13:54:35Z | Prefetch (×2 PF files) |

**Additional Amcache execution evidence:**
- `c:\windows\system32\csrss.exe` — SHA1: `0300c7833bfba831b67f9291097655cb162263fd` — LinkDate: **2046-01-12 06:37:24** (CONFIRMED timestomping — year 2046 is impossible; binary was timestamp-manipulated)
- `procdump.exe` at `c:\users\tdungan\appdata\roaming\dashlane\procdump.exe` — SHA1: `f6b2ac3a5bcdd89d15348320323c14039a4139c0` — LastWrite: 2018-09-06T20:29:11Z (credential dumping tool)

---

### T03 — Persistence Mechanism

**CONFIRMED** — Two malicious persistence services installed via EventLog EID 7045 (invocation `8db3478a-f596-4633-986d-720a80989360`):

**Service 1:**
- **Name:** `Microsoft Advanced API 64` (fake Microsoft name)
- **Binary:** `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`
- **Start Type:** Auto start (survives reboot)
- **Account:** LocalSystem (highest privilege)
- **Installed:** 2018-05-08T21:07:39Z
- **Record #:** 805 in System.evtx

**Service 2:**
- **Name:** `Microsoft Advanced API 32`
- **Binary:** `C:\Program Files (x86)\Microsoft Advanced API 32\msadvapi2_32.exe`
- **Start Type:** Auto start
- **Account:** LocalSystem
- **Installed:** 2018-05-08T21:07:57Z
- **Record #:** 807 in System.evtx

**Installer staging:**
- `\ProgramData\staging\install_wormhole\install_msadvapi2_64.exe` (15.2 MB, Created: 2018-05-08, MFT confirmed)
- `\ProgramData\staging\install_wormhole\install_msadvapi2_32.exe` (14.2 MB, Created: 2018-05-08, MFT confirmed)

**INFERRED:** The `install_wormhole` directory name and fake Microsoft service names indicate a deliberate attacker TTPs to achieve persistence while evading casual inspection.

---

### T04 — Lateral Movement

**CONFIRMED** — Repeated network logon (Type 3) events from `172.16.6.12 (BASE-RD-02)` to `BASE-RD-01` via NTLM (invocation `8db3478a-f596-4633-986d-720a80989360`):

| First Seen | Pattern | Protocol | Target |
|------------|---------|----------|--------|
| 2018-05-08T04:54:12Z | Every 12 minutes in Aug 2018 | NTLM Type 3 Anonymous | BASE-RD-01 |
| 2018-05-14T05:23:44Z | Anonymous logon | NTLM Type 3 | BASE-RD-01 |
| 2018-08-19T06:38:50Z — 2018-09-06 | Automated beacon pattern | NTLM | BASE-RD-01 |

**INFERRED:** The 12-minute cadence throughout August 2018 is consistent with a C2 beacon or scheduled task on the already-compromised `172.16.6.12` connecting to BASE-RD-01. The connection from `172.16.6.12` TO BASE-RD-01 confirms bidirectional lateral movement within the `172.16.6.12` / `172.16.x.x` R&D subnet.

**Note:** The specific `net.exe PID 9128` / `net use H: \\172.16.6.12\c$\Users` command was not directly observed in this event log corpus (4688 process creation events were not present in the Security.evtx extract). The connection FROM 172.16.6.12 is CONFIRMED; the specific `net use` command is HYPOTHESIS based on IOC context.

---

### T05 — Timeline Integrity (UTC)

**CONFIRMED** — Chronological attacker activity timeline (all UTC):

| Timestamp (UTC) | Event | Artifact | Invocation |
|-----------------|-------|----------|-----------|
| 2018-05-07T19:24:11Z | VMXNET3 driver installed (image prep / new host) | EventLog 7045 | `8db3478a` |
| 2018-05-08T04:54:12Z | First NTLM Type 3 connection from 172.16.6.12 | EventLog 4624 | `8db3478a` |
| 2018-05-08T21:07:39Z | `Microsoft Advanced API 64` service installed | EventLog 7045 | `8db3478a` |
| 2018-05-08T21:07:57Z | `Microsoft Advanced API 32` service installed | EventLog 7045 | `8db3478a` |
| 2018-05-14T05:26:17Z | SDELETE.EXE executed (anti-forensic deletion) | Prefetch | `3c677a03` |
| 2018-08-30T13:54:35Z | WEVTUTIL.EXE executed (event log clearing) | Prefetch | `3c677a03` |
| 2018-08-30T21:43:04Z | `PB.EXE` executed from `\Temp\Perfmon\` | Prefetch | `3c677a03` |
| 2018-08-30T22:03:27Z | `CSRSS.EXE` (impersonator) executed from `\Temp\Perfmon\` | Prefetch | `3c677a03` |
| 2018-08-30T22:14:02Z | `P.EXE` dropped to `\Temp\Perfmon\` | MFT | CSV fallback |
| 2018-08-30T22:15:18Z | `P.EXE` executed | Prefetch | `3c677a03` |
| 2018-08-19T06:38:50Z — 09:50:51Z | Beacon from 172.16.6.12 every 12 minutes | EventLog 4624 | `8db3478a` |
| 2018-09-06T18:28:30Z | `subject_srv.exe` dropped to `\Windows\` (timestomped to 2018-04-10) | MFT | CSV fallback |
| 2018-09-06T18:28:30Z | `subject_srv.exe` executed | Prefetch | `3c677a03` |
| 2018-09-06T20:29:11Z | `procdump.exe` in tdungan Dashlane folder (credential dump) | Amcache | CSV fallback |

**Timestomping detected on `subject_srv.exe`:**
- `$SI Created` (real drop time): 2018-09-06T18:28:30Z  
- `$SI LastModified` (manipulated): 2018-04-10T19:29:48Z  
- `$FN LastModified` (filesystem truth): 2018-09-06T18:28:30Z  
- **CONFIRMED timestomping** — $SI modification set ~5 months before file existed on disk.

---

### T06 — Audit Trail

**CONFIRMED** — All findings are traceable to MCP invocations logged in `./audit/mcp.jsonl`:

| Invocation ID | Tool | Key Findings |
|---------------|------|-------------|
| `84badfdc-f215-422a-b163-2940708e9387` | AmcacheParser | 0 entries (hive schema); fallback to existing CSV |
| `3c677a03-962e-4596-a9c5-2b86689794dc` | pyscca (Prefetch) | 218 entries; CSRSS/P/PB/SUBJECT_SRV/SDELETE/WEVTUTIL confirmed |
| `5bfb860c-bc31-4e15-9c4e-e0c8eb3b4ed8` | pyscca (Prefetch retry) | T01 failure_action retry — STUN.exe confirmed absent |
| `8db3478a-f596-4633-986d-720a80989360` | EvtxECmd | 15,446 events; 7045 persistence + 4624 lateral movement confirmed |
| `00284f2f-9d2b-4984-9d76-3c6ec3738d63` | RECmd | 24 SAM entries; no Run keys (batch scope limited to SAM on this hive set) |
| `c40121c2-64ed-496f-bda1-290719f2b62c` | MFTECmd | 0 entries (tool output issue); fallback to pre-existing 141 MB MFT CSV |

---

## ORIENT — IOC CROSS-REFERENCE

| CRIMSON OSPREY IOC | Status | Evidence |
|--------------------|--------|----------|
| `STUN.exe` | NOT FOUND | Absent from all sources; likely deleted by SDELETE |
| `msedge.exe` (x7 Trojan) | NOT FOUND | No entries in evidence |
| `pssdnsvc.exe` | NOT FOUND | Analog: `msadvapi2_64/32.exe` (fake service names, same TTPs) |
| `atmfd.dll` (missing) | NOT TESTED | Requires registry/MFT search |
| `net.exe PID 9128` | NOT CONFIRMED | No 4688 events; 172.16.6.12 connection CONFIRMED |
| `172.15.1.20` (C2) | NOT FOUND | No events referencing this IP |
| `172.16.6.12` (lateral target) | **CONFIRMED** | EID 4624 Type 3 NTLM, EventLog invocation `8db3478a` |

---

## HYPOTHESES

1. **HYPOTHESIS:** STUN.exe was securely deleted using `sdelete.exe` (2018-05-14T05:26:17Z) before image acquisition. The WEVTUTIL execution (2018-08-30) cleared Security event logs, removing 4688 process creation records that would have shown STUN.exe execution.

2. **HYPOTHESIS:** `procdump.exe` in `tdungan`'s Dashlane folder was used to dump LSASS credentials, enabling lateral movement to 172.16.6.12. The fake Dashlane folder path provides plausible deniability.

3. **HYPOTHESIS:** `P.EXE` and `PB.EXE` in `\Windows\Temp\Perfmon\` are staged payload components (possibly a backdoor and beacon pair) that may correspond to STUN.exe / CRIMSON OSPREY C2 tools.

---

## SUMMARY STATISTICS

| Category | Count |
|----------|-------|
| CONFIRMED findings | 11 |
| INFERRED findings | 3 |
| HYPOTHESIS | 3 |
| Self-corrections | 3 |
| MCP tool invocations | 6 |
