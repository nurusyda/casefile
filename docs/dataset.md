# CaseFile — Dataset Documentation

## Source

SANS FOR508 SRL-2018 "CRIMSON OSPREY" case, publicly distributed with the SANS
FOR508 course. The agent was tested across **four investigations spanning four
distinct hosts** from the same intrusion. Three investigations used full disk +
memory pairs; one was a memory-only acquisition.

## Coverage Matrix

| Fixture | Host | Role | Disk image | Memory image |
|---|---|---|---|---|
| SRL-2018 | BASE-RD-01 | Workstation (paired) | `base-rd-01-cdrive.E01` | `base-rd01-memory.img` |
| SRL-2018-DC | BASE-DC | Domain Controller (paired) | `base-dc-cdrive.E01` | `base-dc-memory.img` |
| SRL-2018-FILE | BASE-FILE | File Server (paired) | `base-file-cdrive.E01` | `base-file-memory.img` |
| SRL-2018-WKSTN | `base-wkstn-01` | Workstation (memory only) | — | `base-wkstn-01-memory.img` |

All evidence is from the same SRL-2018 CRIMSON OSPREY intrusion, sourced from
SANS FOR508 course materials.

## Provenance

Each evidence item:

- SHA-256 hash computed and recorded at ingest (`scripts/ingest.sh`)
- Original file never modified — analysis performed on extracted artifacts in `analysis/`
- Evidence directories write-blocked via `.claude/settings.json` deny rules
- Every tool invocation recorded to `audit/mcp.jsonl` with timestamps

Law 1 (CLAUDE.md): evidence is read-only. The agent never writes to evidence paths.

## Artifact Inventory (per host, where available)

| Artifact | Tool | Format | RD-01 | DC | FILE | WKSTN |
|---|---|---|---|---|---|---|
| Registry hives (SYSTEM/SOFTWARE/SECURITY/SAM) | RECmd | CSV | ✓ | ✓ | ✓ | — |
| Amcache.hve + transaction logs | RECmd | CSV | ✓ | ✓ | ✓ | — |
| Prefetch (`*.pf`) | pyscca | JSON | ✓ | — | — | — |
| Windows Event Logs (`*.evtx`) | EvtxECmd | CSV | ✓ | ✓ | ✓ | — |
| $MFT | MFTECmd | CSV | ✓ | ✓ | ✓† | — |
| Memory image (`.img`) | Volatility 3 | JSON | ✓ | ✓ | ✓ | ✓ |
| USN Journal ($J) | MFTECmd $J mode | CSV | ✓ | ✓ | ✓ | — |
| Sigma rule scan | Hayabusa | CSV | ✓ | ✓ | ✓ | — |

†BASE-FILE's `$MFT` was corrupt — MFTECmd returned 0 entries on that hive
version. The grounding verifier correctly flagged the resulting traceability
gap rather than fabricating values.

## What the Agent Found

### BASE-RD-01 (workstation, paired)

Confirmed running malware via cross-correlation of memory + prefetch + amcache:

- `CSRSS.EXE` malicious impersonator in `Windows\Temp\Perfmon\` — timestomped
  SHA1 `0300c7833bfba831b67f9291097655cb162263fd` (Tier 2 verified against
  `Amcache_UnassociatedFileEntries.csv`)
- Execution chain corroborated across Amcache, Prefetch, and Volatility3 pslist
- 10 grounded findings, 0 hallucinations, 0 contradicted

### BASE-DC (domain controller, paired)

DCSync activity and suspicious account creation:

- 975 TGS requests for `spservices` targeting `spfarm` from `172.16.4.7`
  (Kerberoasting)
- 1,025 Logon Type 3 events from `172.16.6.12` (BASE-RD-02 as network logon source)
- AES256 ticket encryption observed in 4769 events
- 12 grounded findings, 0 hallucinations, 0 contradicted

### BASE-FILE (file server, paired)

Lateral movement evidence and anti-forensics:

- EID 1102 (audit log cleared) — security log clearing
- SDELETE / `wevtutil` activity in Amcache execution history
- Corrupt `$MFT` produced 0 parser records; agent correctly recorded the
  traceability gap rather than fabricating
- 9 claims, 7 grounded, 2 transparent traceability gaps, 0 hallucinations,
  0 contradicted

### base-wkstn-01 (memory only)

Live C2 listener and beaconing identified from memory alone:

- `subject_srv.exe` (PID 12528) listening on TCP 3262, established inbound
  connection from `172.16.5.50:56722`
- 6 outbound CLOSED connections from `172.16.7.11` to `172.16.4.10:8080`
  (C2/proxy beaconing pattern)
- Volatility3 PdbSignatureScanner failed on this specific Windows build —
  pslist/pstree/cmdline returned 0 records. Agent flagged 4 ungrounded claims
  rather than inventing process-tree data.
- 10 claims, 6 grounded, 4 transparent traceability gaps, 0 hallucinations,
  0 contradicted

## Aggregate

| Metric | Value |
|---|---|
| Total findings recorded | 31 |
| Total claims verified | 41 |
| Grounded (Tier 1 + Tier 2) | 35 (85.4%) |
| Contradicted (fabricated) | **0** |
| **Hallucination rate** | **0.0%** |
| Transparent traceability gaps | 6 (parser tool failures correctly flagged) |
| Artifact categories tested | 3 (disk, AD/DC, memory) |

Reproduce all four cases via `bash verify.sh` from a fresh clone — no raw
evidence required, the script runs against committed sanitized fixtures.
