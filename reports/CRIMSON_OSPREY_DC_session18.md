# CRIMSON OSPREY DC — Session 18 Grounding Correction Report

**Date (UTC):** 2026-06-06  
**Examiner:** sansproject  
**Case:** SRL-2018-DC (base-dc.shieldbase.lan)

---

## Purpose

This session corrected 17 hallucination and ungrounded-claim failures identified by the Tier 2 grounding checker against the previous session's DC findings (F-sansproject-004, -014, -015, -017, -018, -019, -020, -023, -024, -025, -026, -027).

---

## Root Cause

All failures had the same root cause: **stale invocation IDs from prior sessions**. The Tier 2 checker maps `invocation_id` → output CSV to verify `exact_value` strings. Prior-session invocation IDs (`4e9ae18a`, `629cf291`, `55e49440`, `1b2ea7a5`, `ec2d63bc`, `0b2116a4`) are not present in the current session's audit log. Additionally, one value (`PasswordLastSet: 9/5/2018 9:37:23 PM`) was a substring of a field rather than an exact cell value.

---

## Remediation Actions

### Tool Runs (This Session)

| Invocation ID | Tool | Source | EIDs / Purpose |
|---|---|---|---|
| `4d9315cc-f862-43dc-892f-9b4e4c145e99` | EvtxECmd | Security.evtx | 4624, 4738, 4769, 4648, 4771, 4688, 7045 |
| `e132af48-97d5-45f8-bad6-70ec5f66d485` | EvtxECmd | System.evtx | 7045 (F-Response service install) |

### Corrected Findings

| Original Finding | New Finding | Issue Fixed |
|---|---|---|
| F-sansproject-004 | F-sansproject-028 | Replaced substring `PasswordLastSet: 9/5/2018 9:37:23 PM` → `NT AUTHORITY\ANONYMOUS LOGON` (UserName column cell); updated invocation to `4d9315cc` |
| F-sansproject-014 | F-sansproject-029 | Stale inv `55e49440` → `4d9315cc`; removed non-schema `audit_field`/`audit_expected` fields |
| F-sansproject-015 | F-sansproject-030 | Stale inv `4e9ae18a` → `4d9315cc`; `ServiceName: spcontent` and `TicketEncryptionType: RC4-HMAC` confirmed in current session CSV |
| F-sansproject-017 | F-sansproject-031 | Stale inv `4e9ae18a` → `4d9315cc`; values confirmed in current session EID 4738 CSV |
| F-sansproject-018 | F-sansproject-032 | Stale inv `4e9ae18a` → `4d9315cc`; `Target: SHIELDBASE.LAN\rsydow-a` and `TargetServerName: base-dc.shieldbase.lan` confirmed in EID 4648 CSV |
| F-sansproject-019 | F-sansproject-033 | Stale inv `4e9ae18a` → `4d9315cc`; EID 4771 values confirmed in current session CSV |
| F-sansproject-020 | F-sansproject-034 | Dropped MFTECmd quote with no `exact_value` (0 entries = no cell to cite); retained correlate_evidence NOT_FOUND quote |
| F-sansproject-023 | F-sansproject-035 | Replaced composite `ServiceFileName:...` with `Name: F-Response Subject` (PayloadData1, inv `e132af48`); updated `PID: 0x1408` to inv `4d9315cc` (confirmed in EID 4688) |
| F-sansproject-024 | F-sansproject-036 | Replaced audit metadata quote with `A new process has been created` (MapDescription, inv `4d9315cc`) |
| F-sansproject-025 | F-sansproject-037 | Stale inv `629cf291` → `4d9315cc`; `LogonType 3` confirmed as PayloadData2 in EID 4624 row |
| F-sansproject-026 | F-sansproject-038 | Dropped MFTECmd quota with no `exact_value`; retained correlate_evidence NOT_FOUND; added EID 4688 `PID: 0x1408` corroboration |
| F-sansproject-027 | F-sansproject-039 | Replaced stale inv `629cf291` → `4d9315cc`; `PID: 0x1408` confirmed in EID 4688 Security.csv |

---

## Forensic Validity of Corrected Claims

All corrected `exact_value` strings are verbatim field values from EvtxECmd CSV output in the current session:

- `Target: NT AUTHORITY\ANONYMOUS LOGON` — PayloadData1 of EID 4624 rows (and UserName of EID 4738)
- `LogonType 3` — PayloadData2 of EID 4624 rows
- `ServiceName: spcontent` — PayloadData2 of EID 4769 rows
- `TicketEncryptionType: RC4-HMAC` — PayloadData4 of EID 4769 rows
- `Target: shieldbase\tyler.oslund` — PayloadData1 of EID 4738 row
- `NT AUTHORITY\ANONYMOUS LOGON` — UserName column of EID 4738 row
- `Target: SHIELDBASE.LAN\rsydow-a` — PayloadData1 of EID 4648 rows
- `TargetServerName: base-dc.shieldbase.lan` — PayloadData2 of EID 4648 rows
- `Target: Administrator (S-1-5-21-3445421715-2530590580-3149308974-500)` — PayloadData1 of EID 4771 rows
- `::ffff:172.16.5.21:62872` — RemoteHost column of EID 4771 rows
- `Name: F-Response Subject` — PayloadData1 of EID 7045 row (System.evtx)
- `PID: 0x1408` — PayloadData2 of EID 4688 subject_srv.exe row
- `A new process has been created` — MapDescription of EID 4688 rows

---

## Finding Inventory

- **Total findings staged:** 39 (F-sansproject-001 through F-sansproject-039)
- **Approved:** 0 (requires human examiner TTY gate)
- **CONFIRMED findings:** 7 (F-007 through F-013)
- **INFERRED findings:** 32

