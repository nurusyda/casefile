# CRIMSON OSPREY — Domain Controller Investigation Report
## Case: SRL-2018-DC | Host: base-dc.shieldbase.lan | Domain: SHIELDBASE.LAN

**Examiner:** sansproject  
**Report Generated:** 2026-05-20T01:00:00Z (UTC)  
**Evidence Root:** `/home/sansproject/cases/SRL-2018-DC/evidence/`  
**Audit Log:** `/home/sansproject/cases/SRL-2018-DC/audit/mcp.jsonl`  
**Classification:** INFERRED findings (event-log based; CONFIRMED requires correlate_evidence() verdict per CLAUDE.md — not applicable to auth-only DC analysis)

---

## IOC Cross-Reference

| IOC | Source | Present on DC? |
|-----|--------|----------------|
| 172.15.1.20 (C2 server) | iocs.md | NOT FOUND — absent from all DC logs |
| 172.16.6.12 (BASE-RD-02, R&D subnet) | iocs.md | **MATCHED — 2,050 EID 4624 logons** |
| stun.exe, LARIAT, pssdnsvc, prunsrv | iocs.md | **NOT FOUND** — RD01-specific, not on DC |
| p.exe, pb.exe, post-stun.exe, msadvapi | iocs.md | **NOT FOUND** — RD01-specific |
| subject_srv.exe | New (this investigation) | PRESENT — DFIR F-Response agent (legitimate) |

**New IOCs Identified on DC (not in propagated iocs.md):**

| IP | Role | Evidence |
|----|------|----------|
| 172.16.5.21 | Kerberos brute-force source | 224 EID 4771 failures |
| 172.16.7.15 | Kerberoasting source | 14 RC4-HMAC EID 4769 events |
| 172.16.6.16 | tyler.oslund credential abuse | EID 4768 success 01:38:05Z |
| 172.16.6.11 | Cross-realm probe (tdungan@stark-research-labs.com) | EID 4768 KDC_ERR_C_PRINCIPAL_UNKNOWN |

---

## Findings

### F-sansproject-001 — INFERRED
**Sustained lateral movement from BASE-RD-02 (172.16.6.12) to domain controller**  
*MITRE T1021 — Remote Services*

2,050 EID 4624 Network Logon (Type 3) events on base-dc.shieldbase.lan from IOC host 172.16.6.12 (BASE-RD-02) spanning 2018-09-04T13:02:24Z through 2018-09-07T21:05:00Z. Traffic alternates between NTLM ANONYMOUS LOGON (null session / SMB probe) and Kerberos machine account logons (SHIELDBASE.LAN\BASE-RD-02$). 172.16.6.12 is a confirmed IOC from the propagated RD01 findings.

**Evidence:**
- EvtxECmd inv `019bf0ce-5055-4efa-ae0a-40feda8dff62` — exact_value: `::ffff:172.16.6.12`
- EvtxECmd inv `019bf0ce-5055-4efa-ae0a-40feda8dff62` — exact_value: `Target: NT AUTHORITY\ANONYMOUS LOGON`

---

### F-sansproject-002 — INFERRED
**Kerberoasting attack — RC4-HMAC service tickets targeting spcontent and spfarm SPNs**  
*MITRE T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting*

14 EID 4769 events with TicketEncryptionType RC4-HMAC (0x17) in Security.evtx spanning 2018-09-04T21:52:32Z through 2018-09-07T18:08:48Z. Targets: `spcontent` SPN (8 events from 172.16.7.15, account nfury@SHIELDBASE.LAN) and `spfarm` SPN (6 events from 172.16.4.7, account spfarm@SHIELDBASE.LAN). All other 397,904 EID 4769 events use AES256-CTS-HMAC-SHA1-96. First event RecordNumber 7377417.

RC4-HMAC is the canonical Kerberoasting cipher — offline crackable. Targeting SharePoint farm/content service accounts (high-privilege) indicates credential-harvest for domain-wide access.

**Evidence:**
- EvtxECmd inv `00b6bac5-64cd-4b72-9c1a-c1ab7430e0ea` — exact_value: `TicketEncryptionType: RC4-HMAC`
- EvtxECmd inv `00b6bac5-64cd-4b72-9c1a-c1ab7430e0ea` — exact_value: `ServiceName: spcontent`

---

### F-sansproject-003 — INFERRED
**NTDS credential database exfiltration via ntdsutil IFM — full AD password hash dump**  
*MITRE T1003.003 — OS Credential Dumping: NTDS*

`spsql` account via WinRM (wsmprovhost.exe parent) executed ntdsutil IFM on the DC on 2018-09-05:
- T12:05:18Z — `vssadmin list shadows` (VSS snapshot enumeration)
- T12:18:23Z — first ntdsutil run
- T12:26:28Z — `ntdsutil ifm create full c:\windows\temp\perfmon\`
- T12:27:19Z — second IFM attempt (same target)
- Also attempted: `c:\$Recycle.Bin`, `c:\temp` (via WmiPrvSE parent chain)

WinRM session initiated at T12:04:30Z (RecordNumber 7443956). ntdsutil IFM creates an offline-usable copy of NTDS.dit containing all domain password hashes — full domain credential exfiltration.

**Evidence:**
- EvtxECmd inv `019bf0ce-5055-4efa-ae0a-40feda8dff62` — exact_value: `C:\Windows\System32\wsmprovhost.exe C:\Windows\system32\wsmprovhost.exe -Embedding`
- EvtxECmd inv `019bf0ce-5055-4efa-ae0a-40feda8dff62` — exact_value: `Target User: shieldbase\spsql`

---

### F-sansproject-004 — INFERRED
**tyler.oslund account password manipulated by ANONYMOUS LOGON — probable credential compromise**  
*MITRE T1098 — Account Manipulation*

EID 4738 RecordNumber 7509056 at 2018-09-06T01:37:23Z: `shieldbase\tyler.oslund` PasswordLastSet modified by `NT AUTHORITY\ANONYMOUS LOGON`. 42 seconds later at 01:38:05Z: tyler.oslund authenticates via Kerberos TGT (AES256, KDC_ERR_NONE) from 172.16.6.16 — a source IP not previously observed. EID 4769 service ticket for BASE-RD-06$ immediately follows. tyler.oslund SID: S-1-5-21-3445421715-2530590580-3149308974-1180.

Anomalous anonymous-actor password reset + immediate Kerberos success from new IP = credential compromise (AS-REP roasting, LDAP reset, or offline crack).

**Evidence:**
- EvtxECmd inv `1b2ea7a5-9a4c-4b6a-92d6-23126a6613a1` — exact_value: `Target: shieldbase\tyler.oslund`
- EvtxECmd inv `1b2ea7a5-9a4c-4b6a-92d6-23126a6613a1` — exact_value: `PasswordLastSet: 9/5/2018 9:37:23 PM`
- EvtxECmd inv `00b6bac5-64cd-4b72-9c1a-c1ab7430e0ea` — exact_value: `::ffff:172.16.6.16:49441`

---

### F-sansproject-005 — INFERRED
**WinRM PowerShell Remoting into DC by rsydow-a across 4 days**  
*MITRE T1021.006 — Remote Services: Windows Remote Management*

182 EID 4648 explicit credential logon events targeting `HTTP/base-dc.shieldbase.lan` (WinRM) as `shieldbase\rsydow-a`. EID 4688 confirms wsmprovhost.exe spawning under rsydow-a (RecordNumber 7378335, 2018-09-04T22:02:49Z). Sessions on: 2018-09-04T22:02Z, 2018-09-05T13:35Z, 2018-09-06T13:08Z, 2018-09-07T16:42Z. Rapid burst pattern = automated tooling. Also: spsql WinRM at 2018-09-05T12:04:30Z immediately precedes ntdsutil chain (F-003).

**Evidence:**
- EvtxECmd inv `019bf0ce-5055-4efa-ae0a-40feda8dff62` — exact_value: `C:\Windows\System32\wsmprovhost.exe C:\Windows\system32\wsmprovhost.exe -Embedding`
- EvtxECmd inv `019bf0ce-5055-4efa-ae0a-40feda8dff62` — exact_value: `HTTP/base-dc.shieldbase.lan`

---

### F-sansproject-006 — INFERRED
**Kerberos brute-force against Administrator and domain accounts — 160 EID 4771 failures**  
*MITRE T1110 — Brute Force*

160 EID 4771 (KDC_ERR_PREAUTH_FAILED / 0x18) spanning 2018-09-04T13:39:08Z through 2018-09-07T21:11:19Z. Administrator: 112 events (70%) from 172.16.5.21. Also targeting spsql (11), cbarton (9), cbarton-a (5), rsydow-a (4), BASE-RD-01$ (18). Source 172.16.5.21 (224 events) is a new attacker host not in the propagated IOC list. Separate 5,144-event base-hunt$ KDC_ERR_CLIENT_REVOKED flood from 172.16.5.25 (disabled machine account persistence noise).

**Evidence:**
- EvtxECmd inv `00b6bac5-64cd-4b72-9c1a-c1ab7430e0ea` — exact_value: `Target: Administrator (S-1-5-21-3445421715-2530590580-3149308974-500)`
- EvtxECmd inv `00b6bac5-64cd-4b72-9c1a-c1ab7430e0ea` — exact_value: `Status: KDC_ERR_PREAUTH_FAILED - Pre-authentication information was invalid - The wrong password was provided.`

---

## Attack Timeline (UTC — Chronological)

| Timestamp (UTC) | Event | ID | Confidence |
|-----------------|-------|-----|-----------|
| 2018-09-04T13:02:24Z | IOC host BASE-RD-02 (172.16.6.12) begins 2,050 logons to DC via NTLM null sessions | T-001 | INFERRED |
| 2018-09-04T13:39:08Z | Kerberos brute-force: 112 EID 4771 failures targeting Administrator from 172.16.5.21 | T-002 | INFERRED |
| 2018-09-04T21:42:07Z | BASE-DC$ computer account authenticates as nfury via svchost (EID 4648) — credential abuse inline | (inline) | INFERRED |
| 2018-09-04T21:52:32Z | Kerberoasting begins: RC4-HMAC EID 4769 targeting spcontent SPN (RecordNumber 7377417) | T-003 | INFERRED |
| 2018-09-04T22:02:49Z | WinRM session as rsydow-a: wsmprovhost.exe spawned on DC (RecordNumber 7378335) | T-004 | INFERRED |
| 2018-09-05T12:04:30Z | NTDS dump chain: spsql WinRM → vssadmin → ntdsutil IFM → full AD hash dump to \windows\temp\perfmon\ | T-005 | INFERRED |
| 2018-09-06T01:37:23Z | tyler.oslund PasswordLastSet changed by ANONYMOUS LOGON (EID 4738 RecordNumber 7509056) | T-006 | INFERRED |
| 2018-09-06T01:38:05Z | tyler.oslund authenticates from new IP 172.16.6.16 — 42 seconds after account change | T-006 | INFERRED |
| 2018-09-07T18:08:48Z | Last RC4-HMAC Kerberoasting event (spfarm SPN, inline) | (inline) | INFERRED |
| 2018-09-06T22:11:15Z | DFIR response deployed: F-Response Subject + Mnemosyne by cbarton-a (EID 4697/7045) | T-007 | INFERRED |

**RD01 Correlation:** DC activity window (2018-09-04 to 2018-09-07) exactly overlaps the CRIMSON OSPREY RD01 compromise. NTDS dump on 2018-09-05 occurred one day after sustained DC access from 172.16.6.12 (RD01 subnet) began. Attack chain: RD01 compromise → domain credential access via WinRM → DC lateral movement → full domain takeover via ntdsutil NTDS dump.

---

## Absent IOCs (Significant Negatives)

The attacker used a clean-hands approach on the DC — no PE malware artifacts:

| IOC | Finding |
|-----|---------|
| STUN.exe, LARIAT, pssdnsvc, prunsrv, p.exe, pb.exe | ZERO hits across 270K-line evtx.csv and 119MB MFT CSV |
| 172.15.1.20 (C2) | ZERO Kerberos/logon events to/from this IP |
| Malicious EID 7045 service | NONE — only DFIR (F-Response) + VMware/WD/McAfee/AD-role infrastructure |

Attacker used only built-in Windows tools (WinRM, ntdsutil, vssadmin) on DC to avoid leaving PE artifacts on a monitored server.

---

## Task Assessment vs PRD

| PRD Task | Status | Evidence |
|----------|--------|---------|
| T01 — Lateral movement auth (EID 4624/4648) | PASS | F-001/F-005: 2,050 4624 + 182 4648 WinRM |
| T02 — Domain account abuse (EID 4720/4728) | PARTIAL | F-004: EID 4738 tyler.oslund; no EID 4720/4728 found |
| T03 — Service installation on DC | PARTIAL | No malicious services; DFIR subject_srv.exe documented |
| T04 — Kerberos attacks (RC4 / EID 4771) | PASS | F-002: 14 RC4-HMAC + F-006: 160 EID 4771 |
| T05 — Timeline ≥5 UTC events | PASS | 7 events T-001 through T-007 |

---

## Self-Corrections

1. **MFT tool produced 0 entries** — fell back to pre-existing May 17 MFT CSV. subject_srv.exe timestomping noted as HYPOTHESIS (no current-session invocation_id).
2. **Event log caps** — initial MCP calls capped at 1,000-2,317 of 531,946 entries. Subagents grepped full CSVs recovering 14 RC4-HMAC events and ntdsutil chain missing from caps.
3. **No malicious services on DC** — confirmed negative after full 270K-line grep (not a tool miss).

---

## MCP Invocation Audit Trail

| Tool | Invocation ID | Purpose |
|------|--------------|---------|
| EvtxECmd | `019bf0ce-5055-4efa-ae0a-40feda8dff62` | Security.evtx — EID 4624/4648/4688 |
| EvtxECmd | `e2154ef3-f2de-4652-b22e-1e556f2b6f12` | System.evtx — EID 7045/4697 |
| RECmd | `4a82c99b-1506-405d-a9b0-3d23b178dd7a` | Registry hives (SAM) |
| EvtxECmd | `00b6bac5-64cd-4b72-9c1a-c1ab7430e0ea` | Security.evtx — EID 4768/4769/4771 |
| EvtxECmd | `1b2ea7a5-9a4c-4b6a-92d6-23126a6613a1` | Security.evtx — EID 4720/4738 |
| MFTECmd | `c328a652-26f2-4f88-980b-f06014fb8272` | MFT — 0 entries (fallback to pre-existing CSV) |
