**Dataset**: SANS FOR508 SRL-2018 "CRIMSON OSPREY" case. The agent was tested across five investigations spanning five distinct hosts from the same intrusion: three disk+memory pairs (workstation BASE-RD-01, domain controller BASE-DC, file server BASE-FILE), one memory-only workstation (`base-wkstn-01`), and a live re-ingest of the workstation E01 (SRL-2018-RD01, 2026-06-12). Coverage spans three artifact categories: disk forensics, AD/DC artifacts, and live memory analysis. Full documentation at `docs/dataset.md`.

**What the agent found, per host:**

- **BASE-RD-01**: confirmed running malware via memory + prefetch + amcache cross-correlation; 10 grounded findings, 0 hallucinations.
- **BASE-DC**: Kerberoasting (975 TGS requests) and DCSync activity; 12 grounded findings, 0 hallucinations.
- **BASE-FILE**: lateral movement evidence and log-clearing anti-forensics (EID 1102, SDELETE, wevtutil); 7 grounded findings, 2 transparent traceability gaps from corrupt `$MFT`, 0 hallucinations.
- **base-wkstn-01 (memory only)**: `subject_srv.exe` C2 listener on TCP 3262, established inbound connection, 6 outbound beaconing attempts to `172.16.4.10:8080`; 6 grounded findings, 4 transparent traceability gaps from Volatility3 PDB symbol resolution failure, 0 hallucinations.
- **base-rd-01 (workstation, live re-ingest 2026-06-12)**: end-to-end live run via `ralph.sh` in a single iteration with zero corrections; 14 claims, 14 grounded (100%), 2 CONFIRMED findings, 0.0% hallucination. 65 turns, API-equivalent cost USD 5.11 at public Sonnet 4.6 rates. Token usage and audit log committed at `results/SRL-2018-RD01_session_tokens.json` and `results/SRL-2018-RD01_audit_sample.jsonl`.

Each evidence item is documented with its source, SHA-256 hash at ingest, artifact provenance, and read-only handling (Law 1: evidence is never modified). Full documentation — including which artifacts were parsed per host, what the agent found, and the known parser-coverage gaps on the file-server hive version — is in the repository at `docs/dataset.md`.
