**Dataset**: SANS FOR508 SRL-2018 "CRIMSON OSPREY" case. The agent was tested across eight investigations spanning five distinct hosts from the same intrusion: four committed reproducibility fixtures plus four live re-runs on a clean SIFT Workstation 2024.4 OVA (2026-06-12 and 2026-06-13), with real token usage captured from Claude Code session transcripts. Coverage spans three artifact categories: disk forensics, AD/DC artifacts, and live memory analysis. Full documentation at `docs/dataset.md`.

**What the agent found, per host:**

- **BASE-RD-01 (fixture)**: confirmed running malware via memory + prefetch + amcache cross-correlation; 10 grounded findings, 0 hallucination.
- **BASE-RD-01 (live re-run, 2026-06-13)**: disk path reproducible on clean SIFT OVA with Prefetch (219 .pf) + Event Logs (296 .evtx); 14 claims, 14 grounded (100%), 0 hallucination. $3.83 USD API-equiv.
- **BASE-DC**: Kerberoasting (975 TGS requests) and DCSync activity; 12 grounded findings, 0 hallucination. Live re-run self-correction (Volatility3 schema mismatch) resolved in 1 iteration. $6.47.
- **BASE-FILE (fixture)**: lateral movement evidence and log-clearing anti-forensics (EID 1102, SDELETE, wevtutil); 7 grounded, 2 transparent traceability gaps from corrupt `$MFT`, 0 hallucination.
- **BASE-FILE (live re-run, 2026-06-13)**: memory-only path — `$MFT` and `Prefetch/` not extracted during ingest, causing MEMORY_ONLY classification. 15 claims, 3 grounded (20.0%), 0 contradicted. Discovered completely different evidence (live PID 6160, C2 beacons) vs. fixture (service install, log clearing). Both 0% hallucination. $5.28.
- **base-wkstn-01 (fixture)**: `subject_srv.exe` C2 listener on TCP 3262, established inbound connection, beaconing to `172.16.4.10:8080`; 6 grounded, 4 traceability gaps, 0 hallucination.
- **base-wkstn-01 (live re-run, 2026-06-13)**: stable re-run — same 4 observations as fixture, 8/12 grounded (66.7%), 0 contradicted. Consistent because both runs were MEMORY_ONLY. $5.38.
- **base-rd-01 (RD-01 live run, 2026-06-12)**: memory-focused path; 14 claims, 14 grounded (100%), 2 CONFIRMED findings, 0 corrections. $5.11.

Each evidence item is documented with its source, SHA-256 hash at ingest, artifact provenance, and read-only handling (Law 1: evidence is never modified). Full documentation — including which artifacts were parsed per host, what the agent found, and the known parser-coverage gaps on the file-server hive version — is in the repository at `docs/dataset.md`.
