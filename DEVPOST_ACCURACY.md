POST-CORRECTION GROUNDING VERIFICATION (across all eight investigations — five hosts)

| Dataset        | Host role                       | Claims | Grounded       | Tier 2 | Halluc. | verify.sh |
|----------------|---------------------------------|--------|----------------|--------|---------|-----------|
| SRL-2018       | Workstation (disk+mem)          | 10     | 10 (100%)      | 7      | 0.0%    | ✅ fixture |
| SRL-2018-DC    | Domain Controller               | 12     | 12 (100%)      | 3      | 0.0%    | ✅ fixture |
| SRL-2018-FILE  | File Server                     | 9      | 7 (77.8%)      | 6      | 0.0%    | ✅ fixture |
| SRL-2018-WKSTN | base-wkstn-01 (memory only)     | 10     | 6 (60.0%)      | 3      | 0.0%    | ✅ fixture |
| SRL-2018-RD01  | base-rd-01 (live, 2026-06-12)   | 14     | 14 (100%)      | —      | 0.0%    | live re-run |
| SRL-2018-FILE (live) | File Server (mem-only, 06-13) | 15     | 3 (20.0%)      | 0      | 0.0%    | live re-run |
| SRL-2018-WKSTN (live) | Workstation (mem-only, 06-13) | 12     | 8 (66.7%)      | 0      | 0.0%    | live re-run |
| SRL-2018 (live) | Workstation (disk+mem, 06-13)   | 14     | 14 (100%)      | 0      | 0.0%    | live re-run |
| **Aggregate**  | **5 hosts, 8 investigations**   | **96** | **74 (77.1%)** | **19** | **0.0%** | **41 reproducible** |

Reproducible core: the four `✅ fixture` rows (41 claims) reproduce from a fresh clone via `bash verify.sh`, no raw evidence required. The four live re-runs add breadth (live SIFT OVA, real token capture) and are documented with sanitized audit samples in `results/`. Hallucination rate = CONTRADICTED / total = 0.0% on every dataset.

CaseFile uses two-tier grounding verification:

- **Tier 1 (attestation)**: the claim's tool was actually called with a non-zero record count, verified against the append-only audit log via `invocation_id`.
- **Tier 2 (literal value)**: in addition to Tier 1, the `exact_value` cited in the claim's `evidence_quote` appears as a literal cell in the tool's CSV output.

Hallucination rate = CONTRADICTED claims / total claims. **Zero contradicted across 96 claims, all eight datasets.**

The two ungrounded claims on the file-server case are transparent traceability gaps — the live MFT parser returned 0 entries against a corrupt `$MFT`, so no `csv_files` were available for Tier 2 verification. The grounding verifier correctly refused to label these as CONFIRMED rather than fabricating evidence — exactly the failure mode the architecture is designed to make impossible.

The four ungrounded claims on the WKSTN case reflect a genuine tool failure: `correlate_evidence` returned ERROR because Volatility3 pslist produced 0 records (PDB symbol resolution failure on that specific Windows build). The architecture flagged these as ungrounded rather than fabricating values.

The RD-01 case (14/14 grounded, 0 corrections, 65 turns) was a live run on 2026-06-12 ingesting `base-rd-01-cdrive.E01` + memory end-to-end via `ralph.sh` in a single iteration. API-equivalent cost at public Sonnet 4.6 rates: USD 5.11. This submission ran on a flat Claude Pro subscription, so the figure is the pay-as-you-go equivalent.

**False-positive rate** on a 25-row benign control corpus: **0.0%** (0 rows flagged). The synthetic clean-Windows corpus is passed through five parsers via `tests/test_false_positive.py` (44 tests). `csrss.exe` at `C:\Windows\System32` is NOT flagged; `csrss.exe` at `Temp\Perfmon` IS flagged — proving path-sensitive matching rather than name-blind keyword hits.

**Self-correction in practice**: DC and WKSTN runs both initially triggered the grounding verifier's correction loop and failed across all 3 iterations due to an exact-string tool-name match in the verifier (the alias-string-match bug between `detect_host_type` and `mcp__casefile__detect_host_type`). The architecture printed `Human review required` rather than silently certifying. The fix landed in `grounding.py` (commit `891956b`); both cases re-ran clean. A second real correction event occurred during the live DC re-run on 2026-06-12 (commit `2d7156e`): the agent referenced `total_records` in its Volatility3 attestations while the audit log records `parsed_record_count`. The grounding verifier correctly refused to mark these as grounded, and the correction loop resolved them in 1 iteration. Both pre- and post-correction state are preserved in the committed audit logs. **Zero hallucinations were ever certified; the system either grounded the claim or refused to certify.**

## EVIDENCE INTEGRITY APPROACH

CaseFile enforces evidence integrity architecturally, not via prompts:

1. **Law 1 in CLAUDE.md** states evidence is read-only. The agent never writes to evidence paths.

2. **Tool-surface enforcement**: parsers accept evidence paths as inputs only; write paths are constrained to the case's `analysis/` directory via `_enforce_case_root()` (`mcp_server/tools/_shared.py`), which raises `PathConfinementError` on any path that escapes the case root.

3. **Capability absence**: the destructive and approval capabilities are NOT exposed as MCP tools. `casefile-approve` is a separate CLI requiring a real TTY + `getpass` password. The AI cannot approve its own findings because the capability does not exist in its tool surface.

4. **Bypass-validation matrix** (`docs/SECURITY_MODEL.md`): nine documented bypass-attempt tests, each with file:line references, classified as Architectural (cannot be bypassed) or Environmental (depends on system configuration). BYPASS-1 through BYPASS-6 specifically test spoliation resistance. All architectural tests PASSED. Two GAPs are honestly documented (network egress controls, `BLOCKED_COMMANDS` not enforced at MCP call time — mitigated because no shell-exec tool is registered).

5. **BYPASS-9 (evidence-borne prompt injection)**: six tests prove that adversarial instructions embedded inside evidence content (filenames, registry values, event-log fields, finding text) cannot escalate the agent's privileges, because destructive and approval capabilities are not registered as MCP tools. Injection can bias reasoning; it cannot reach action. The reasoning channel is caught downstream by the grounding verifier.

**Run-to-run variance — host_type classification fork (FILE case).** The SRL-2018-FILE fixture (disk-and-log path, 77.8% grounded) and the 2026-06-13 live SIFT OVA re-run (memory-only path, 20.0% grounded) produced zero overlapping findings against the same evidence. The fork occurred because the re-run's ingest could not extract `$MFT` or `Prefetch/`, causing `detect_host_type` to classify as MEMORY_ONLY, which CLAUDE.md LAW 2 routing restricts to memory-only parsers. The fixture benefited from pre-existing CSV fallbacks and event logs, producing a completely different evidence set (service install, log clearing, timestomping vs. live PIDs, C2 beacons). Both runs: 0.0% hallucination. The WKSTN re-run did not exhibit this fork (both fixture and re-run were MEMORY_ONLY — stable, deterministic). Full analysis in `docs/accuracy_report.md`.

Full methodology, per-checkpoint CFA-Bench scoring, the negative-control / false-positive section, the complete self-correction log, the Volatility3 schema-mismatch note, and the missed-artifacts / hallucinations-found-during-testing subsections are in the repository at `docs/accuracy_report.md` and `docs/SECURITY_MODEL.md`.
