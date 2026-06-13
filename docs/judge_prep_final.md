# CaseFile — Judge-Prep Pack (Final State)

Repo: `nurusyda/casefile` @ `main`, commit `1d0839b` (post-reconciliation).
All findings below verified against a fresh clone: `verify.sh` reproduced at
41/35/0/0.0%; the three-claim trace resolved against `results/*_audit_sample.jsonl`;
source read for the claim-to-code trace.

---

## PART A — STAGE TWO DRAFT EVALUATION

Draft ratings on the six equally-weighted criteria, in official tiebreak order.
Judging discretion belongs to the human; every score below is checkable against
the cited evidence. Scale: 5 = best-in-pool, engagement-ready; 3 = competent,
unremarkable; 1 = barely addressed.

### Draft scorecard

| # | Criterion | Draft | One-line justification |
|---|-----------|:----:|------------------------|
| 1 | Autonomous Execution Quality | **4** | Real autonomous self-correction documented (commit `2d7156e`, 0 human intervention, 1 iteration); correction loop + heartbeat rule operational; plan still reads as tool battery rather than hypothesis-driven re-sequencing. |
| 2 | IR Accuracy | **5** | Two-tier verifier, 0.0% hallucination across all 8 datasets, honest ungrounded labeling, genuinely self-critical report; three-claim trace now resolves against `results/*_audit_sample.jsonl` (DC 4/4, FILE 3/3, workstation 3/3). |
| 3 | Breadth & Depth | **4** | Disk + memory + AD/DC + event logs across five hosts, deterministic cross-source correlation engine; Windows-only, no network capture. |
| 4 | Constraint Implementation | **5** | Textbook architectural enforcement: capability absence, path confinement, 9-test bypass matrix incl. evidence-borne injection — all verified in code (38 tests passing). |
| 5 | Audit Trail Quality | **5** | Structured JSONL with invocation-id linkage, timestamps, token usage, by-hand verification doc; `regen_audit_samples.py` guarantees cited IDs resolve in `results/`; full trace pointer in `results/README.md`. |
| 6 | Usability & Documentation | **4** | One-command `verify.sh`, `DEPLOY.md`, mkdocs site, `setup-sift.sh`; a practitioner could deploy from the README. |

Criterion 1 moved from 3 → 4 because the autonomous self-correction evidence
(commit `2d7156e`) is now surfaced explicitly and distinguished from the
human-fixed alias bug. Criterion 5 moved from 4 → 5 because the three-claim
trace gap is closed.

### Per-criterion detail

**1 — Autonomous Execution Quality (4).** The `ralph.sh` loop re-prompts on
incomplete checkpoints and runs a post-investigation grounding correction loop
(up to 3 attempts). The WKSTN fixture audit shows genuine reaction to failure:
`pyscca` returns `rc=127` and Volatility3 `pslist` returns 0 records, and the
agent records only grounded netscan findings. The accuracy report now explicitly
distinguishes two correction events: (a) the alias-bug arc (verifier bug, human
fix, demonstrates refusal-to-certify); (b) the Volatility3 `total_records` →
`parsed_record_count` fix (commit `2d7156e`, agent made schema mistake, verifier
flagged it, agent corrected its own attestations in 1 iteration with zero human
intervention — traceable in `results/SRL-2018-DC_audit_sample.jsonl`). The
latter is the Project Requirement #1 evidence. Held at 4 rather than 5 because
the committed tool-call order reads as a planned plugin battery, not the
"forms a hypothesis, recognizes results don't add up, re-sequences mid-run"
arc the 5-anchor describes.

**2 — IR Accuracy (5).** This is the submission's center of gravity.
`grounding.py` implements Tier 1 (invocation-id attestation) and Tier 2
(`_verify_exact_value_in_csv`, line 368 — exact cited value must appear as a
literal CSV cell). Findings carry CONFIRMED / INFERRED / HYPOTHESIS labels.
The accuracy report is genuinely self-critical: reports 20.0% and 60.0%
grounded cases at face value, names *why* (corrupt `$MFT`, symbol failure),
documents hallucinations caught during testing. 0.0% CONTRADICTED across all
datasets. **The three-claim trace resolves** — `results/*_audit_sample.jsonl`
now contains every cited invocation_id (regenerated via
`scripts/regen_audit_samples.py`). A judge tracing SRL-2018 "CSRSS.EXE
Malicious Impersonator" → `f9a16390…` → `AmcacheParser` rc 0 / 223 records
will find it in the sample file.

**3 — Breadth & Depth (4).** Five hosts from one intrusion across three artifact
classes (disk, AD/DC, live memory). The depth signal is the deterministic
`correlate_evidence` cross-source engine and the memory-only path (proves
grounding works for live acquisition). Ceiling: Windows-only parser surface,
no network-packet analysis.

**4 — Constraint Implementation (5).** Verified in code: `mcp_server/server.py`
registers exactly 23 tools; `casefile-approve` is NOT among them — it is a
separate CLI gated by `sys.stdin.isatty()` + `getpass()`. Evidence writes
confined by `_enforce_case_root()` / `PathConfinementError`. Nine bypass tests
with file:line refs, including BYPASS-9 (evidence-borne prompt injection), all
passing (38 tests). The agent physically cannot run destructive commands.

**5 — Audit Trail Quality (5).** JSONL entries carry `ts` (UTC), `invocation_id`,
`tool`, `returncode`, `parsed_record_count`, `duration_ms`, `cmd`. Per-session
JSON and per-iteration token usage committed. `docs/manual_verification.md`
walks one finding by hand. `results/README.md` has a trace pointer directing
judges to `fixtures/reproducibility/` for full logs. `scripts/regen_audit_samples.py`
guarantees the sample files resolve every cited invocation_id. The investigation
is fully reconstructable.

**6 — Usability & Documentation (4).** `bash verify.sh` reproduces cleanly
(all four fixtures PASS, 0.0% hallucination, exit 0). `setup-sift.sh`,
`docs/DEPLOY.md`, mkdocs site, README quickstart present. A practitioner could
deploy and extend. Not a 5 only because deployment assumes a SIFT/Ubuntu
environment and several external tools.

### Claim-to-code trace (two most impressive claims)

1. *"A two-tier grounding verifier checks every claim against tool output and self-corrects."*
   **SUPPORTED.** `mcp_server/tools/grounding.py`: `_resolve_tool_name` alias map (line 73),
   Tier-1 attestation via `_check_audit_field` (line 277), Tier-2 `_verify_exact_value_in_csv`
   (line 368), `GroundingReport.hallucination_rate` (line 159); correction loop in `ralph.sh`
   and `scripts/grounding_verify.py`.

2. *"The AI cannot approve its own findings because the capability does not exist in its tool surface."*
   **SUPPORTED.** `mcp_server/server.py` `_TOOL_DEFS` lists 23 tools, none of which is approve;
   `mcp_server/tools/findings.py:494` `cli_approve` is CLI-only behind `isatty()` + `getpass()`.

### Red flags (none remain that indicate fabrication)

- **Headline-number consistency — RESOLVED.** All surfaces now lead with 41
  (the judge-reproducible number shown in the demo video), with 96 as breadth.
  Same numbers, same framing, same voice across README, Devpost page, accuracy
  report, and `results/`.
- **Three-claim trace — RESOLVED.** `results/*_audit_sample.jsonl` now contains
  every cited invocation_id. `results/README.md` has a trace pointer.
- **Stale heading — RESOLVED.** `accuracy_report.md` heading now reads
  "(across all eight investigations — five hosts)."
- **Criterion-1 self-correction — RESOLVED.** Autonomous vs human-fixed
  correction events are explicitly distinguished in both the accuracy report
  and README.
- **Compressed commit window (Jun 10–13).** Flag only — within the Apr 15–Jun 15
  period, no post-deadline commits. Timestamps are forgeable; this is a
  follow-up signal, never a verdict.

### Standout elements (worth raising at calibration)

- Capability-absence as the enforcement mechanism (not a prompt) — verifiable in 30 seconds.
- The architecture *refusing to certify* and printing `Human review required` rather than guessing.
- Evidence-borne prompt-injection test (BYPASS-9).
- `verify.sh` reproduced from a fresh clone in under a minute (independently confirmed).
- `regen_audit_samples.py` — deterministic trace guarantee for judge inspection.

### Confidence notes (judgments resting on the team's claims, not independently verified)

- **Video content:** Could not load video. Duration (~4:17), narration, live-terminal
  execution, and on-screen self-correction all need a human to confirm.
- **Live datasets** (RD01, FILE-live, WKSTN-live, SRL-live = 55 of the 96 claims):
  only sanitized audit *samples* are committed. The 41 fixture claims reproduced
  via `verify.sh`; the live ones were not re-derived.
- **"672 tests pass":** from the README; the full pytest suite was not run.
- **Token/cost figures:** from `results/*_session_tokens.json`; not independently checked.
- **Check 4 (Demo Video):** PASS WITH WARNING — video content unverified by this
  assistant. Human must confirm: live terminal, audio narration, self-correction
  on screen, no copyrighted music.

---

## PART B — RECONCILIATION STATUS (all complete)

| Edit | Description | Status |
|------|-------------|--------|
| 1 | Unified accuracy table with `verify.sh` column across README, accuracy_report.md, DEVPOST_ACCURACY.md | ✅ Done |
| 2 | README headline 41-first framing | ✅ Done |
| 3 | DEVPOST_TEXT measured-result paragraph 41-first | ✅ Done |
| 4 | `results/README.md` trace pointer + `regen_audit_samples.py` | ✅ Done |
| 5 | `grounding.py` docstring fix (Phase 2 future → Tier 2 implemented) | ✅ Done |
| 6 | Criterion-1 autonomous self-correction callout in accuracy report + README | ✅ Done |

### Additional improvements beyond the original prep

- **41-first framing across all surfaces** — every headline now matches the demo video.
- **`scripts/regen_audit_samples.py`** — deterministic regeneration of audit samples
  so cited invocation_ids always resolve.
- **Regenerated `results/*_audit_sample.jsonl`** — DC (4/4 cited IDs), FILE (3/3),
  workstation (3/3) all resolve.
- **Two stale "five datasets" references fixed** in README prose (outside the table).
- **Ungrounded math unified** — 2+4+12+4 = 22, 96−74 = 22 ✓.

### Remaining open items (minor, not blocking)

- **Image 9 wording:** The loop prints `0 CONTRADICTED, 4 UNGROUNDED` then
  `GROUNDING FAILURE: CONTRADICTED claims detected` — the second message should
  say "ungrounded or contradicted claims detected" (cosmetic).
- **WKSTN variance section:** The run-to-run variance section in the accuracy
  report should explicitly name the workstation case shown in the video
  (WKSTN at 12 claims then 5 on clean re-run vs committed fixture at 10/6).
- **Re-sequencing evidence for Criterion 1:** If live session transcripts show
  the agent pivoting tools because a result didn't add up, surfacing a 3-sentence
  excerpt would strengthen the Criterion-1 case toward a 5.

---

## REPRODUCIBILITY CHECK (final)

```bash
$ bash verify.sh
=== CaseFile Reproducibility Verification ===
  SRL-2018-DC:    claims=12 grounded=12 contradicted=0 halluc%=0 tier2=3 → PASS
  SRL-2018-FILE:  claims=9  grounded=7  contradicted=0 halluc%=0 tier2=6 → PASS
  SRL-2018-WKSTN: claims=10 grounded=6  contradicted=0 halluc%=0 tier2=3 → PASS
  SRL-2018:       claims=10 grounded=10 contradicted=0 halluc%=0 tier2=7 → PASS
AGGREGATE          claims=41 grounded=35 contradicted=0 halluc%=0.0
✓ All 4 case(s) PASSED reproducibility check.
Exit 0.
```

Three-claim trace (post-regeneration):
```
DC:   4/4 cited invocation_ids resolve in results/SRL-2018-DC_audit_sample.jsonl
FILE: 3/3 cited invocation_ids resolve in results/SRL-2018-FILE_audit_sample.jsonl
WS:   3/3 cited invocation_ids resolve in results/SRL-2018_workstation_audit_sample.jsonl
```

---

*Generated 2026-06-13. This document reflects the repo at commit `1d0839b`
after all reconciliation edits were applied and verified.*
