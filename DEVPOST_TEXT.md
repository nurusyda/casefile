## The problem

Autonomous AI agents are now running real intrusions at machine speed — the 2025 GTG-1002 campaign showed an AI executing 80–90% of an operation with humans intervening only a handful of times. The defender's side of that equation is still manual. And the obvious fix — point an LLM at forensic artifacts — fails in the one way that matters most in DFIR: it hallucinates. A fabricated execution timestamp or an invented service name doesn't just waste time; it corrupts the investigation.

**CaseFile is built on one conviction: in forensics, an unverified finding is worse than no finding.** So instead of trusting the model to be careful, we made it *architecturally unable* to fabricate an accepted finding.

## What it does

CaseFile is a custom MCP (Model Context Protocol) server that gives Claude Code structured, typed access to 13 Windows forensic parsers (Amcache, Prefetch, Event Logs, Registry, MFT, ShellBags, LNK, JumpLists, Hayabusa, Volatility 3, and more), a deterministic cross-source correlation engine, and — the core of the project — a **two-tier grounding verifier** that checks every claim the agent makes against the actual tool output, then **self-corrects** when a claim fails.

- **Tier 1** confirms the invocation ID behind a claim exists in the append-only audit log.
- **Tier 2** opens the parser's CSV output and confirms the exact value cited (a hash, a service name, a timestamp) appears as a literal cell — catching the "right tool, wrong value" failure mode.
- If any claim is CONTRADICTED, `ralph.sh` feeds a targeted correction prompt back to Claude Code (up to 3 attempts) until every claim is grounded or the budget runs out.

Measured result across five distinct hosts from the SANS SRL-2018 CRIMSON OSPREY case — three disk+memory pairs (workstation BASE-RD-01, domain controller BASE-DC, file server BASE-FILE), one memory-only workstation (`base-wkstn-01`), and a live re-ingest of the workstation E01 (SRL-2018-RD01, 2026-06-12) — spanning three artifact categories (disk forensics, AD/DC artifacts, and live memory analysis): **0.0% hallucination over 55 claims (49 grounded, 89.1%).**

## How we built it

The whole system runs under seven non-negotiable investigation laws defined in `CLAUDE.md`: evidence is read-only, the agent routes through MCP tools and never raw shell, it labels every finding CONFIRMED / INFERRED / HYPOTHESIS, and it logs every tool call. Crucially, the destructive and approval capabilities **are not exposed as MCP tools at all** — `casefile-approve` is a separate CLI that requires a human TTY and password. The AI cannot approve its own findings because the capability does not exist in its tool surface.

We documented and tested this in a bypass-validation matrix (`docs/SECURITY_MODEL.md`): nine bypass attempts, each classified as architecturally blocked or environment-dependent, with file-and-line references. BYPASS-9 specifically tests **evidence-borne prompt injection** — adversarial instructions planted in filenames, registry values, and log fields — and proves they can influence the model's reasoning but cannot reach a privileged action.

Late in the project we added a USN Journal parser specifically to counter anti-forensic file deletion — the SDELETE and `wevtutil` activity in the file-server image. The change journal preserves rename/delete events even when the MFT record is gone.

## Challenges we ran into

The honest ones, because they shaped the design:

- **Verification is harder than generation.** Proving a claim is grounded required parsing CSV outputs back into comparable cell values and handling channel filtering so a System-log claim isn't "verified" against a Security log.
- **Real evidence breaks parsers.** On the file-server image, the live Amcache and MFT parsers returned 0 entries on that hive version, and one image had a corrupt `$MFT`. On the second workstation run, Volatility3 pslist returned 0 records due to a PDB symbol resolution failure on that specific Windows build. Rather than fabricate, the framework flags the traceability gap transparently — which is why the file-server reports 77.8% grounded and the memory-only workstation reports 60% grounded, both with 0% hallucination, not a fake 100%.
- **Making it reproducible by a stranger.** We built `verify.sh` so a judge can re-run grounding verification against committed sanitized fixtures and reproduce our numbers from a fresh clone, with no raw evidence required. Four committed fixture cases, 41 claims, exit 0 in under a minute. The fifth case (RD-01, 14/14 grounded, 0 corrections) is documented as a live-run case — its token usage and audit log are committed at `results/SRL-2018-RD01_session_tokens.json` and `results/SRL-2018-RD01_audit_sample.jsonl`.
- **Self-correction has limits, and the architecture has to make that visible.** Two of our cases initially triggered the correction loop and failed across all 3 iterations. The system printed `Human review required` and stopped certifying claims. Investigation revealed a strict-string-match in the verifier itself — a bug in the verification layer, not the agent. The fix went into `grounding.py` (commit `891956b`); both cases re-ran clean. We consider this the architecture working as designed: refuse to silently certify, force investigation when the loop can't converge. A second correction event occurred during the live DC re-run on 2026-06-12 (commit `2d7156e`): the agent referenced `total_records` while the audit log records `parsed_record_count`, producing 5 UNGROUNDED claims. The grounding verifier correctly refused to certify them, and the correction loop resolved all 5 in 1 iteration. A real schema gap surfaced in production, was flagged transparently, and self-corrected.

## What we learned

That the right place to enforce truthfulness in an AI agent is the **capability layer, not the prompt**. Prompts are advisory; a tool that isn't registered cannot be called. Every guarantee CaseFile makes that actually holds is one we moved out of the prompt and into the architecture.

## What's next

Cross-case correlation via OpenSearch indexing of the audit log. Validation against the SANS FOR526 memory-forensics case and a Linux-host DFIR corpus to widen the parser surface beyond Windows. A browser-based examiner review portal so the approval gate doesn't need to be a TTY. And — the most important one — a public benchmark that other teams can run their agents against, so "hallucination rate on real evidence" becomes a measurable property of any DFIR agent, not just ours.
