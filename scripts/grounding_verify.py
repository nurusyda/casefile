#!/usr/bin/env python3
"""
scripts/grounding_verify.py
============================
Post-completion grounding verification for ralph.sh.

Called by ralph.sh after TASK_COMPLETE is detected.
Reads findings.json, runs verify_finding_claims() and assert_sources_attested()
on every finding, writes analysis/claim_accuracy_report.json.

Exit codes:
  0 — all claims grounded (or grounding module unavailable)
  2 — one or more CONTRADICTED claims detected (triggers correction loop)

Environment variables (all required):
  CASE_DIR        — path to the case directory
  AUDIT_LOG       — path to audit/mcp.jsonl
  FINDINGS_FILE   — path to findings.json
  CLAIM_REPORT    — path to write claim_accuracy_report.json
"""
import json
import os
import sys
from pathlib import Path

try:
    from mcp_server.tools.grounding import (
        verify_finding_claims,
        get_attested_sources,
        assert_sources_attested,
        build_claim_accuracy_report,
    )
except ImportError as e:
    print(f"[grounding] IMPORT ERROR: {e}", flush=True)
    print("[grounding] FATAL: grounding module not available — cannot verify findings.", flush=True)
    sys.exit(1)  # Fatal: grounding module required; exit(0) would silently skip all checks

case_dir = os.environ.get("CASE_DIR", ".")
audit_log_path = os.environ.get("AUDIT_LOG", f"{case_dir}/audit/mcp.jsonl")
findings_file = os.environ.get("FINDINGS_FILE", f"{case_dir}/findings.json")
claim_report_path = os.environ.get("CLAIM_REPORT", f"{case_dir}/analysis/claim_accuracy_report.json")

# Load findings
if not Path(findings_file).exists():
    print(f"[grounding] No findings file at {findings_file} — skipping.", flush=True)
    sys.exit(0)

with open(findings_file, encoding="utf-8") as fh:
    findings = json.load(fh)

if not findings:
    print("[grounding] No findings to verify.", flush=True)
    sys.exit(0)

# Get attested sources from audit log
attested = get_attested_sources(audit_log_path)
print(f"[grounding] Attested tools: {sorted(attested)}", flush=True)

# Verify each finding
results = []
total_contradicted = 0
total_ungrounded = 0
attestation_warnings: list[str] = []

for finding in findings:
    fid = finding.get("id") or finding.get("finding_id", "<unknown>")

    # Source attestation check
    try:
        attn_warns = assert_sources_attested(finding, attested)
        attestation_warnings.extend(attn_warns)
        for w in attn_warns:
            print(f"[grounding] ATTESTATION WARNING: {w}", flush=True)
    except Exception as exc:
        print(f"[grounding] assert_sources_attested failed for {fid}: {exc}", flush=True)

    # Claim-level verification
    try:
        result = verify_finding_claims(finding, audit_log_path)
        results.append(result)

        if result.contradicted > 0:
            total_contradicted += result.contradicted
            for claim in result.claims:
                if claim.status == "CONTRADICTED":
                    print(
                        f"[grounding] CONTRADICTED — {fid}: "
                        f"claim '{claim.claim_text[:80]}' — {claim.note}",
                        flush=True,
                    )
        if result.ungrounded > 0:
            total_ungrounded += result.ungrounded
            print(
                f"[grounding] UNGROUNDED — {fid}: {result.ungrounded} ungrounded claim(s)",
                flush=True,
            )
        if result.passed:
            print(f"[grounding] GROUNDED ✓ — {fid}", flush=True)

    except Exception as exc:
        print(f"[grounding] verify_finding_claims failed for {fid}: {exc}", flush=True)

# Build and write claim accuracy report
if results:
    report = build_claim_accuracy_report(results)
    Path(claim_report_path).parent.mkdir(parents=True, exist_ok=True)
    with open(claim_report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[grounding] Claim accuracy report written to {claim_report_path}", flush=True)
    print(
        f"[grounding] Summary: "
        f"findings={report.get('total_findings', '?')} "
        f"claims={report.get('total_claims', '?')} "
        f"grounded={report.get('grounded', '?')} "
        f"contradicted={report.get('contradicted', '?')} "
        f"hallucination_rate={report.get('hallucination_rate', '?')}",
        flush=True,
    )

# Exit non-zero only if CONTRADICTED claims — forces correction loop
if total_contradicted > 0:
    print(
        f"[grounding] {total_contradicted} CONTRADICTED claim(s) detected. "
        "Signalling correction needed.",
        flush=True,
    )
    sys.exit(2)

if attestation_warnings:
    print(
        f"[grounding] {len(attestation_warnings)} attestation warning(s). "
        "Findings reference tools with no audit log entries.",
        flush=True,
    )

print("[grounding] All claims grounded. ✓", flush=True)
sys.exit(0)
