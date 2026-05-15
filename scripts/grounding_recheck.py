#!/usr/bin/env python3
"""
scripts/grounding_recheck.py
=============================
Re-verification of findings after a correction iteration in ralph.sh.

Lighter than grounding_verify.py — just checks for CONTRADICTED claims
and updates the claim accuracy report. Does not repeat attestation warnings.

Exit codes:
  0 — no CONTRADICTED claims remaining
  2 — CONTRADICTED claims still present (caller should retry or escalate)

Environment variables:
  CASE_DIR        — path to the case directory
  AUDIT_LOG       — path to audit/mcp.jsonl
  FINDINGS_FILE   — path to findings.json
  CLAIM_REPORT    — path to write updated claim_accuracy_report.json
"""
import json
import os
import sys
from pathlib import Path

try:
    from mcp_server.tools.grounding import (
        verify_finding_claims,
        build_claim_accuracy_report,
    )
except ImportError as e:
    print(f"[grounding-recheck] IMPORT ERROR: {e}", flush=True)
    sys.exit(1)  # Fatal: grounding module required; exit(0) would silently skip all checks

case_dir = os.environ.get("CASE_DIR", ".")
audit_log_path = os.environ.get("AUDIT_LOG", f"{case_dir}/audit/mcp.jsonl")
findings_file = os.environ.get("FINDINGS_FILE", f"{case_dir}/findings.json")
claim_report_path = os.environ.get("CLAIM_REPORT", f"{case_dir}/analysis/claim_accuracy_report.json")

if not Path(findings_file).exists():
    print(f"[grounding-recheck] No findings file at {findings_file}.", flush=True)
    sys.exit(0)

with open(findings_file, encoding="utf-8") as fh:
    findings = json.load(fh)

results = []
total_contradicted = 0

for finding in findings:
    fid = finding.get("id") or finding.get("finding_id", "<unknown>")
    try:
        result = verify_finding_claims(finding, audit_log_path)
        results.append(result)
        total_contradicted += result.contradicted
        if result.contradicted > 0:
            for claim in result.claims:
                if claim.status == "CONTRADICTED":
                    print(
                        f"[grounding-recheck] STILL CONTRADICTED — {fid}: "
                        f"'{claim.claim_text[:80]}' — {claim.note}",
                        flush=True,
                    )
    except Exception as exc:
        print(f"[grounding-recheck] verify_finding_claims failed for {fid}: {exc}", flush=True)
        total_contradicted += 1  # Count verification failures as unresolved

if results:
    report = build_claim_accuracy_report(results)
    Path(claim_report_path).parent.mkdir(parents=True, exist_ok=True)
    with open(claim_report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(
        f"[grounding-recheck] hallucination_rate={report.get('hallucination_rate')} "
        f"contradicted={report.get('contradicted')}",
        flush=True,
    )

sys.exit(2 if total_contradicted > 0 else 0)
