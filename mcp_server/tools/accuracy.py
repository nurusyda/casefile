"""
accuracy.py — generate_accuracy_report() MCP tool
Compares APPROVED CaseFile findings against a ground truth file.
Produces structured accuracy metrics for submission and judge review.
Inference Constraint Level: HIGH — reads only, no artifact access.
"""
from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mcp_server.tools._shared import audit_log

CASE_DIR = Path(os.environ.get("CASEFILE_CASE_DIR", Path.home() / "cases" / "active"))
FINDINGS_FILE = CASE_DIR / "findings.json"


def generate_accuracy_report(
    case_id: str,
    ground_truth_file: str,
) -> dict:
    """
    Compare APPROVED CaseFile findings against a ground truth JSON file.

    Args:
        case_id: Identifier for this case (e.g. 'CRIMSON_OSPREY').
        ground_truth_file: Path to ground truth JSON file. Must contain
            a 'checkpoints' list, each with 'id', 'question', 'answer' (bool),
            and optionally 'ioc' and 'notes'.

    Returns:
        Structured accuracy report with TP, FP, FN, hallucination_rate,
        confirmed_ratio, and per-checkpoint scores.
    """
    # Load ground truth
    gt_path = Path(ground_truth_file)
    if not gt_path.exists():
        return {"error": f"Ground truth file not found: {ground_truth_file}"}

    ground_truth = json.loads(gt_path.read_text())
    checkpoints = ground_truth.get("checkpoints", [])

    # Load approved findings
    if not FINDINGS_FILE.exists():
        approved_findings = []
    else:
        all_findings = json.loads(FINDINGS_FILE.read_text())
        approved_findings = [f for f in all_findings if f.get("status") == "APPROVED"]

    total_findings = len(approved_findings)
    confirmed = [f for f in approved_findings if f.get("confidence") == "CONFIRMED"]
    inferred = [f for f in approved_findings if f.get("confidence") != "CONFIRMED"]

    # Score checkpoints
    checkpoint_scores = []
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for cp in checkpoints:
        cp_id = cp["id"]
        question = cp["question"]
        ground_truth_answer = cp.get("answer", False)
        ioc = cp.get("ioc", "")

        # Check if any approved finding references this IOC or checkpoint
        matched = False
        matched_finding_id = None
        for f in approved_findings:
            obs = f.get("observation", "").lower()
            interp = f.get("interpretation", "").lower()
            src = f.get("artifact_source", "").lower()
            if ioc and ioc.lower() in (obs + interp + src):
                matched = True
                matched_finding_id = f.get("finding_id")
                break
            if cp_id.lower() in (obs + interp):
                matched = True
                matched_finding_id = f.get("finding_id")
                break

        if ground_truth_answer and matched:
            result = "TP"
            true_positives += 1
        elif ground_truth_answer and not matched:
            result = "FN"
            false_negatives += 1
        elif not ground_truth_answer and matched:
            result = "FP"
            false_positives += 1
        else:
            result = "TN"

        checkpoint_scores.append({
            "checkpoint_id": cp_id,
            "question": question,
            "ground_truth": ground_truth_answer,
            "casefile_detected": matched,
            "result": result,
            "matched_finding": matched_finding_id,
        })

    # Metrics
    total_checkpoints = len(checkpoints)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    hallucination_rate = false_positives / total_findings if total_findings > 0 else 0.0
    confirmed_ratio = len(confirmed) / total_findings if total_findings > 0 else 0.0

    report = {
        "report_id": f"AR-{case_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
        "case_id": case_id,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "methodology": "CFA-Bench",
        "findings_summary": {
            "total_approved": total_findings,
            "confirmed": len(confirmed),
            "inferred": len(inferred),
            "confirmed_ratio": round(confirmed_ratio, 3),
        },
        "accuracy_metrics": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "hallucination_rate": round(hallucination_rate, 3),
            "checkpoints_total": total_checkpoints,
            "checkpoints_passed": true_positives,
        },
        "checkpoint_scores": checkpoint_scores,
        "ground_truth_file": str(gt_path),
        "ground_truth_sha256": hashlib.sha256(gt_path.read_bytes()).hexdigest(),
    }

    audit_log(
        tool="generate_accuracy_report",
        invocation_id=report["report_id"],
        cmd=f"generate_accuracy_report(case_id={case_id!r}, ground_truth_file={ground_truth_file!r})",
        returncode=0,
        stdout_lines=len(checkpoint_scores),
        stderr_excerpt="",
        parsed_record_count=total_findings,
        duration_ms=0,
        extra={"true_positives": true_positives, "hallucination_rate": round(hallucination_rate, 3)},
    )

    return report
