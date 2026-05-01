"""
test_accuracy.py — Tests for generate_accuracy_report() MCP tool.
Validates metric computation, schema, and edge cases.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch
import tempfile
import os


def make_ground_truth(checkpoints, tmp_path):
    gt = {"case_id": "TEST", "checkpoints": checkpoints}
    p = tmp_path / "ground_truth.json"
    p.write_text(json.dumps(gt))
    return str(p)


def make_findings(findings, tmp_path):
    fd = tmp_path / "findings.json"
    fd.write_text(json.dumps(findings))
    return tmp_path


@pytest.fixture
def tmp_case(tmp_path):
    return tmp_path


def call_report(case_dir, gt_file, case_id="TEST"):
    with patch.dict("os.environ", {"CASEFILE_CASE_DIR": str(case_dir)}, clear=False):
        from importlib import reload
        import mcp_server.tools.accuracy as acc
        reload(acc)
        return acc.generate_accuracy_report(case_id=case_id, ground_truth_file=gt_file)


def test_report_schema_keys(tmp_case):
    gt = make_ground_truth([], tmp_case)
    result = call_report(tmp_case, gt)
    for key in ("report_id", "case_id", "generated_utc", "methodology",
                 "findings_summary", "accuracy_metrics", "checkpoint_scores"):
        assert key in result, f"Missing key: {key}"


def test_methodology_is_cfa_bench(tmp_case):
    gt = make_ground_truth([], tmp_case)
    result = call_report(tmp_case, gt)
    assert result["methodology"] == "CFA-Bench"


def test_no_findings_zero_metrics(tmp_case):
    gt = make_ground_truth(
        [{"id": "CP1", "question": "Malware?", "answer": True, "ioc": "STUN.exe"}],
        tmp_case
    )
    result = call_report(tmp_case, gt)
    m = result["accuracy_metrics"]
    assert m["true_positives"] == 0
    assert m["false_negatives"] == 1
    assert m["hallucination_rate"] == 0.0


def test_true_positive_detected(tmp_case):
    findings = [{"finding_id": "F-test-001", "status": "APPROVED",
                 "confidence": "CONFIRMED",
                 "observation": "STUN.exe found in System32",
                 "interpretation": "malware present", "artifact_source": "/cases/amcache.hve"}]
    case_dir = make_findings(findings, tmp_case)
    gt = make_ground_truth(
        [{"id": "CP1", "question": "Malware?", "answer": True, "ioc": "STUN.exe"}],
        tmp_case
    )
    result = call_report(case_dir, gt)
    assert result["accuracy_metrics"]["true_positives"] == 1
    assert result["accuracy_metrics"]["false_negatives"] == 0


def test_false_positive_counted(tmp_case):
    findings = [{"finding_id": "F-test-001", "status": "APPROVED",
                 "confidence": "CONFIRMED",
                 "observation": "STUN.exe seen", "interpretation": "", "artifact_source": ""}]
    case_dir = make_findings(findings, tmp_case)
    gt = make_ground_truth(
        [{"id": "CP1", "question": "Malware?", "answer": False, "ioc": "STUN.exe"}],
        tmp_case
    )
    result = call_report(case_dir, gt)
    assert result["accuracy_metrics"]["false_positives"] == 1


def test_hallucination_rate_calculation(tmp_case):
    findings = [
        {"finding_id": "F-001", "status": "APPROVED", "confidence": "CONFIRMED",
         "observation": "STUN.exe", "interpretation": "", "artifact_source": ""},
        {"finding_id": "F-002", "status": "APPROVED", "confidence": "CONFIRMED",
         "observation": "nothing relevant", "interpretation": "", "artifact_source": ""},
    ]
    case_dir = make_findings(findings, tmp_case)
    gt = make_ground_truth(
        [{"id": "CP1", "question": "Malware?", "answer": False, "ioc": "STUN.exe"}],
        tmp_case
    )
    result = call_report(case_dir, gt)
    assert result["accuracy_metrics"]["hallucination_rate"] == 0.5


def test_confirmed_ratio(tmp_case):
    findings = [
        {"finding_id": "F-001", "status": "APPROVED", "confidence": "CONFIRMED",
         "observation": "", "interpretation": "", "artifact_source": ""},
        {"finding_id": "F-002", "status": "APPROVED", "confidence": "INFERRED",
         "observation": "", "interpretation": "", "artifact_source": ""},
    ]
    case_dir = make_findings(findings, tmp_case)
    gt = make_ground_truth([], tmp_case)
    result = call_report(case_dir, gt)
    assert result["findings_summary"]["confirmed_ratio"] == 0.5


def test_draft_findings_excluded(tmp_case):
    findings = [
        {"finding_id": "F-001", "status": "DRAFT", "confidence": "CONFIRMED",
         "observation": "STUN.exe", "interpretation": "", "artifact_source": ""},
    ]
    case_dir = make_findings(findings, tmp_case)
    gt = make_ground_truth(
        [{"id": "CP1", "question": "Malware?", "answer": True, "ioc": "STUN.exe"}],
        tmp_case
    )
    result = call_report(case_dir, gt)
    assert result["accuracy_metrics"]["true_positives"] == 0


def test_missing_ground_truth_file(tmp_case):
    result = call_report(tmp_case, "/nonexistent/path/gt.json")
    assert "error" in result


def test_report_id_contains_case_id(tmp_case):
    gt = make_ground_truth([], tmp_case)
    result = call_report(tmp_case, gt, case_id="CRIMSON_OSPREY")
    assert "CRIMSON_OSPREY" in result["report_id"]


def test_ground_truth_sha256_present(tmp_case):
    gt = make_ground_truth([], tmp_case)
    result = call_report(tmp_case, gt)
    assert "ground_truth_sha256" in result
    assert len(result["ground_truth_sha256"]) == 64


def test_empty_ioc_checkpoint_no_crash(tmp_case):
    """CP5/CP6-style checkpoints with empty ioc string should not crash or false-match."""
    findings = [{"finding_id": "F-001", "status": "APPROVED", "confidence": "CONFIRMED",
                 "observation": "timeline produced", "interpretation": "", "artifact_source": ""}]
    case_dir = make_findings(findings, tmp_case)
    gt = make_ground_truth(
        [{"id": "CP5", "question": "Coherent UTC timeline produced?", "answer": True, "ioc": ""}],
        tmp_case
    )
    result = call_report(case_dir, gt)
    assert "accuracy_metrics" in result
    assert result["accuracy_metrics"]["checkpoints_total"] == 1


def test_audit_log_entry_on_success(tmp_case, monkeypatch):
    """generate_accuracy_report() must write an audit log entry on success."""
    audit_calls = []

    import mcp_server.tools.accuracy as acc
    original = acc.audit_log

    def mock_audit(**kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(acc, "audit_log", mock_audit)

    gt = make_ground_truth([], tmp_case)
    with __import__("unittest.mock", fromlist=["patch"]).patch.dict(
        "os.environ", {"CASEFILE_CASE_DIR": str(tmp_case)}, clear=False
    ):
        acc.generate_accuracy_report(case_id="TEST", ground_truth_file=gt)

    assert len(audit_calls) == 1
    assert audit_calls[0]["tool"] == "generate_accuracy_report"
    assert audit_calls[0]["returncode"] == 0


def test_audit_log_entry_on_missing_gt(tmp_case, monkeypatch):
    """generate_accuracy_report() must write an audit log entry even on error."""
    audit_calls = []

    import mcp_server.tools.accuracy as acc

    def mock_audit(**kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(acc, "audit_log", mock_audit)

    with __import__("unittest.mock", fromlist=["patch"]).patch.dict(
        "os.environ", {"CASEFILE_CASE_DIR": str(tmp_case)}, clear=False
    ):
        result = acc.generate_accuracy_report(case_id="TEST", ground_truth_file="/nonexistent/gt.json")

    assert "error" in result
    assert len(audit_calls) == 1
    assert audit_calls[0]["returncode"] == 1
