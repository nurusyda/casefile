"""
tests/test_export_findings.py — Tests for the export_findings MCP tool.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.tools.export_findings import export_findings, _finding_to_ecs, _finding_to_ocsf


@pytest.fixture(autouse=True)
def _mock_audit_log(monkeypatch):
    monkeypatch.setattr("mcp_server.tools.export_findings.audit_log", lambda **kwargs: None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_FINDING = {
    "finding_id": "F-casefile-001",
    "title": "Fake Windows service with C2 endpoint",
    "observation": "msadvapi2_64.exe registered as a Windows service with 172.16.6.12 as argument.",
    "interpretation": "Attacker installed a persistent backdoor using F-Response disguised as a Microsoft service.",
    "confidence": "HIGH",
    "provenance": "CONFIRMED",
    "status": "APPROVED",
    "severity": "CRITICAL",
    "mitre_ids": ["T1543.003", "T1543"],
    "iocs": ["172.16.6.12", "msadvapi2_64.exe"],
    "supporting_invocation_ids": ["inv-abc123"],
    "created_at": "2026-05-19T10:00:00+00:00",
    "timestamp": "2018-03-15T08:30:00+00:00",
}

SAMPLE_DRAFT_FINDING = {
    "finding_id": "F-casefile-002",
    "title": "CSRSS masquerading in Temp directory",
    "observation": "CSRSS.EXE running from C:\\Windows\\Temp\\Perfmon\\.",
    "interpretation": "Process masquerading as legitimate CSRSS to evade detection.",
    "confidence": "HIGH",
    "provenance": "CONFIRMED",
    "status": "DRAFT",
    "severity": "CRITICAL",
    "mitre_ids": ["T1036.005"],
    "iocs": [],
    "supporting_invocation_ids": ["inv-def456"],
}


@pytest.fixture
def case_dir(tmp_path):
    """Set up a temporary case directory with sample findings."""
    findings_data = {"findings": [SAMPLE_FINDING, SAMPLE_DRAFT_FINDING]}
    (tmp_path / "findings.json").write_text(json.dumps(findings_data))
    (tmp_path / "exports").mkdir(exist_ok=True)
    return tmp_path


@pytest.fixture
def env_case_dir(case_dir, monkeypatch):
    """Set CASEFILE_CASE_DIR to the temp case dir."""
    monkeypatch.setenv("CASEFILE_CASE_DIR", str(case_dir))
    return case_dir


# ---------------------------------------------------------------------------
# ECS conversion unit tests
# ---------------------------------------------------------------------------

class TestFindingToEcs:
    def test_basic_structure(self):
        event = _finding_to_ecs(SAMPLE_FINDING, "SRL-2018")
        assert event["ecs"]["version"].startswith("8.")
        assert event["event"]["kind"] == "finding"
        assert event["event"]["id"] == "F-casefile-001"

    def test_severity_mapping(self):
        event = _finding_to_ecs(SAMPLE_FINDING, "SRL-2018")
        assert event["event"]["severity"] == 99  # CRITICAL

    def test_medium_severity(self):
        f = {**SAMPLE_FINDING, "severity": "MEDIUM"}
        event = _finding_to_ecs(f, "SRL-2018")
        assert event["event"]["severity"] == 47

    def test_mitre_techniques_split(self):
        event = _finding_to_ecs(SAMPLE_FINDING, "SRL-2018")
        # T1543 has no dot — should be in technique, not subtechnique
        techniques = [t["id"] for t in event["threat"]["technique"]]
        subtechniques = [t["id"] for t in event["threat"]["subtechnique"]]
        assert "T1543" in techniques
        assert "T1543.003" in subtechniques

    def test_iocs_included(self):
        event = _finding_to_ecs(SAMPLE_FINDING, "SRL-2018")
        assert "indicator" in event
        assert "172.16.6.12" in event["indicator"]["description"]

    def test_no_iocs(self):
        f = {**SAMPLE_FINDING, "iocs": []}
        event = _finding_to_ecs(f, "SRL-2018")
        assert "indicator" not in event

    def test_case_id_in_labels(self):
        event = _finding_to_ecs(SAMPLE_FINDING, "SRL-2018")
        assert event["labels"]["case_id"] == "SRL-2018"

    def test_supporting_invocations_in_labels(self):
        event = _finding_to_ecs(SAMPLE_FINDING, "SRL-2018")
        assert "supporting_invocations" in event["labels"]
        assert "inv-abc123" in json.loads(event["labels"]["supporting_invocations"])


# ---------------------------------------------------------------------------
# OCSF conversion unit tests
# ---------------------------------------------------------------------------

class TestFindingToOcsf:
    def test_class_uid(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert event["class_uid"] == 2004
        assert event["class_name"] == "Security Finding"

    def test_severity_id(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert event["severity_id"] == 5  # CRITICAL

    def test_status_approved(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert event["status_id"] == 1

    def test_status_draft(self):
        event = _finding_to_ocsf(SAMPLE_DRAFT_FINDING, "SRL-2018")
        assert event["status_id"] == 0

    def test_attacks_array(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert "attacks" in event
        technique_ids = [a["technique"]["uid"] for a in event["attacks"]]
        assert "T1543.003" in technique_ids
        assert "T1543" in technique_ids

    def test_no_attacks_when_no_mitre(self):
        f = {**SAMPLE_FINDING, "mitre_ids": []}
        event = _finding_to_ocsf(f, "SRL-2018")
        assert "attacks" not in event

    def test_observables_from_iocs(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert "observables" in event
        names = [o["name"] for o in event["observables"]]
        assert "172.16.6.12" in names

    def test_metadata_product(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert event["metadata"]["product"]["name"] == "CaseFile"
        assert event["metadata"]["version"] == "1.3.0"

    def test_finding_uid(self):
        event = _finding_to_ocsf(SAMPLE_FINDING, "SRL-2018")
        assert event["finding"]["uid"] == "F-casefile-001"


# ---------------------------------------------------------------------------
# export_findings integration tests
# ---------------------------------------------------------------------------

class TestExportFindings:
    def test_ecs_export_approved_only(self, env_case_dir):
        result = export_findings(format="ecs", status_filter="APPROVED")
        assert result["exported_count"] == 1
        assert result["format"] == "ecs"
        assert result["output_path"] is not None
        assert len(result["events"]) == 1
        assert result["events"][0]["event"]["id"] == "F-casefile-001"

    def test_ocsf_export_approved_only(self, env_case_dir):
        result = export_findings(format="ocsf", status_filter="APPROVED")
        assert result["exported_count"] == 1
        assert result["events"][0]["class_uid"] == 2004

    def test_export_all_no_filter(self, env_case_dir):
        result = export_findings(format="ecs", status_filter=None)
        assert result["exported_count"] == 2

    def test_export_draft_only(self, env_case_dir):
        result = export_findings(format="ecs", status_filter="DRAFT")
        assert result["exported_count"] == 1
        assert result["events"][0]["event"]["id"] == "F-casefile-002"

    def test_output_file_written(self, env_case_dir):
        result = export_findings(format="ecs", status_filter=None)
        out = env_case_dir / result["output_path"]
        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) == 2

    def test_custom_output_path(self, env_case_dir):
        out = str(env_case_dir / "exports" / "custom_export.json")
        result = export_findings(format="ocsf", status_filter=None, output_path=out)
        assert result["output_path"] == "exports/custom_export.json"
        assert (env_case_dir / result["output_path"]).exists()

    def test_unknown_format_returns_error(self, env_case_dir):
        result = export_findings(format="stix")  # type: ignore
        assert "error" in result
        assert result["exported_count"] == 0

    def test_missing_findings_json(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASEFILE_CASE_DIR", str(tmp_path))
        result = export_findings(format="ecs")
        assert "error" in result
        assert result["exported_count"] == 0

    def test_empty_findings_list(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASEFILE_CASE_DIR", str(tmp_path))
        (tmp_path / "findings.json").write_text('{"findings": []}')
        result = export_findings(format="ecs", status_filter=None)
        assert result["exported_count"] == 0
        assert result["events"] == []

    def test_ecs_output_is_valid_json_list(self, env_case_dir):
        result = export_findings(format="ecs", status_filter=None)
        # Each event should be serializable
        for event in result["events"]:
            serialized = json.dumps(event)
            restored = json.loads(serialized)
            assert restored["event"]["kind"] == "finding"

    def test_ocsf_output_is_valid_json_list(self, env_case_dir):
        result = export_findings(format="ocsf", status_filter=None)
        for event in result["events"]:
            serialized = json.dumps(event)
            restored = json.loads(serialized)
            assert restored["class_uid"] == 2004
