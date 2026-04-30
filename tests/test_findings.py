"""Tests for the findings state machine.

Covers: record_finding, get_findings, record_timeline_event, approve_finding.
Note: approve_finding is intentionally NOT registered as an MCP tool.
The human-in-the-loop gate is enforced via cli_approve() which requires a TTY.
These tests call approve_finding() directly to verify the approval logic.
"""
import json
import pytest


@pytest.fixture(autouse=True)
def isolated_case_dir(tmp_path, monkeypatch):
    case_dir = tmp_path / "test_case"
    case_dir.mkdir()
    monkeypatch.setenv("CASEFILE_CASE_DIR", str(case_dir))
    monkeypatch.setenv("CASEFILE_EXAMINER", "testuser")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    import mcp_server.tools._shared as shared
    monkeypatch.setattr(shared, "AUDIT_FILE", audit_dir / "mcp.jsonl")
    return case_dir


def test_record_finding_returns_draft_id():
    from mcp_server.tools.findings import record_finding
    result = record_finding(
        title="Test", observation="A", interpretation="B",
        confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache",
    )
    assert result["status"] == "DRAFT"
    assert result["finding_id"] == "F-testuser-001"


def test_record_finding_sequential_ids():
    from mcp_server.tools.findings import record_finding
    r1 = record_finding(title="F1", observation="A", interpretation="B",
                        confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    r2 = record_finding(title="F2", observation="C", interpretation="D",
                        confidence="INFERRED", artifact_source="/b", supporting_tool="parse_mft")
    assert r1["finding_id"] == "F-testuser-001"
    assert r2["finding_id"] == "F-testuser-002"


def test_record_finding_writes_json(isolated_case_dir):
    from mcp_server.tools.findings import record_finding
    record_finding(title="P", observation="X", interpretation="Y",
                   confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_registry")
    data = json.loads((isolated_case_dir / "findings.json").read_text())
    assert len(data) == 1
    assert data[0]["status"] == "DRAFT"


def test_record_finding_logs_to_audit(tmp_path, monkeypatch):
    import mcp_server.tools._shared as shared
    audit_file = tmp_path / "mcp.jsonl"
    monkeypatch.setattr(shared, "AUDIT_FILE", audit_file)
    from mcp_server.tools.findings import record_finding
    result = record_finding(title="A", observation="X", interpretation="Y",
                            confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    record = json.loads(audit_file.read_text().strip())
    assert record["tool"] == "record_finding"
    assert record["finding_id"] == result["finding_id"]


def test_get_findings_returns_all():
    from mcp_server.tools.findings import record_finding, get_findings
    record_finding(title="F1", observation="A", interpretation="B",
                   confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_mft")
    record_finding(title="F2", observation="C", interpretation="D",
                   confidence="INFERRED", artifact_source="/b", supporting_tool="parse_registry")
    result = get_findings()
    assert result["total"] == 2
    assert result["total_draft"] == 2


def test_get_findings_filters_by_status():
    from mcp_server.tools.findings import record_finding, get_findings
    record_finding(title="F1", observation="A", interpretation="B",
                   confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_mft")
    assert get_findings(status="DRAFT")["returned"] == 1
    assert get_findings(status="APPROVED")["returned"] == 0


def test_get_findings_empty():
    from mcp_server.tools.findings import get_findings
    assert get_findings()["total"] == 0


def test_record_timeline_event_draft_id():
    from mcp_server.tools.findings import record_timeline_event
    result = record_timeline_event(
        timestamp="2018-09-06T18:28:30Z", description="mnemosyne installed",
        artifact_source="/a", event_type="persistence", supporting_tool="parse_event_logs",
    )
    assert result["status"] == "DRAFT"
    assert result["event_id"] == "T-testuser-001"


def test_record_timeline_event_sequential():
    from mcp_server.tools.findings import record_timeline_event
    r1 = record_timeline_event(timestamp="2018-08-27T23:57Z", description="E1",
                                artifact_source="/a", event_type="execution", supporting_tool="parse_event_logs")
    r2 = record_timeline_event(timestamp="2018-08-28T00:11Z", description="E2",
                                artifact_source="/b", event_type="persistence", supporting_tool="parse_event_logs")
    assert r1["event_id"] == "T-testuser-001"
    assert r2["event_id"] == "T-testuser-002"


def test_record_timeline_event_writes_json(isolated_case_dir):
    from mcp_server.tools.findings import record_timeline_event
    record_timeline_event(timestamp="2018-09-06T18:28Z", description="mnemosyne",
                          artifact_source="/a", event_type="persistence", supporting_tool="parse_event_logs")
    data = json.loads((isolated_case_dir / "timeline.json").read_text())
    assert len(data) == 1
    assert data[0]["event_type"] == "persistence"


def test_blocked_commands_contains_destructive():
    from mcp_server.tools.findings import BLOCKED_COMMANDS
    for cmd in ("rm", "dd", "mkfs", "approve"):
        assert cmd in BLOCKED_COMMANDS


def test_bad_confidence_defaults_to_inferred():
    from mcp_server.tools.findings import record_finding
    result = record_finding(title="X", observation="A", interpretation="B",
                            confidence="MAYBE", artifact_source="/a", supporting_tool="parse_mft")
    assert result["record"]["confidence"] == "INFERRED"


def test_mitre_technique_stored():
    from mcp_server.tools.findings import record_finding
    result = record_finding(title="X", observation="A", interpretation="B",
                            confidence="CONFIRMED", artifact_source="/a",
                            supporting_tool="parse_amcache", mitre_technique="T1036.004")
    assert result["record"]["mitre_technique"] == "T1036.004"


# -- approve_finding ----------------------------------------------------------

def test_approve_finding_flips_status(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    result = approve_finding(r["finding_id"])
    assert result["status"] == "APPROVED"

def test_approve_finding_sets_approved_by(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    result = approve_finding(r["finding_id"])
    assert result["approved_by"] == "testuser"

def test_approve_finding_sets_approved_at(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    result = approve_finding(r["finding_id"])
    assert result["approved_at"] is not None

def test_approve_finding_content_hash_present(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    result = approve_finding(r["finding_id"])
    assert "content_hash" in result
    assert len(result["content_hash"]) == 64

def test_approve_finding_persists_to_json(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    import json
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    approve_finding(r["finding_id"])
    data = json.loads((isolated_case_dir / "findings.json").read_text())
    assert data[0]["status"] == "APPROVED"
    assert data[0]["approved_by"] == "testuser"
    assert "content_hash" in data[0]

def test_approve_finding_writes_approvals_jsonl(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    import json
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    approve_finding(r["finding_id"])
    approvals_file = isolated_case_dir / "approvals.jsonl"
    assert approvals_file.exists()
    rec = json.loads(approvals_file.read_text().strip())
    assert rec["finding_id"] == r["finding_id"]
    assert rec["approved_by"] == "testuser"
    assert "content_hash" in rec

def test_approve_finding_writes_audit_log(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    import json
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    approve_finding(r["finding_id"])
    import mcp_server.tools._shared as shared
    records = [json.loads(l) for l in shared.AUDIT_FILE.read_text().splitlines() if l.strip()]
    approve_records = [rec for rec in records if rec["tool"] == "approve_finding"]
    assert len(approve_records) == 1
    assert approve_records[0]["finding_id"] == r["finding_id"]

def test_approve_finding_not_found(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    import json
    record_finding(title="T", observation="O", interpretation="I",
                   confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    result = approve_finding("F-testuser-999")
    assert "error" in result
    import mcp_server.tools._shared as shared
    records = [json.loads(l) for l in shared.AUDIT_FILE.read_text().splitlines() if l.strip()]
    assert any(r["tool"] == "approve_finding" and r["returncode"] == 1 for r in records)

def test_approve_finding_already_approved(isolated_case_dir):
    from mcp_server.tools.findings import record_finding, approve_finding
    r = record_finding(title="T", observation="O", interpretation="I",
                       confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache")
    approve_finding(r["finding_id"])
    result = approve_finding(r["finding_id"])
    assert "error" in result
    assert "already" in result["error"].lower()

def test_approve_finding_no_findings_file(isolated_case_dir):
    from mcp_server.tools.findings import approve_finding
    import json
    result = approve_finding("F-testuser-001")
    assert "error" in result
    import mcp_server.tools._shared as shared
    records = [json.loads(l) for l in shared.AUDIT_FILE.read_text().splitlines() if l.strip()]
    assert any(r["tool"] == "approve_finding" and r["returncode"] == 1 for r in records)


def test_cli_approve_rejects_no_args():
    from mcp_server.tools.findings import cli_approve
    import pytest
    with pytest.raises(SystemExit) as e:
        cli_approve([])
    assert e.value.code == 1


def test_cli_approve_rejects_extra_args():
    from mcp_server.tools.findings import cli_approve
    import pytest
    with pytest.raises(SystemExit) as e:
        cli_approve(["F-testuser-001", "extra"])
    assert e.value.code == 1
