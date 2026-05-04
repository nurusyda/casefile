import pytest
import os
from mcp_server.tools.correlation import (
    correlate_evidence, _decide_verdict, SourceResult, CorrelationToolError
)

@pytest.fixture
def mock_env(monkeypatch, tmp_path):
    case = tmp_path / "case_a"
    case.mkdir()
    (case / "audit").mkdir()
    monkeypatch.setenv("CASEFILE_CASE_DIR", str(case))
    monkeypatch.setenv("CASEFILE_EXAMINER", "analyst_01")
    # Mocking audit file path to avoid permission issues in CI
    monkeypatch.setattr("mcp_server.tools._shared.AUDIT_FILE", case / "audit" / "mcp.jsonl")
    return case

def test_verdict_logic_confirmed_running():
    res = _decide_verdict(
        SourceResult("amcache", True),
        SourceResult("prefetch", True),
        SourceResult("memory", True),
        SourceResult("mft", True)
    )
    assert res[0] == "CONFIRMED_RUNNING"

def test_verdict_logic_memory_only():
    res = _decide_verdict(
        SourceResult("amcache", False),
        SourceResult("prefetch", False),
        SourceResult("memory", True),
        SourceResult("mft", False)
    )
    assert res[0] == "MEMORY_ONLY"

def test_verdict_logic_historical():
    res = _decide_verdict(
        SourceResult("amcache", True),
        SourceResult("prefetch", False),
        SourceResult("memory", False),
        SourceResult("mft", True)
    )
    assert res[0] == "CONFIRMED_HISTORICAL"

def test_verdict_logic_not_found():
    res = _decide_verdict(
        SourceResult("amcache", False),
        SourceResult("prefetch", False),
        SourceResult("memory", False),
        SourceResult("mft", False)
    )
    assert res[0] == "NOT_FOUND"

def test_input_validation(mock_env):
    with pytest.raises(CorrelationToolError):
        correlate_evidence("")

def test_return_schema(mock_env):
    result = correlate_evidence("evil.exe")
    keys = ["process_name", "verdict", "verdict_reasoning", "invocation_id", "amcache"]
    for key in keys:
        assert key in result
    assert result["process_name"] == "evil.exe"

def test_audit_logging_writes_file(mock_env):
    correlate_evidence("test.exe")
    audit_path = mock_env / "audit" / "mcp.jsonl"
    assert audit_path.exists()
    assert "correlate_evidence" in audit_path.read_text()
