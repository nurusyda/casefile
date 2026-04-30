import json
import pathlib
import pytest

SETTINGS_PATH = pathlib.Path(".claude/settings.json")

@pytest.fixture(scope="module")
def settings():
    assert SETTINGS_PATH.exists(), ".claude/settings.json missing"
    return json.loads(SETTINGS_PATH.read_text())

def test_settings_file_exists():
    assert SETTINGS_PATH.exists()

def test_settings_has_permissions_block(settings):
    assert "permissions" in settings

def test_deny_blocks_mnt_evidence_write(settings):
    assert "Write(/mnt/evidence/*)" in settings["permissions"]["deny"]

def test_deny_blocks_mnt_evidence_edit(settings):
    assert "Edit(/mnt/evidence/*)" in settings["permissions"]["deny"]

def test_deny_blocks_case_evidence_write(settings):
    assert "Write(cases/*/evidence/*)" in settings["permissions"]["deny"]

def test_deny_blocks_case_evidence_edit(settings):
    assert "Edit(cases/*/evidence/*)" in settings["permissions"]["deny"]

def test_deny_blocks_chmod_mnt_evidence(settings):
    assert "Bash(chmod * /mnt/evidence/*)" in settings["permissions"]["deny"]

def test_deny_blocks_audit_log_write(settings):
    assert "Write(**/audit/mcp.jsonl)" in settings["permissions"]["deny"]

def test_deny_blocks_approvals_write(settings):
    assert "Write(**/approvals.jsonl)" in settings["permissions"]["deny"]

def test_allow_list_contains_all_mcp_tools(settings):
    allow = settings["permissions"]["allow"]
    expected = [
        "mcp__casefile__parse_amcache",
        "mcp__casefile__parse_prefetch",
        "mcp__casefile__parse_event_logs",
        "mcp__casefile__parse_registry",
        "mcp__casefile__parse_mft",
        "mcp__casefile__record_finding",
        "mcp__casefile__get_findings",
        "mcp__casefile__record_timeline_event",
    ]
    for tool in expected:
        assert tool in allow, f"Missing from allow list: {tool}"
