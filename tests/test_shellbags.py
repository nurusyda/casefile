"""Tests for mcp_server.tools.shellbags -- parse_shellbags()."""
from __future__ import annotations

import csv
import io
import json
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_server.tools.shellbags import (
    _flag_suspicious,
    _parse_sbecmd_csv,
    _safe_int,
    parse_shellbags,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CSV = """\
AbsolutePath,FirstInteracted,LastInteracted,MRUPosition,SourceFile,ShellType,SlotModified,Extension,Value
C:\\Users\\tdungan\\Desktop,2018-03-01T08:00:00,2018-09-06T18:00:00,0,NTUSER.DAT,Directory,2018-09-06T18:00:00,,
C:\\Windows\\Temp\\Perfmon,2018-05-01T10:00:00,2018-08-30T14:00:00,1,NTUSER.DAT,Directory,2018-08-30T14:00:00,,
\\\\172.16.6.12\\C$,2018-05-10T09:00:00,2018-09-01T11:00:00,2,UsrClass.dat,Network,2018-09-01T11:00:00,,
C:\\Users\\tdungan\\AppData\\Roaming\\Microsoft,2018-01-15T08:00:00,2018-09-06T17:00:00,3,NTUSER.DAT,Directory,2018-09-06T17:00:00,,
"""

SAMPLE_ENTRY = {
    "absolute_path": "C:\\Windows\\Temp\\Perfmon",
    "first_interacted": "2018-05-01T10:00:00",
    "last_interacted": "2018-08-30T14:00:00",
    "mru_position": 1,
    "source_file": "NTUSER.DAT",
    "shell_type": "Directory",
    "slot_modified": "2018-08-30T14:00:00",
    "extension": None,
    "value": None,
}


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CASEFILE_CASE_ROOT", str(tmp_path))
    monkeypatch.setenv("CASEFILE_EXAMINER", "testexaminer")
    return tmp_path


@pytest.fixture
def hive_dir(case_dir):
    d = case_dir / "analysis" / "user_hives"
    d.mkdir(parents=True)
    # Create fake NTUSER.DAT
    (d / "NTUSER.DAT").write_bytes(b"REGF" + b"\x00" * 100)
    return d


@pytest.fixture
def audit_file(case_dir):
    audit = case_dir / "audit"
    audit.mkdir()
    f = audit / "mcp.jsonl"
    f.write_text("")
    return f


# ---------------------------------------------------------------------------
# Unit tests: CSV parsing
# ---------------------------------------------------------------------------

class TestParseSBECmdCSV:
    def test_parses_all_rows(self):
        entries = _parse_sbecmd_csv(SAMPLE_CSV)
        assert len(entries) == 4

    def test_absolute_path_populated(self):
        entries = _parse_sbecmd_csv(SAMPLE_CSV)
        paths = [e["absolute_path"] for e in entries]
        assert "C:\\Users\\tdungan\\Desktop" in paths
        assert "\\\\172.16.6.12\\C$" in paths

    def test_timestamps_populated(self):
        entries = _parse_sbecmd_csv(SAMPLE_CSV)
        desktop = next(e for e in entries if "Desktop" in e["absolute_path"])
        assert desktop["first_interacted"] == "2018-03-01T08:00:00"
        assert desktop["last_interacted"] == "2018-09-06T18:00:00"

    def test_mru_position_int(self):
        entries = _parse_sbecmd_csv(SAMPLE_CSV)
        assert entries[0]["mru_position"] == 0

    def test_source_file_populated(self):
        entries = _parse_sbecmd_csv(SAMPLE_CSV)
        network = next(e for e in entries if "172.16.6.12" in e["absolute_path"])
        assert network["source_file"] == "UsrClass.dat"

    def test_empty_csv_returns_empty(self):
        entries = _parse_sbecmd_csv("AbsolutePath,FirstInteracted\n")
        assert entries == []

    def test_skips_rows_without_path(self):
        csv_no_path = "AbsolutePath,FirstInteracted\n,2018-01-01\n"
        entries = _parse_sbecmd_csv(csv_no_path)
        assert entries == []


# ---------------------------------------------------------------------------
# Unit tests: safe_int
# ---------------------------------------------------------------------------

class TestSafeInt:
    def test_valid_int(self):
        assert _safe_int("5") == 5

    def test_empty_string(self):
        assert _safe_int("") is None

    def test_non_numeric(self):
        assert _safe_int("abc") is None

    def test_none(self):
        assert _safe_int(None) is None


# ---------------------------------------------------------------------------
# Unit tests: flag_suspicious
# ---------------------------------------------------------------------------

class TestFlagSuspicious:
    def test_network_share_flagged(self):
        entries = [{"absolute_path": "\\\\172.16.6.12\\C$", "shell_type": "Network",
                    "first_interacted": None, "last_interacted": None,
                    "mru_position": 0, "source_file": "UsrClass.dat",
                    "slot_modified": None, "extension": None, "value": None}]
        suspicious = _flag_suspicious(entries)
        assert len(suspicious) == 1
        assert any("Network share" in r for r in suspicious[0]["suspicion_reasons"])

    def test_temp_directory_flagged(self):
        entries = [{"absolute_path": "C:\\Windows\\Temp\\Perfmon", "shell_type": "Directory",
                    "first_interacted": None, "last_interacted": None,
                    "mru_position": 1, "source_file": "NTUSER.DAT",
                    "slot_modified": None, "extension": None, "value": None}]
        suspicious = _flag_suspicious(entries)
        assert len(suspicious) == 1
        assert any("temp" in r.lower() for r in suspicious[0]["suspicion_reasons"])

    def test_appdata_flagged(self):
        entries = [{"absolute_path": "C:\\Users\\tdungan\\AppData\\Roaming\\evil",
                    "shell_type": "Directory", "first_interacted": None,
                    "last_interacted": None, "mru_position": 0,
                    "source_file": "NTUSER.DAT", "slot_modified": None,
                    "extension": None, "value": None}]
        suspicious = _flag_suspicious(entries)
        assert len(suspicious) == 1

    def test_normal_path_not_flagged(self):
        entries = [{"absolute_path": "C:\\Users\\tdungan\\Documents",
                    "shell_type": "Directory", "first_interacted": None,
                    "last_interacted": None, "mru_position": 0,
                    "source_file": "NTUSER.DAT", "slot_modified": None,
                    "extension": None, "value": None}]
        suspicious = _flag_suspicious(entries)
        assert len(suspicious) == 0

    def test_recycle_bin_flagged(self):
        entries = [{"absolute_path": "C:\\$Recycle.Bin\\S-1-5-21",
                    "shell_type": "Directory", "first_interacted": None,
                    "last_interacted": None, "mru_position": 0,
                    "source_file": "NTUSER.DAT", "slot_modified": None,
                    "extension": None, "value": None}]
        suspicious = _flag_suspicious(entries)
        assert len(suspicious) == 1
        assert any("Recycle" in r for r in suspicious[0]["suspicion_reasons"])

    def test_suspicious_confidence_label(self):
        entries = [{"absolute_path": "\\\\evil\\share", "shell_type": "Network",
                    "first_interacted": None, "last_interacted": None,
                    "mru_position": 0, "source_file": "UsrClass.dat",
                    "slot_modified": None, "extension": None, "value": None}]
        suspicious = _flag_suspicious(entries)
        assert suspicious[0]["confidence"] == "INFERRED"


# ---------------------------------------------------------------------------
# Integration tests: parse_shellbags
# ---------------------------------------------------------------------------

def _make_fake_run_tool(csv_content: str, out_dir_ref: list):
    """Returns a mock run_tool that writes CSV to the output directory."""
    def fake_run_tool(cmd, timeout=120):
        # Extract output dir from command (handles shlex.quote paths)
        parts = cmd.split("--csv ")
        if len(parts) > 1:
            raw = parts[1].strip().split()[0]
            out = raw.replace("'", "")
            out_path = Path(out)
            out_path.mkdir(parents=True, exist_ok=True)
            (out_path / "SBECmd_Output.csv").write_text(csv_content, encoding="utf-8")
            out_dir_ref.append(out_path)
        result = MagicMock()
        result.stdout = "Processed 4 entries\n"
        result.stderr = ""
        result.returncode = 0
        return result
    return fake_run_tool


class TestParseShellbags:
    def test_missing_hive_dir_returns_error(self, case_dir, audit_file):
        with patch("mcp_server.tools.shellbags.audit_log"):
            result = parse_shellbags(str(case_dir / "nonexistent"))
        assert result["error"] is not None
        assert "does not exist" in result["error"]

    def test_missing_hive_files_returns_error(self, case_dir, audit_file):
        empty_dir = case_dir / "analysis" / "empty_hives"
        empty_dir.mkdir(parents=True)
        with patch("mcp_server.tools.shellbags.audit_log"):
            result = parse_shellbags(str(empty_dir))
        assert result["error"] is not None
        assert "NTUSER.DAT" in result["error"]

    def test_successful_parse(self, hive_dir, case_dir, audit_file):
        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(SAMPLE_CSV, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert result["error"] is None
        assert result["total_entries"] == 4
        assert result["entries_returned"] == 4
        assert result["tool"] == "SBECmd"

    def test_suspicious_entries_populated(self, hive_dir, case_dir, audit_file):
        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(SAMPLE_CSV, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        # Network share + Temp + AppData = at least 3 suspicious
        assert len(result["suspicious"]) >= 2

    def test_invocation_id_present(self, hive_dir, case_dir, audit_file):
        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(SAMPLE_CSV, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert "invocation_id" in result
        assert len(result["invocation_id"]) > 0

    def test_path_confinement_enforced(self, tmp_path, monkeypatch, audit_file):
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_dir))
        monkeypatch.setenv("CASEFILE_EXAMINER", "testexaminer")

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "NTUSER.DAT").write_bytes(b"REGF" + b"\x00" * 100)

        with patch("mcp_server.tools.shellbags.audit_log"):
            result = parse_shellbags(str(outside))

        assert result["error"] is not None
        assert "outside" in result["error"].lower() or "CASEFILE_CASE_ROOT" in result["error"]

    def test_run_tool_exception_returns_error(self, hive_dir, case_dir, audit_file):
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=RuntimeError("SBECmd failed")):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert result["error"] is not None
        assert "SBECmd failed" in result["error"]

    def test_no_csv_output_returns_graceful_result(self, hive_dir, case_dir, audit_file):
        def fake_no_csv(cmd, timeout=120):
            # Don't write any CSV
            result = MagicMock()
            result.stdout = ""
            result.stderr = ""
            result.returncode = 0
            return result

        with patch("mcp_server.tools.shellbags.run_tool", side_effect=fake_no_csv):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert result["error"] is None
        assert result["total_entries"] == 0
        assert "no output" in result["analyst_note"].lower() or \
               "no CSV" in result.get("analyst_note", "")

    def test_cap_at_500(self, hive_dir, case_dir, audit_file):
        # Generate 600 rows
        header = "AbsolutePath,FirstInteracted,LastInteracted,MRUPosition,SourceFile,ShellType,SlotModified,Extension,Value\n"
        rows = "\n".join(
            f"C:\\Users\\user\\Documents\\file{i},2018-01-01,2018-09-01,{i},NTUSER.DAT,Directory,2018-09-01,,"
            for i in range(600)
        )
        big_csv = header + rows

        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(big_csv, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert result["total_entries"] == 600
        assert result["entries_returned"] <= 500
        assert result["entries_capped"] is True

    def test_include_all_bypasses_cap(self, hive_dir, case_dir, audit_file):
        header = "AbsolutePath,FirstInteracted,LastInteracted,MRUPosition,SourceFile,ShellType,SlotModified,Extension,Value\n"
        rows = "\n".join(
            f"C:\\Users\\user\\Documents\\file{i},2018-01-01,2018-09-01,{i},NTUSER.DAT,Directory,2018-09-01,,"
            for i in range(600)
        )
        big_csv = header + rows

        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(big_csv, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir), include_all=True)

        assert result["total_entries"] == 600
        assert result["entries_returned"] == 600
        assert result["entries_capped"] is False

    def test_audit_log_called_on_success(self, hive_dir, case_dir, audit_file):
        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(SAMPLE_CSV, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log") as mock_audit:
                parse_shellbags(str(hive_dir))

        assert mock_audit.called
        call_kwargs = mock_audit.call_args[1]
        assert call_kwargs["tool"] == "SBECmd"
        assert call_kwargs["returncode"] == 0

    def test_output_dir_within_case_root(self, hive_dir, case_dir, audit_file):
        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(SAMPLE_CSV, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert result["output_dir"] is not None
        out = Path(result["output_dir"])
        case_root = Path(os.environ.get("CASEFILE_CASE_ROOT", ""))
        assert str(out).startswith(str(case_root))

    def test_analyst_note_present(self, hive_dir, case_dir, audit_file):
        out_dir_ref = []
        with patch("mcp_server.tools.shellbags.run_tool",
                   side_effect=_make_fake_run_tool(SAMPLE_CSV, out_dir_ref)):
            with patch("mcp_server.tools.shellbags.audit_log"):
                result = parse_shellbags(str(hive_dir))

        assert "analyst_note" in result
        assert len(result["analyst_note"]) > 0
