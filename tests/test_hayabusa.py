"""Tests for mcp_server/tools/hayabusa.py"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_server.tools.hayabusa import (
    HayabusaToolError,
    _canonical_level,
    _level_rank,
    _parse_csv,
    _safe_int,
    parse_hayabusa,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ROWS = [
    {
        "Timestamp": "2018-08-15 22:28:54.592 +07:00",
        "RuleTitle": "PowerShell ShellCode",
        "Level": "high",
        "Computer": "base-rd-01.shieldbase.lan",
        "Channel": "PwSh",
        "EventID": "4104",
        "RecordID": "4439",
        "Details": "ScriptBlock: ...",
        "ExtraFieldInfo": "",
        "RuleID": "abc-123",
    },
    {
        "Timestamp": "2018-08-15 22:30:00.000 +07:00",
        "RuleTitle": "Mimikatz Detection",
        "Level": "crit",
        "Computer": "base-rd-01.shieldbase.lan",
        "Channel": "Security",
        "EventID": "4688",
        "RecordID": "5000",
        "Details": "Process: mimikatz.exe",
        "ExtraFieldInfo": "",
        "RuleID": "def-456",
    },
    {
        "Timestamp": "2018-08-15 22:35:00.000 +07:00",
        "RuleTitle": "Potentially Malicious PwSh",
        "Level": "med",
        "Computer": "base-rd-01.shieldbase.lan",
        "Channel": "PwSh",
        "EventID": "4104",
        "RecordID": "5001",
        "Details": "ScriptBlock: Invoke-Mimikatz",
        "ExtraFieldInfo": "",
        "RuleID": "ghi-789",
    },
    {
        "Timestamp": "2018-08-15 22:40:00.000 +07:00",
        "RuleTitle": "Logon Failure",
        "Level": "low",
        "Computer": "base-rd-01.shieldbase.lan",
        "Channel": "Security",
        "EventID": "4625",
        "RecordID": "5002",
        "Details": "User: testuser",
        "ExtraFieldInfo": "",
        "RuleID": "jkl-012",
    },
    {
        "Timestamp": "2018-08-15 22:45:00.000 +07:00",
        "RuleTitle": "PwSh Scriptblock",
        "Level": "info",
        "Computer": "base-rd-01.shieldbase.lan",
        "Channel": "PwSh",
        "EventID": "4104",
        "RecordID": "5003",
        "Details": "ScriptBlock: $PSVersionTable",
        "ExtraFieldInfo": "",
        "RuleID": "mno-345",
    },
]

FIELDNAMES = [
    "Timestamp", "RuleTitle", "Level", "Computer", "Channel",
    "EventID", "RecordID", "Details", "ExtraFieldInfo", "RuleID",
]


@pytest.fixture
def sample_csv(tmp_path) -> Path:
    """Write SAMPLE_ROWS to a temp CSV and return its path."""
    csv_path = tmp_path / "hayabusa_test.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(SAMPLE_ROWS)
    return csv_path


@pytest.fixture
def evtx_dir(tmp_path) -> Path:
    """Create a fake evtx directory."""
    d = tmp_path / "evtx"
    d.mkdir()
    (d / "fake.evtx").write_bytes(b"\x00" * 100)
    return d


@pytest.fixture
def analysis_dir(tmp_path) -> Path:
    d = tmp_path / "analysis"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Unit: level helpers
# ---------------------------------------------------------------------------

class TestLevelHelpers:
    def test_canonical_level_abbreviations(self):
        assert _canonical_level("crit") == "critical"
        assert _canonical_level("med") == "medium"
        assert _canonical_level("info") == "informational"
        assert _canonical_level("high") == "high"
        assert _canonical_level("low") == "low"

    def test_canonical_level_full_names(self):
        assert _canonical_level("critical") == "critical"
        assert _canonical_level("medium") == "medium"
        assert _canonical_level("informational") == "informational"

    def test_canonical_level_case_insensitive(self):
        assert _canonical_level("HIGH") == "high"
        assert _canonical_level("Med") == "medium"

    def test_level_rank_ordering(self):
        assert _level_rank("crit") > _level_rank("high")
        assert _level_rank("high") > _level_rank("med")
        assert _level_rank("med") > _level_rank("low")
        assert _level_rank("low") > _level_rank("info")
        assert _level_rank("info") > 0

    def test_level_rank_unknown_returns_zero(self):
        assert _level_rank("unknown") == 0


class TestSafeInt:
    def test_valid_integer(self):
        assert _safe_int("4104") == 4104

    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_empty_string_returns_none(self):
        assert _safe_int("") is None

    def test_non_numeric_returns_none(self):
        assert _safe_int("abc") is None


# ---------------------------------------------------------------------------
# Unit: CSV parsing
# ---------------------------------------------------------------------------

class TestParseCsv:
    def test_total_events(self, sample_csv):
        result = _parse_csv(sample_csv, "low", None)
        assert result["total_events"] == 5

    def test_by_level_counts(self, sample_csv):
        result = _parse_csv(sample_csv, "low", None)
        assert result["by_level"]["high"] == 1
        assert result["by_level"]["critical"] == 1
        assert result["by_level"]["medium"] == 1
        assert result["by_level"]["low"] == 1
        assert result["by_level"]["informational"] == 1

    def test_high_and_critical_only(self, sample_csv):
        result = _parse_csv(sample_csv, "low", None)
        levels = {r["level"] for r in result["high_and_critical"]}
        assert levels == {"high", "critical"}
        assert len(result["high_and_critical"]) == 2

    def test_high_and_critical_fields(self, sample_csv):
        result = _parse_csv(sample_csv, "low", None)
        row = next(r for r in result["high_and_critical"] if r["level"] == "high")
        assert row["rule_title"] == "PowerShell ShellCode"
        assert row["event_id"] == 4104
        assert row["computer"] == "base-rd-01.shieldbase.lan"
        assert row["rule_id"] == "abc-123"

    def test_min_level_filters_top_rules(self, sample_csv):
        result = _parse_csv(sample_csv, "high", None)
        titles = [r["rule_title"] for r in result["top_rules"]]
        # medium and low should not appear in top_rules
        assert "Logon Failure" not in titles
        assert "Potentially Malicious PwSh" not in titles

    def test_top_rules_sorted_by_count(self, sample_csv):
        result = _parse_csv(sample_csv, "low", None)
        counts = [r["count"] for r in result["top_rules"]]
        assert counts == sorted(counts, reverse=True)

    def test_rule_title_filter(self, sample_csv):
        result = _parse_csv(sample_csv, "low", "Mimikatz")
        titles = {r["rule_title"] for r in result["top_rules"]}
        assert all("Mimikatz" in t or "mimikatz" in t.lower() for t in titles)

    def test_rule_title_filter_case_insensitive(self, sample_csv):
        result = _parse_csv(sample_csv, "low", "powershell shellcode")
        assert len(result["top_rules"]) >= 1


# ---------------------------------------------------------------------------
# Integration: parse_hayabusa()
# ---------------------------------------------------------------------------

class TestParseHayabusaSuccess:
    def test_returns_expected_schema(self, evtx_dir, sample_csv, analysis_dir):
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir))

        assert "csv_path" in result
        assert "total_events" in result
        assert "by_level" in result
        assert "high_and_critical" in result
        assert "top_rules" in result
        assert "high_crit_count" in result
        assert "invocation_id" in result
        assert "analyst_note" in result

    def test_total_events_correct(self, evtx_dir, sample_csv, analysis_dir):
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir))

        assert result["total_events"] == 5

    def test_high_crit_count(self, evtx_dir, sample_csv, analysis_dir):
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir))

        assert result["high_crit_count"] == 2

    def test_invocation_id_is_uuid(self, evtx_dir, sample_csv, analysis_dir):
        import re
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir))

        assert uuid_pattern.match(result["invocation_id"])

    def test_analyst_note_contains_count(self, evtx_dir, sample_csv, analysis_dir):
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir))

        assert "2" in result["analyst_note"]
        assert "Tier 2" in result["analyst_note"]


class TestParseHayabusaAuditLog:
    def test_audit_log_written_on_success(self, evtx_dir, sample_csv, analysis_dir):
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log") as mock_audit:
            mock_run.return_value = (0, "", "")
            parse_hayabusa(str(evtx_dir))

        mock_audit.assert_called_once()
        kwargs = mock_audit.call_args.kwargs
        assert kwargs["tool"] == "parse_hayabusa"
        assert kwargs["returncode"] == 0

    def test_audit_log_contains_csv_files(self, evtx_dir, sample_csv, analysis_dir):
        """csv_files in extra is mandatory for Tier 2 grounding."""
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log") as mock_audit:
            mock_run.return_value = (0, "", "")
            parse_hayabusa(str(evtx_dir))

        extra = mock_audit.call_args.kwargs["extra"]
        assert "csv_files" in extra
        assert len(extra["csv_files"]) == 1
        assert extra["csv_files"][0] == str(sample_csv)

    def test_audit_log_contains_examiner(self, evtx_dir, sample_csv, analysis_dir, monkeypatch):
        monkeypatch.setenv("CASEFILE_EXAMINER", "test_examiner")
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log") as mock_audit:
            mock_run.return_value = (0, "", "")
            parse_hayabusa(str(evtx_dir))

        assert mock_audit.call_args.kwargs["examiner"] == "test_examiner"

    def test_audit_log_failure_does_not_mask_result(self, evtx_dir, sample_csv, analysis_dir):
        """Logging failure must never prevent the result from being returned."""
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log", side_effect=OSError("disk full")):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir))

        assert result["total_events"] == 5


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestParseHayabusaInputValidation:
    def test_missing_evtx_dir_raises(self, tmp_path):
        with pytest.raises(ValueError, match="does not exist"):
            parse_hayabusa(str(tmp_path / "nonexistent"))

    def test_symlink_evtx_dir_raises(self, tmp_path, evtx_dir):
        link = tmp_path / "link"
        link.symlink_to(evtx_dir)
        with pytest.raises(ValueError, match="symlink"):
            parse_hayabusa(str(link))

    def test_invalid_min_level_raises(self, evtx_dir):
        with pytest.raises(ValueError, match="Invalid min_level"):
            parse_hayabusa(str(evtx_dir), min_level="extreme")


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestParseHayabusaErrors:
    def test_binary_not_found_raises(self, evtx_dir, analysis_dir):
        with patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._run_hayabusa",
                   side_effect=HayabusaToolError("hayabusa binary not found")), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            with pytest.raises(HayabusaToolError, match="binary not found"):
                parse_hayabusa(str(evtx_dir))

    def test_nonzero_exit_no_csv_raises(self, evtx_dir, tmp_path, analysis_dir):
        missing_csv = tmp_path / "nonexistent.csv"
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=missing_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (1, "", "some error")
            with pytest.raises(HayabusaToolError):
                parse_hayabusa(str(evtx_dir))

    def test_timeout_raises(self, evtx_dir, analysis_dir):
        with patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._run_hayabusa",
                   side_effect=HayabusaToolError("hayabusa timed out after 600s")), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            with pytest.raises(HayabusaToolError, match="timed out"):
                parse_hayabusa(str(evtx_dir))

    def test_audit_log_written_on_error(self, evtx_dir, tmp_path, analysis_dir):
        missing_csv = tmp_path / "nonexistent.csv"
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=missing_csv), \
             patch("mcp_server.tools.hayabusa.audit_log") as mock_audit:
            mock_run.return_value = (1, "", "error output")
            with pytest.raises(HayabusaToolError):
                parse_hayabusa(str(evtx_dir))

        mock_audit.assert_called_once()


# ---------------------------------------------------------------------------
# Min level filtering
# ---------------------------------------------------------------------------

class TestMinLevel:
    def test_min_level_high_excludes_medium_from_top_rules(self, evtx_dir, sample_csv, analysis_dir):
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir), min_level="high")

        top_levels = {r["level"] for r in result["top_rules"]}
        assert "medium" not in top_levels
        assert "low" not in top_levels
        assert "informational" not in top_levels

    def test_high_and_critical_always_returned_regardless_of_min_level(
        self, evtx_dir, sample_csv, analysis_dir
    ):
        """high_and_critical rows ignore min_level — always return high+crit."""
        with patch("mcp_server.tools.hayabusa._run_hayabusa") as mock_run, \
             patch("mcp_server.tools.hayabusa._analysis_dir", return_value=analysis_dir), \
             patch("mcp_server.tools.hayabusa._default_output_path", return_value=sample_csv), \
             patch("mcp_server.tools.hayabusa.audit_log"):
            mock_run.return_value = (0, "", "")
            result = parse_hayabusa(str(evtx_dir), min_level="critical")

        assert result["high_crit_count"] == 2
        assert len(result["high_and_critical"]) == 2
