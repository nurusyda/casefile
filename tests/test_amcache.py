"""
Tests for parse_amcache()

Run on any machine (no SIFT required):
    pytest tests/test_amcache.py -v

These tests mock run_tool() so AmcacheParser.dll is never invoked.
pyscca is not required — AmcacheParser uses a separate code path.
They exercise the CSV parser, suspicious-flag logic, context-window cap,
error handling, and audit log output.
"""

import csv
import io
import json
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Make the repo root importable when running from tests/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.tools.amcache import (
    _flag_suspicious,
    _inject_source_column,
    _norm_ts,
    _parse_amcache_csv,
    _safe_int,
    parse_amcache,
)


# ── CSV fixtures ──────────────────────────────────────────────────────────────

CLEAN_CSV = """\
Name,FullPath,SHA1,FileKeyLastWriteTimestamp,LinkDate,Size,Publisher,ProductName,FileDescription,ProgramId,FileId,Language
notepad.exe,C:\\Windows\\System32\\notepad.exe,aabbcc1122334455667788990011223344556677,2024-01-10 09:00:00,,45056,Microsoft Corporation,Windows,Notepad,{ABC},,
calc.exe,C:\\Windows\\System32\\calc.exe,bbcc22334455667788990011223344556677aabb,2024-01-11 10:00:00,,102400,Microsoft Corporation,Windows,Calculator,{DEF},,
"""

SUSPICIOUS_CSV = """\
Name,FullPath,SHA1,FileKeyLastWriteTimestamp,LinkDate,Size,Publisher,ProductName,FileDescription,ProgramId,FileId,Language
STUN.exe,C:\\Windows\\System32\\STUN.exe,deadbeefdeadbeefdeadbeefdeadbeefdeadbeef,2024-03-01 12:00:00,,98304,,,,{GHI},,
evil.exe,C:\\Users\\Public\\evil.exe,cafebabecafebabecafebabecafebabecafebabe,2024-03-01 13:00:00,,65536,,,,{JKL},,
msedge.exe,C:\\Windows\\Temp\\msedge.exe,1234567890abcdef1234567890abcdef12345678,2024-03-01 14:00:00,,204800,,,masquerading edge,{MNO},,
"""


# ── _parse_amcache_csv ────────────────────────────────────────────────────────

class TestParseAmcacheCSV:
    def test_basic_parsing(self):
        entries = _parse_amcache_csv(CLEAN_CSV)
        assert len(entries) == 2

    def test_field_names(self):
        entries = _parse_amcache_csv(CLEAN_CSV)
        e = entries[0]
        assert e["name"] == "notepad.exe"
        assert "system32" in e["full_path"].lower()
        assert e["sha1"] == "aabbcc1122334455667788990011223344556677"
        assert e["publisher"] == "Microsoft Corporation"

    def test_sha1_lowercased(self):
        csv_text = CLEAN_CSV.replace(
            "aabbcc1122334455667788990011223344556677",
            "AABBCC1122334455667788990011223344556677",
        )
        entries = _parse_amcache_csv(csv_text)
        assert entries[0]["sha1"] == "aabbcc1122334455667788990011223344556677"

    def test_empty_csv(self):
        entries = _parse_amcache_csv("")
        assert entries == []

    def test_header_only_csv(self):
        entries = _parse_amcache_csv(
            "Name,FullPath,SHA1,FileKeyLastWriteTimestamp\n"
        )
        assert entries == []

    def test_source_column_propagated(self):
        tagged = _inject_source_column(CLEAN_CSV, "InventoryApplicationFile")
        entries = _parse_amcache_csv(tagged)
        assert entries[0]["source"] == "InventoryApplicationFile"


# ── _flag_suspicious ──────────────────────────────────────────────────────────

class TestFlagSuspicious:
    def setup_method(self):
        tagged = _inject_source_column(SUSPICIOUS_CSV, "InventoryApplicationFile")
        self.entries = _parse_amcache_csv(tagged)

    def test_system32_no_publisher_flagged(self):
        stun = next(e for e in self.entries if e["name"] == "STUN.exe")
        flagged = _flag_suspicious([stun])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        # No publisher + SHA1 available
        assert any("unsigned" in r.lower() or "no publisher" in r.lower() for r in reasons)

    def test_public_path_flagged(self):
        evil = next(e for e in self.entries if e["name"] == "evil.exe")
        flagged = _flag_suspicious([evil])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("suspicious path" in r.lower() for r in reasons)

    def test_temp_path_flagged(self):
        msedge = next(e for e in self.entries if e["name"] == "msedge.exe")
        flagged = _flag_suspicious([msedge])
        assert any("suspicious path" in r.lower() for r in flagged[0]["suspicion_reasons"])

    def test_clean_entries_not_flagged(self):
        tagged = _inject_source_column(CLEAN_CSV, "InventoryApplicationFile")
        clean_entries = _parse_amcache_csv(tagged)
        # notepad and calc are in System32 with Microsoft publisher — no flags expected
        flagged = _flag_suspicious(clean_entries)
        assert flagged == [], f"Clean entries incorrectly flagged: {flagged}"

    def test_suspicious_has_original_fields(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            assert "name" in f
            assert "full_path" in f
            assert "sha1" in f
            assert "suspicion_reasons" in f
            assert isinstance(f["suspicion_reasons"], list)


# ── _norm_ts ──────────────────────────────────────────────────────────────────

class TestNormTs:
    def test_space_separated(self):
        result = _norm_ts("2024-03-01 12:00:00")
        assert "T" in result
        assert result.endswith("Z")

    def test_already_iso(self):
        result = _norm_ts("2024-03-01T12:00:00Z")
        assert result == "2024-03-01T12:00:00Z"

    def test_empty(self):
        assert _norm_ts("") is None
        assert _norm_ts("0") is None
        assert _norm_ts("N/A") is None

    def test_none_input(self):
        assert _norm_ts(None) is None


# ── _safe_int ─────────────────────────────────────────────────────────────────

class TestSafeInt:
    def test_valid(self):
        assert _safe_int("45056") == 45056

    def test_empty(self):
        assert _safe_int("") is None

    def test_non_numeric(self):
        assert _safe_int("N/A") is None


# ── parse_amcache integration (mocked subprocess) ────────────────────────────

class TestParseAmcacheIntegration:
    """
    These tests create a real Amcache.hve file (just an empty file for path
    validation) and mock run_tool() to return fake AmcacheParser output.
    The CSV is written to a real tmpdir so the file-discovery logic runs.
    """

    def _make_fake_csv(self, tmpdir: Path, prefix: str, csv_content: str) -> None:
        tmpdir.mkdir(parents=True, exist_ok=True)
        csv_path = tmpdir / f"{prefix}_InventoryApplicationFile.csv"
        csv_path.write_text(csv_content, encoding="utf-8")

    @patch("mcp_server.tools.amcache.run_tool")
    def test_successful_parse(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")  # fake registry magic bytes
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout="", stderr=""
        )
        self._make_fake_csv(out_dir, "Amcache", CLEAN_CSV)

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] == 2
        assert result["entries_returned"] == 2
        assert result["tool"] == "AmcacheParser"
        assert result["invocation_id"]  # non-empty UUID

    @patch("mcp_server.tools.amcache.run_tool")
    def test_suspicious_entries_populated(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout="", stderr=""
        )
        self._make_fake_csv(out_dir, "Amcache", SUSPICIOUS_CSV)

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive), output_dir=str(out_dir))

        assert result["error"] is None
        assert len(result["suspicious"]) > 0
        # Every suspicious entry must have suspicion_reasons
        for s in result["suspicious"]:
            assert "suspicion_reasons" in s

    def test_missing_hive_returns_error(self, tmp_path):
        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(tmp_path / "nonexistent.hve"))
        assert result["error"] is not None
        assert "not found" in result["error"].lower()
        assert result["total_entries"] == 0
        assert result["entries"] == []

    @patch("mcp_server.tools.amcache.run_tool")
    def test_context_window_cap(self, mock_run, tmp_path):
        """When total entries > 500 and include_all=False, entries are capped."""
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        # Generate 600 rows
        header = "Name,FullPath,SHA1,FileKeyLastWriteTimestamp,Size,Publisher\n"
        rows = "\n".join(
            f"prog{i}.exe,C:\\Windows\\prog{i}.exe,"
            f"{'a' * 40},2024-01-01 00:00:00,1024,Microsoft Corporation"
            for i in range(600)
        )
        self._make_fake_csv(out_dir, "Amcache", header + rows)

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive), output_dir=str(out_dir), include_all=False)

        assert result["total_entries"] == 600
        assert result["entries_returned"] <= 500
        assert result["entries_capped"] is True

    @patch("mcp_server.tools.amcache.run_tool")
    def test_include_all_bypasses_cap(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = "Name,FullPath,SHA1,FileKeyLastWriteTimestamp,Size,Publisher\n"
        rows = "\n".join(
            f"prog{i}.exe,C:\\Windows\\prog{i}.exe,"
            f"{'b' * 40},2024-01-01 00:00:00,1024,Microsoft Corporation"
            for i in range(600)
        )
        self._make_fake_csv(out_dir, "Amcache", header + rows)

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive), output_dir=str(out_dir), include_all=True)

        assert result["entries_returned"] == 600
        assert result["entries_capped"] is False

    @patch("mcp_server.tools.amcache.run_tool")
    def test_tool_failure_returns_error(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")

        mock_run.side_effect = RuntimeError(
            "Tool exited 1.\nCMD: dotnet ...\nSTDERR: Hive corrupt"
        )

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive))

        assert result["error"] is not None
        assert "Tool exited" in result["error"] or "corrupt" in result["error"].lower()
        assert result["entries"] == []

    @patch("mcp_server.tools.amcache.run_tool")
    def test_audit_log_written(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._make_fake_csv(out_dir, "Amcache", CLEAN_CSV)

        # Redirect audit log to tmp_path
        with patch("mcp_server.tools._shared.AUDIT_FILE", tmp_path / "mcp.jsonl"):
            with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
                result = parse_amcache(str(hive), output_dir=str(out_dir))

        log_path = tmp_path / "mcp.jsonl"
        assert log_path.exists(), "Audit log was not created"

        records = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        assert len(records) >= 1
        record = records[-1]
        assert record["tool"] == "AmcacheParser"
        assert record["invocation_id"] == result["invocation_id"]
        assert record["returncode"] == 0
        assert record["parsed_record_count"] == 2
        assert "examiner" in record
        assert record["examiner"] == "casefile"

    @patch("mcp_server.tools.amcache.run_tool")
    def test_return_schema_complete(self, mock_run, tmp_path):
        """All expected keys must be present in the return dict."""
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._make_fake_csv(out_dir, "Amcache", CLEAN_CSV)

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive), output_dir=str(out_dir))

        required_keys = [
            "invocation_id", "tool", "amcache_path", "run_ts_utc",
            "total_entries", "entries_returned", "entries_capped",
            "entries", "suspicious", "output_dir", "duration_ms",
            "error", "analyst_note",
        ]
        for key in required_keys:
            assert key in result, f"Missing key in result: {key}"

    @patch("mcp_server.tools.amcache.run_tool")
    def test_entries_sorted_by_timestamp(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        csv_content = (
            "Name,FullPath,SHA1,FileKeyLastWriteTimestamp,Size,Publisher\n"
            "b.exe,C:\\b.exe," + "b" * 40 + ",2024-03-02 00:00:00,1024,ACME\n"
            "a.exe,C:\\a.exe," + "a" * 40 + ",2024-01-01 00:00:00,1024,ACME\n"
        )
        self._make_fake_csv(out_dir, "Amcache", csv_content)

        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            result = parse_amcache(str(hive), output_dir=str(out_dir))
        timestamps = [
            e["first_run_utc"] for e in result["entries"]
            if e.get("first_run_utc")
        ]
        assert timestamps == sorted(timestamps), "Entries not sorted by timestamp"
