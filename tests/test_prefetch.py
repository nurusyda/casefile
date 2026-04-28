"""
Tests for parse_prefetch()

Run on any machine (no SIFT required):
    pytest tests/test_prefetch.py -v

Mocks run_tool() so PECmd.dll is never invoked.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.tools.prefetch import (
    _flag_suspicious,
    _norm_ts,
    _parse_prefetch_csv,
    _safe_int,
    parse_prefetch,
)


# ── CSV fixtures ──────────────────────────────────────────────────────────────

CLEAN_CSV = """\
ExecutableName,SourceFilePath,SourceFileName,RunCount,LastRun,RunTime1,FilesLoaded,Directories,VolumeName,VolumeSerial,VolumeCreated,Hash,Size
notepad.exe,C:\\Windows\\System32\\notepad.exe,NOTEPAD.EXE-AB12CD34.pf,5,2024-03-01 09:00:00,2024-02-28 08:00:00,C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE|C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL,C:\\WINDOWS\\SYSTEM32,\\DEVICE\\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,AB12CD34,45056
explorer.exe,C:\\Windows\\explorer.exe,EXPLORER.EXE-DE34EF56.pf,120,2024-03-01 10:00:00,,C:\\WINDOWS\\EXPLORER.EXE|C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL,C:\\WINDOWS,\\DEVICE\\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,DE34EF56,102400
"""

SUSPICIOUS_CSV = """\
ExecutableName,SourceFilePath,SourceFileName,RunCount,LastRun,RunTime1,FilesLoaded,Directories,VolumeName,VolumeSerial,VolumeCreated,Hash,Size
STUN.exe,C:\\Users\\Public\\STUN.exe,STUN.EXE-FF001122.pf,3,2024-03-15 14:00:00,,C:\\USERS\\PUBLIC\\STUN.EXE|C:\\WINDOWS\\TEMP\\DROP.DLL,C:\\USERS\\PUBLIC,\\DEVICE\\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,FF001122,98304
certutil.exe,C:\\Windows\\System32\\certutil.exe,CERTUTIL.EXE-AA334455.pf,2,2024-03-15 14:05:00,,C:\\WINDOWS\\SYSTEM32\\CERTUTIL.EXE,C:\\WINDOWS\\SYSTEM32,\\DEVICE\\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,AA334455,65536
svchost.exe,C:\\Users\\Public\\svchost.exe,SVCHOST.EXE-BB667788.pf,1,2024-03-15 14:10:00,,C:\\USERS\\PUBLIC\\SVCHOST.EXE,C:\\USERS\\PUBLIC,\\DEVICE\\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,BB667788,20480
"""

LOLBAS_CSV = """\
ExecutableName,SourceFilePath,SourceFileName,RunCount,LastRun,RunTime1,FilesLoaded,Directories,VolumeName,VolumeSerial,VolumeCreated,Hash,Size
powershell.exe,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,POWERSHELL.EXE-CC889900.pf,8,2024-03-15 15:00:00,,C:\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE,C:\\WINDOWS\\SYSTEM32,\\DEVICE\\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,CC889900,450560
"""


# ── _parse_prefetch_csv ───────────────────────────────────────────────────────

class TestParsePrefetchCSV:
    def test_basic_parsing(self):
        entries = _parse_prefetch_csv(CLEAN_CSV)
        assert len(entries) == 2

    def test_field_names(self):
        entries = _parse_prefetch_csv(CLEAN_CSV)
        e = entries[0]
        assert e["executable_name"] == "notepad.exe"
        assert e["run_count"] == 5
        assert e["last_run_utc"] is not None
        assert isinstance(e["files_loaded"], list)
        assert len(e["files_loaded"]) == 2

    def test_files_loaded_split(self):
        entries = _parse_prefetch_csv(CLEAN_CSV)
        notepad = entries[0]
        assert "C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE" in notepad["files_loaded"]
        assert "C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL" in notepad["files_loaded"]

    def test_files_loaded_count(self):
        entries = _parse_prefetch_csv(CLEAN_CSV)
        assert entries[0]["files_loaded_count"] == 2

    def test_previous_run_times_parsed(self):
        entries = _parse_prefetch_csv(CLEAN_CSV)
        notepad = entries[0]
        assert isinstance(notepad["previous_run_times"], list)
        assert len(notepad["previous_run_times"]) >= 1

    def test_empty_csv(self):
        assert _parse_prefetch_csv("") == []

    def test_header_only(self):
        assert _parse_prefetch_csv(
            "ExecutableName,SourceFilePath,RunCount,LastRun\n"
        ) == []

    def test_run_count_is_int(self):
        entries = _parse_prefetch_csv(CLEAN_CSV)
        assert isinstance(entries[0]["run_count"], int)


# ── _flag_suspicious ──────────────────────────────────────────────────────────

class TestFlagSuspicious:
    def setup_method(self):
        self.entries = _parse_prefetch_csv(SUSPICIOUS_CSV)

    def test_public_path_flagged(self):
        stun = next(e for e in self.entries if e["executable_name"] == "STUN.exe")
        flagged = _flag_suspicious([stun])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("suspicious path" in r.lower() for r in reasons)

    def test_lolbas_flagged(self):
        certutil = next(e for e in self.entries if e["executable_name"] == "certutil.exe")
        flagged = _flag_suspicious([certutil])
        assert len(flagged) == 1
        assert any("lolbas" in r.lower() or "dual-use" in r.lower()
                   for r in flagged[0]["suspicion_reasons"])

    def test_masquerading_system_binary(self):
        svchost = next(e for e in self.entries if e["executable_name"] == "svchost.exe")
        flagged = _flag_suspicious([svchost])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("masquerad" in r.lower() or "non-system32" in r.lower()
                   or "non-" in r.lower() for r in reasons)

    def test_suspicious_file_loaded(self):
        # STUN.exe loads C:\WINDOWS\TEMP\DROP.DLL — suspicious loaded file
        stun = next(e for e in self.entries if e["executable_name"] == "STUN.exe")
        flagged = _flag_suspicious([stun])
        reasons = flagged[0]["suspicion_reasons"]
        assert any("loaded file" in r.lower() or "drop.dll" in r.lower()
                   or "temp" in r.lower() for r in reasons)

    def test_clean_entries_not_flagged(self):
        clean = _parse_prefetch_csv(CLEAN_CSV)
        flagged = _flag_suspicious(clean)
        # notepad and explorer are clean — no suspicious paths, not LOLBAS
        for f in flagged:
            # The only acceptable reason would be if explorer.exe were flagged
            # as a LOLBAS — it's not in our list, so nothing should be flagged
            assert False, f"Clean entry incorrectly flagged: {f['executable_name']}: {f['suspicion_reasons']}"

    def test_lolbas_powershell(self):
        entries = _parse_prefetch_csv(LOLBAS_CSV)
        flagged = _flag_suspicious(entries)
        assert len(flagged) == 1
        assert any("lolbas" in r.lower() or "dual-use" in r.lower()
                   for r in flagged[0]["suspicion_reasons"])

    def test_suspicion_reasons_is_list(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            assert isinstance(f["suspicion_reasons"], list)
            assert len(f["suspicion_reasons"]) > 0

    def test_original_fields_preserved(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            assert "executable_name" in f
            assert "run_count" in f
            assert "last_run_utc" in f
            assert "files_loaded" in f


# ── _norm_ts ──────────────────────────────────────────────────────────────────

class TestNormTs:
    def test_space_separated(self):
        result = _norm_ts("2024-03-15 14:00:00")
        assert "T" in result
        assert result.endswith("Z")

    def test_already_iso(self):
        assert _norm_ts("2024-03-15T14:00:00Z") == "2024-03-15T14:00:00Z"

    def test_empty_returns_none(self):
        assert _norm_ts("") is None
        assert _norm_ts("0") is None
        assert _norm_ts("N/A") is None

    def test_none_returns_none(self):
        assert _norm_ts(None) is None


# ── _safe_int ─────────────────────────────────────────────────────────────────

class TestSafeInt:
    def test_valid(self):
        assert _safe_int("42") == 42

    def test_empty(self):
        assert _safe_int("") is None

    def test_non_numeric(self):
        assert _safe_int("N/A") is None


# ── parse_prefetch integration (mocked subprocess) ───────────────────────────

class TestParsePrefetchIntegration:
    def _write_csv(self, out_dir: Path, prefix: str, content: str) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{prefix}_PECmd_Output.csv").write_text(content, encoding="utf-8")

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_successful_parse_directory(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "prefetch", CLEAN_CSV)

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] == 2
        assert result["tool"] == "PECmd"
        assert result["invocation_id"]

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_successful_parse_single_file(self, mock_run, tmp_path):
        pf_file = tmp_path / "STUN.EXE-FF001122.pf"
        pf_file.write_bytes(b"\x00" * 16)  # fake .pf content
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "STUN.EXE-FF001122", SUSPICIOUS_CSV)

        result = parse_prefetch(str(pf_file), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] > 0

    def test_missing_path_returns_error(self, tmp_path):
        result = parse_prefetch(str(tmp_path / "nonexistent"))
        assert result["error"] is not None
        assert "not found" in result["error"].lower()
        assert result["entries"] == []

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_suspicious_entries_populated(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "prefetch", SUSPICIOUS_CSV)

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir))

        assert len(result["suspicious"]) > 0
        for s in result["suspicious"]:
            assert "suspicion_reasons" in s
            assert len(s["suspicion_reasons"]) > 0

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_entries_sorted_most_recent_first(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "prefetch", CLEAN_CSV)

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir))

        timestamps = [
            e["last_run_utc"] for e in result["entries"]
            if e.get("last_run_utc")
        ]
        assert timestamps == sorted(timestamps, reverse=True)

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_context_window_cap(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = "ExecutableName,SourceFilePath,SourceFileName,RunCount,LastRun,RunTime1,FilesLoaded,Directories,VolumeName,VolumeSerial,VolumeCreated,Hash,Size\n"
        rows = "\n".join(
            f"prog{i}.exe,C:\\Windows\\prog{i}.exe,PROG{i}.EXE-{i:08X}.pf,"
            f"1,2024-01-01 00:00:00,,C:\\WINDOWS\\PROG{i}.EXE,,\\DEVICE\\HV2,ABCD,2023-01-01,{i:08X},1024"
            for i in range(600)
        )
        self._write_csv(out_dir, "prefetch", header + rows)

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir), include_all=False)

        assert result["total_entries"] == 600
        assert result["entries_returned"] <= 500
        assert result["entries_capped"] is True

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_include_all_bypasses_cap(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = "ExecutableName,SourceFilePath,SourceFileName,RunCount,LastRun,RunTime1,FilesLoaded,Directories,VolumeName,VolumeSerial,VolumeCreated,Hash,Size\n"
        rows = "\n".join(
            f"prog{i}.exe,C:\\Windows\\prog{i}.exe,PROG{i}.EXE-{i:08X}.pf,"
            f"1,2024-01-01 00:00:00,,C:\\WINDOWS\\PROG{i}.EXE,,\\DEVICE\\HV2,ABCD,2023-01-01,{i:08X},1024"
            for i in range(600)
        )
        self._write_csv(out_dir, "prefetch", header + rows)

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir), include_all=True)

        assert result["entries_returned"] == 600
        assert result["entries_capped"] is False

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_empty_prefetch_no_error(self, mock_run, tmp_path):
        """Empty Prefetch folder → no CSV → should return graceful no-error result."""
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"
        out_dir.mkdir()

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        # No CSV files written — simulates empty/disabled Prefetch

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] == 0
        assert "disabled" in result["analyst_note"].lower() or \
               "empty" in result["analyst_note"].lower()

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_tool_failure_returns_error(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()

        mock_run.side_effect = RuntimeError("Tool exited 1.\nSTDERR: Access denied")

        result = parse_prefetch(str(pf_dir))

        assert result["error"] is not None
        assert result["entries"] == []

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_audit_log_written(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "prefetch", CLEAN_CSV)

        with patch("mcp_server.tools._shared.AUDIT_FILE", tmp_path / "mcp.jsonl"):
            result = parse_prefetch(str(pf_dir), output_dir=str(out_dir))

        log_path = tmp_path / "mcp.jsonl"
        assert log_path.exists()

        records = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        assert len(records) >= 1
        record = records[-1]
        assert record["tool"] == "PECmd"
        assert record["invocation_id"] == result["invocation_id"]
        assert record["returncode"] == 0
        assert record["parsed_record_count"] == 2

    @patch("mcp_server.tools.prefetch.run_tool")
    def test_return_schema_complete(self, mock_run, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        out_dir = tmp_path / "prefetch_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "prefetch", CLEAN_CSV)

        result = parse_prefetch(str(pf_dir), output_dir=str(out_dir))

        required_keys = [
            "invocation_id", "tool", "prefetch_path", "run_ts_utc",
            "total_entries", "entries_returned", "entries_capped",
            "entries", "suspicious", "output_dir", "duration_ms",
            "error", "analyst_note",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"
