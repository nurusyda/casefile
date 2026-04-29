"""
Tests for parse_mft()

Run on any machine (no SIFT required):
    pytest tests/test_mft.py -v
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.tools.mft import (
    TIMESTOMP_THRESHOLD_SECONDS,
    _apply_filename_filter,
    _check_timestomping,
    _flag_suspicious,
    _norm_ts,
    _parse_mft_csv,
    parse_mft,
)


# ── CSV fixtures ──────────────────────────────────────────────────────────────

# Clean MFT entries — normal System32 files, no anomalies
CLEAN_CSV = r"""EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ResidentDataBase64,ResidentDataHex,ResidentDataASCII
100,1,True,80,2,.\Windows\System32,notepad.exe,.exe,204800,1,,False,False,False,False,False,False,Archive,Windows,2024-01-10 09:00:00,,2024-01-10 09:00:00,,2024-01-10 09:00:00,,2024-01-10 09:00:00,,,12345,,,,,/cases/MFT,,,
101,1,True,80,2,.\Windows\System32,calc.exe,.exe,102400,1,,False,False,False,False,False,False,Archive,Windows,2024-01-11 10:00:00,,2024-01-11 10:00:00,,2024-01-11 10:00:00,,2024-01-11 10:00:00,,,12345,,,,,/cases/MFT,,,
"""

# Timestomped entry — SI<FN=True, $SI created 2020 vs $FN created 2024
TIMESTOMPED_CSV = r"""EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ResidentDataBase64,ResidentDataHex,ResidentDataASCII
200,1,True,80,2,.\Windows\System32,STUN.exe,.exe,98304,1,,False,False,False,True,False,False,Archive,Windows,2020-01-01 00:00:00,2024-03-15 14:00:00,2020-01-01 00:00:00,2024-03-15 14:00:00,2020-01-01 00:00:00,2024-03-15 14:00:00,2020-01-01 00:00:00,2024-03-15 14:00:00,,12345,,,,,/cases/MFT,,,
"""

# Suspicious entries — deleted, ADS, suspicious path, IOC, Zone.Identifier
SUSPICIOUS_CSV = r"""EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ResidentDataBase64,ResidentDataHex,ResidentDataASCII
300,2,False,80,2,.\Users\Public,evil.exe,.exe,65536,1,,False,False,False,False,False,False,Archive,Windows,2024-01-10 09:00:00,,2024-01-10 09:00:00,,2024-01-10 09:00:00,,2024-01-10 09:00:00,,,12345,,,,,/cases/MFT,,,
301,1,True,80,2,.\Windows,legit.exe,.exe,40960,1,,False,True,False,False,False,False,Archive,Windows,2024-01-10 09:00:00,,2024-01-10 09:00:00,,2024-01-10 09:00:00,,2024-01-10 09:00:00,,,12345,,,,,/cases/MFT,,,
302,1,True,80,2,.\Windows\Temp,malware.exe,.exe,12345,1,,False,False,False,False,False,False,Archive,Windows,2024-03-15 14:00:00,,2024-03-15 14:00:00,,2024-03-15 14:00:00,,2024-03-15 14:00:00,,,12345,,,,,/cases/MFT,,,
303,1,True,80,2,.\Windows\System32,msedge.exe,.exe,98304,1,,False,False,False,False,False,False,Archive,Windows,2024-03-15 14:00:00,,2024-03-15 14:00:00,,2024-03-15 14:00:00,,2024-03-15 14:00:00,,,12345,,,,,/cases/MFT,,,
304,1,True,80,2,.\Users\tdungan\Downloads,tool.exe,.exe,55000,1,,False,False,False,False,False,False,Archive,Windows,2024-03-15 14:00:00,,2024-03-15 14:00:00,,2024-03-15 14:00:00,,2024-03-15 14:00:00,,,12345,,,,3,/cases/MFT,,,
"""

# ── _parse_mft_csv ────────────────────────────────────────────────────────────

class TestParseMftCSV:
    def test_basic_parsing(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        assert len(entries) == 2

    def test_field_names(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        e = entries[0]
        assert e["filename"] == "notepad.exe"
        assert e["extension"] == ".exe"
        assert e["in_use"] is True
        assert e["is_deleted"] is False

    def test_si_timestamps_parsed(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        e = entries[0]
        assert e["si_created_utc"] is not None
        assert "T" in e["si_created_utc"]

    def test_fn_timestamps_parsed(self):
        entries = _parse_mft_csv(TIMESTOMPED_CSV)
        e = entries[0]
        assert e["fn_created_utc"] is not None

    def test_timestomping_detected(self):
        entries = _parse_mft_csv(TIMESTOMPED_CSV)
        assert len(entries) == 1
        e = entries[0]
        assert e["timestomped"] is True
        assert e["timestomp_delta_s"] is not None
        assert e["timestomp_delta_s"] < 0  # SI predates FN

    def test_clean_not_timestomped(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        for e in entries:
            assert e["timestomped"] is False

    def test_deleted_flag(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        deleted = [e for e in entries if e["is_deleted"]]
        assert len(deleted) == 1
        assert deleted[0]["filename"] == "evil.exe"

    def test_ads_flag(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        ads = [e for e in entries if e["has_ads"]]
        assert len(ads) == 1
        assert ads[0]["filename"] == "legit.exe"

    def test_zone_id_parsed(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        downloaded = [e for e in entries if e.get("zone_id")]
        assert len(downloaded) == 1
        assert downloaded[0]["filename"] == "tool.exe"

    def test_empty_csv(self):
        assert _parse_mft_csv("") == []

    def test_required_fields_present(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        for e in entries:
            for key in ["entry_number", "full_path", "filename",
                        "si_created_utc", "fn_created_utc",
                        "timestomped", "is_deleted", "has_ads"]:
                assert key in e, f"Missing key: {key}"


# ── _check_timestomping ───────────────────────────────────────────────────────

class TestCheckTimestomping:
    def test_clear_timestomping(self):
        # SI created in 2020, FN created in 2024 — clear timestomping
        ts, delta = _check_timestomping(
            "2020-01-01T00:00:00Z",
            "2024-03-15T14:00:00Z",
            None, None,
        )
        assert ts is True
        assert delta is not None
        assert delta < 0

    def test_normal_no_timestomping(self):
        # Same timestamps — no timestomping
        ts, delta = _check_timestomping(
            "2024-03-15T14:00:00Z",
            "2024-03-15T14:00:00Z",
            None, None,
        )
        assert ts is False

    def test_small_delta_not_flagged(self):
        # 1 second delta — normal filesystem noise, not timestomping
        ts, delta = _check_timestomping(
            "2024-03-15T14:00:01Z",
            "2024-03-15T14:00:00Z",
            None, None,
        )
        assert ts is False

    def test_missing_timestamps(self):
        ts, delta = _check_timestomping(None, None, None, None)
        assert ts is False
        assert delta is None

    def test_threshold_boundary(self):
        # Just under threshold — not flagged
        ts, _ = _check_timestomping(
            "2024-03-15T13:59:00Z",  # 59s before FN
            "2024-03-15T14:00:00Z",
            None, None,
        )
        assert ts is False

        # Just over threshold — flagged
        ts, _ = _check_timestomping(
            "2024-03-15T13:58:59Z",  # 61s before FN
            "2024-03-15T14:00:00Z",
            None, None,
        )
        assert ts is True


# ── _apply_filename_filter ────────────────────────────────────────────────────

class TestApplyFilenameFilter:
    def test_filter_by_exact_name(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        filtered = _apply_filename_filter(entries, ["msedge.exe"])
        assert len(filtered) == 1
        assert filtered[0]["filename"] == "msedge.exe"

    def test_filter_by_fragment(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        filtered = _apply_filename_filter(entries, ["edge"])
        assert len(filtered) == 1

    def test_empty_filter_returns_all(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        filtered = _apply_filename_filter(entries, [])
        assert len(filtered) == len(entries)

    def test_no_match_returns_empty(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        filtered = _apply_filename_filter(entries, ["nonexistent.exe"])
        assert filtered == []

    def test_case_insensitive(self):
        entries = _parse_mft_csv(SUSPICIOUS_CSV)
        filtered = _apply_filename_filter(entries, ["MSEDGE.EXE"])
        assert len(filtered) == 1


# ── _flag_suspicious ──────────────────────────────────────────────────────────

class TestFlagSuspicious:
    def setup_method(self):
        self.entries = _parse_mft_csv(SUSPICIOUS_CSV)

    def test_deleted_file_flagged(self):
        deleted = next(e for e in self.entries if e["is_deleted"])
        flagged = _flag_suspicious([deleted])
        assert len(flagged) == 1
        assert any("deleted" in r.lower() for r in flagged[0]["suspicion_reasons"])

    def test_ads_flagged(self):
        ads = next(e for e in self.entries if e["has_ads"])
        flagged = _flag_suspicious([ads])
        assert len(flagged) == 1
        assert any("alternate data stream" in r.lower() or "ads" in r.lower()
                   for r in flagged[0]["suspicion_reasons"])

    def test_ioc_filename_flagged(self):
        ioc = next(e for e in self.entries if "msedge" in e["filename"].lower())
        flagged = _flag_suspicious([ioc])
        assert len(flagged) == 1
        assert any("ioc" in r.lower() or "crimson" in r.lower()
                   for r in flagged[0]["suspicion_reasons"])

    def test_zone_id_flagged(self):
        downloaded = next(e for e in self.entries if e.get("zone_id"))
        flagged = _flag_suspicious([downloaded])
        assert len(flagged) == 1
        assert any("zone" in r.lower() or "downloaded" in r.lower()
                   for r in flagged[0]["suspicion_reasons"])

    def test_timestomping_flagged(self):
        entries = _parse_mft_csv(TIMESTOMPED_CSV)
        flagged = _flag_suspicious(entries)
        assert len(flagged) == 1
        assert any("timestomp" in r.lower() for r in flagged[0]["suspicion_reasons"])

    def test_clean_not_flagged(self):
        entries = _parse_mft_csv(CLEAN_CSV)
        flagged = _flag_suspicious(entries)
        assert flagged == [], f"Clean entries incorrectly flagged: {flagged}"

    def test_suspicion_reasons_list(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            assert isinstance(f["suspicion_reasons"], list)
            assert len(f["suspicion_reasons"]) > 0


# ── parse_mft integration (mocked) ───────────────────────────────────────────

class TestParseMftIntegration:
    def _write_csv(self, out_dir: Path, prefix: str, content: str) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{prefix}_MFTECmd_Output.csv").write_text(
            content, encoding="utf-8"
        )

    @patch("mcp_server.tools.mft.run_tool")
    def test_successful_parse(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)  # fake MFT magic
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", CLEAN_CSV)

        result = parse_mft(str(mft_file), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["tool"] == "MFTECmd"
        assert result["invocation_id"]

    @patch("mcp_server.tools.mft.run_tool")
    def test_timestomped_entries_detected(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", TIMESTOMPED_CSV)

        result = parse_mft(str(mft_file), output_dir=str(out_dir))

        assert len(result["timestomped"]) == 1
        ts = result["timestomped"][0]
        assert ts["timestomped"] is True
        assert ts["filename"] == "STUN.exe"

    @patch("mcp_server.tools.mft.run_tool")
    def test_filename_filter_applied(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", SUSPICIOUS_CSV)

        result = parse_mft(
            str(mft_file),
            output_dir=str(out_dir),
            filename_filter=["msedge.exe"],
        )

        assert result["error"] is None
        for e in result["entries"]:
            assert "msedge" in e["filename"].lower()

    def test_missing_mft_returns_error(self, tmp_path):
        result = parse_mft(str(tmp_path / "nonexistent"))
        assert result["error"] is not None
        assert "not found" in result["error"].lower()

    @patch("mcp_server.tools.mft.run_tool")
    def test_at_flag_in_cmd(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", CLEAN_CSV)

        parse_mft(str(mft_file), output_dir=str(out_dir))

        cmd_used = mock_run.call_args[0][0]
        assert "--at" in cmd_used

    @patch("mcp_server.tools.mft.run_tool")
    def test_suspicious_entries_populated(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", SUSPICIOUS_CSV)

        result = parse_mft(str(mft_file), output_dir=str(out_dir))

        assert len(result["suspicious"]) > 0

    @patch("mcp_server.tools.mft.run_tool")
    def test_context_window_cap(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = (
            "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,FullPath,FileName,"
            "Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,"
            "SI_LastModified,SI_LastAccess,SI_MFTRecordChanged,SI_Created,"
            "FN_LastModified,FN_LastAccess,FN_MFTRecordChanged,FN_Created,"
            "ObjectIdFileDroid,LogfileSequenceNumber,SecurityId,ZoneIdContents,"
            "SIMftEntryFlags,FNMftEntryFlags\n"
        )
        ts = "2024-01-01 00:00:00"
        rows = "\n".join(
            f"{i},1,TRUE,80,C:\\Windows\\file{i}.dll,file{i}.dll,"
            f".dll,1024,1,,FALSE,FALSE,FALSE,"
            f"{ts},{ts},{ts},{ts},{ts},{ts},{ts},{ts},"
            f",{i},,,ARCHIVE,ARCHIVE"
            for i in range(600)
        )
        self._write_csv(out_dir, "mft", header + rows)

        result = parse_mft(
            str(mft_file),
            output_dir=str(out_dir),
            filename_filter=["file"],  # matches all 600
        )

        assert result["total_entries"] == 600
        assert result["entries_returned"] <= 500
        assert result["entries_capped"] is True

    @patch("mcp_server.tools.mft.run_tool")
    def test_tool_failure_returns_error(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE")

        mock_run.side_effect = RuntimeError("Tool exited 1.\nSTDERR: Out of memory")

        result = parse_mft(str(mft_file))

        assert result["error"] is not None
        assert result["entries"] == []

    @patch("mcp_server.tools.mft.run_tool")
    def test_audit_log_written(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", CLEAN_CSV)

        with patch("mcp_server.tools._shared.AUDIT_FILE", tmp_path / "mcp.jsonl"):
            result = parse_mft(str(mft_file), output_dir=str(out_dir))

        log_path = tmp_path / "mcp.jsonl"
        assert log_path.exists()

        records = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        record = records[-1]
        assert record["tool"] == "MFTECmd"
        assert record["invocation_id"] == result["invocation_id"]
        assert "examiner" in record
        assert record["examiner"] == "casefile"

    @patch("mcp_server.tools.mft.run_tool")
    def test_return_schema_complete(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "mft", CLEAN_CSV)

        result = parse_mft(str(mft_file), output_dir=str(out_dir))

        required = [
            "invocation_id", "tool", "mft_path", "run_ts_utc",
            "total_entries", "entries_returned", "entries_capped",
            "entries", "timestomped", "suspicious",
            "output_dir", "duration_ms", "error", "analyst_note",
        ]
        for key in required:
            assert key in result, f"Missing key: {key}"
