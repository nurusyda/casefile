"""
Tests for parse_registry()

Run on any machine (no SIFT required):
    pytest tests/test_registry.py -v
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.tools.registry import (
    KROLL_BATCH_FILE,
    _build_category_summary,
    _flag_suspicious,
    _norm_ts,
    _parse_recmd_csv,
    parse_registry,
)


# ── CSV fixtures (concatenated strings — no backslash escaping issues) ────────

CLEAN_CSV = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueData,"
    "ValueData2,ValueData3,Comment,Recursive,DeletedRecord,LastWriteTimestamp\n"
    "NTUSER.DAT,NTUser,Run key,run,"
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run,"
    "OneDrive,C:\\Program Files\\OneDrive\\OneDrive.exe /background,"
    ",,,FALSE,FALSE,2024-01-15 10:00:00\n"
    "NTUSER.DAT,NTUser,UserAssist,userassist,"
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist,"
    "notepad.exe,RunCount: 5 | LastRun: 2024-02-01 09:00:00,"
    ",,,FALSE,FALSE,2024-02-01 09:00:00\n"
)

SUSPICIOUS_CSV = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueData,"
    "ValueData2,ValueData3,Comment,Recursive,DeletedRecord,LastWriteTimestamp\n"
    "NTUSER.DAT,NTUser,Run key,run,"
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run,"
    "STUN,C:\\Windows\\System32\\STUN.exe,,,"
    ",FALSE,FALSE,2024-03-15 14:00:00\n"
    "SYSTEM,System,Services,services,"
    "SYSTEM\\CurrentControlSet\\Services\\pssdnsvc,"
    "ImagePath,C:\\Windows\\System32\\STUN.exe,,,"
    ",FALSE,FALSE,2024-03-15 14:01:00\n"
    "NTUSER.DAT,NTUser,Run key,run,"
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run,"
    "updater,powershell -enc SGVsbG8gV29ybGQ=,,,"
    ",FALSE,FALSE,2024-03-15 14:02:00\n"
    "NTUSER.DAT,NTUser,Run key,run,"
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run,"
    "deleted_entry,C:\\temp\\evil.exe,,,"
    ",FALSE,TRUE,2024-03-15 14:03:00\n"
)

USB_CSV = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueData,"
    "ValueData2,ValueData3,Comment,Recursive,DeletedRecord,LastWriteTimestamp\n"
    "SYSTEM,System,USB Devices,usb,"
    "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk,"
    "FriendlyName,SanDisk Ultra USB,,,"
    ",FALSE,FALSE,2024-03-10 08:00:00\n"
)


# ── _parse_recmd_csv ──────────────────────────────────────────────────────────

class TestParseRecmdCSV:
    def test_basic_parsing(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        assert len(entries) == 2

    def test_field_names(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        e = entries[0]
        assert e["category"] == "run"
        assert e["value_name"] == "OneDrive"
        assert "OneDrive.exe" in e["value_data"]

    def test_category_lowercased(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        assert entries[0]["category"] == entries[0]["category"].lower()

    def test_timestamp_parsed(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        assert entries[0]["last_write_utc"] is not None
        assert "T" in entries[0]["last_write_utc"]

    def test_deleted_flag(self):
        entries = _parse_recmd_csv(SUSPICIOUS_CSV)
        deleted = [e for e in entries if e.get("deleted")]
        assert len(deleted) == 1
        assert deleted[0]["value_name"] == "deleted_entry"

    def test_empty_csv(self):
        assert _parse_recmd_csv("") == []

    def test_header_only(self):
        assert _parse_recmd_csv(
            "HivePath,HiveType,Category,KeyPath,ValueName,ValueData\n"
        ) == []

    def test_value_data_combined(self):
        # ValueData2 and ValueData3 should be combined with " | "
        csv = (
            "HivePath,HiveType,Description,Category,KeyPath,ValueName,"
            "ValueData,ValueData2,ValueData3,Comment,Recursive,DeletedRecord,"
            "LastWriteTimestamp\n"
            "NTUSER.DAT,NTUser,Test,userassist,some\\key,prog.exe,"
            "RunCount: 3,LastRun: 2024-01-01,,,,FALSE,2024-01-01 00:00:00\n"
        )
        entries = _parse_recmd_csv(csv)
        assert len(entries) == 1
        assert "RunCount: 3" in entries[0]["value_data"]
        assert "LastRun: 2024-01-01" in entries[0]["value_data"]

    def test_required_fields_present(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        for e in entries:
            for key in ["category", "key_path", "value_name",
                        "value_data", "last_write_utc", "deleted"]:
                assert key in e, f"Missing key: {key}"


# ── _flag_suspicious ──────────────────────────────────────────────────────────

class TestFlagSuspicious:
    def setup_method(self):
        self.entries = _parse_recmd_csv(SUSPICIOUS_CSV)

    def test_run_key_stun_flagged(self):
        stun = next(e for e in self.entries if e["value_name"] == "STUN")
        flagged = _flag_suspicious([stun])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("persistence" in r.lower() or "run" in r.lower()
                   for r in reasons)

    def test_service_pssdnsvc_flagged(self):
        svc = next(e for e in self.entries if e["value_name"] == "ImagePath")
        flagged = _flag_suspicious([svc])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("pssdnsvc" in r.lower() or "ioc" in r.lower()
                   for r in reasons)

    def test_powershell_encoded_flagged(self):
        ps = next(e for e in self.entries if e["value_name"] == "updater")
        flagged = _flag_suspicious([ps])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("powershell" in r.lower() or "-enc" in r.lower()
                   for r in reasons)

    def test_deleted_entry_flagged(self):
        deleted = next(e for e in self.entries if e.get("deleted"))
        flagged = _flag_suspicious([deleted])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("deleted" in r.lower() or "anti-forensic" in r.lower()
                   for r in reasons)

    def test_clean_run_key_not_flagged(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        onedrive = next(e for e in entries if e["value_name"] == "OneDrive")
        flagged = _flag_suspicious([onedrive])
        assert flagged == [], f"OneDrive incorrectly flagged: {flagged}"

    def test_suspicion_reasons_no_duplicates(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            assert len(f["suspicion_reasons"]) == len(set(f["suspicion_reasons"]))

    def test_original_fields_preserved(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            for key in ["category", "key_path", "value_name", "value_data"]:
                assert key in f


# ── _build_category_summary ───────────────────────────────────────────────────

class TestBuildCategorySummary:
    def test_counts_correctly(self):
        entries = _parse_recmd_csv(SUSPICIOUS_CSV)
        summary = _build_category_summary(entries)
        assert summary["run"] == 3  # 3 run key entries in SUSPICIOUS_CSV
        assert summary["services"] == 1

    def test_empty_entries(self):
        assert _build_category_summary([]) == {}

    def test_returns_dict(self):
        entries = _parse_recmd_csv(CLEAN_CSV)
        summary = _build_category_summary(entries)
        assert isinstance(summary, dict)


# ── parse_registry integration (mocked) ──────────────────────────────────────

class TestParseRegistryIntegration:
    def _write_csv(self, out_dir: Path, prefix: str, content: str) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{prefix}_RECmd_Batch_Output.csv").write_text(
            content, encoding="utf-8"
        )

    def _make_batch_file(self, tmp_path: Path) -> Path:
        """Create a fake batch file so path validation passes."""
        batch = tmp_path / "Kroll_Batch.reb"
        batch.write_text("# fake batch file for testing\n")
        return batch

    @patch("mcp_server.tools.registry.run_tool")
    def test_successful_parse(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", CLEAN_CSV)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        assert result["error"] is None
        assert result["total_entries"] == 2
        assert result["tool"] == "RECmd"
        assert result["invocation_id"]

    @patch("mcp_server.tools.registry.run_tool")
    def test_suspicious_entries_populated(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", SUSPICIOUS_CSV)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        assert len(result["suspicious"]) > 0
        for s in result["suspicious"]:
            assert "suspicion_reasons" in s

    @patch("mcp_server.tools.registry.run_tool")
    def test_category_summary_populated(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", SUSPICIOUS_CSV)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        assert isinstance(result["category_summary"], dict)
        assert "run" in result["category_summary"]

    def test_missing_hive_dir_returns_error(self, tmp_path):
        result = parse_registry(str(tmp_path / "nonexistent"))
        assert result["error"] is not None
        assert "not found" in result["error"].lower()

    def test_missing_batch_file_returns_error(self, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        result = parse_registry(
            str(hive_dir),
            batch_file=str(tmp_path / "nonexistent.reb"),
        )
        assert result["error"] is not None
        assert "batch file" in result["error"].lower()

    @patch("mcp_server.tools.registry.run_tool")
    def test_context_window_cap(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = (
            "HivePath,HiveType,Description,Category,KeyPath,ValueName,"
            "ValueData,ValueData2,ValueData3,Comment,Recursive,"
            "DeletedRecord,LastWriteTimestamp\n"
        )
        rows = "\n".join(
            f"NTUSER.DAT,NTUser,UserAssist,userassist,"
            f"Software\\UserAssist,prog{i}.exe,RunCount: 1,,,"
            f",FALSE,FALSE,2024-01-01 00:00:00"
            for i in range(600)
        )
        self._write_csv(out_dir, "registry", header + rows)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
            include_all=False,
        )

        assert result["total_entries"] == 600
        assert result["entries_returned"] <= 500
        assert result["entries_capped"] is True

    @patch("mcp_server.tools.registry.run_tool")
    def test_include_all_bypasses_cap(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = (
            "HivePath,HiveType,Description,Category,KeyPath,ValueName,"
            "ValueData,ValueData2,ValueData3,Comment,Recursive,"
            "DeletedRecord,LastWriteTimestamp\n"
        )
        rows = "\n".join(
            f"NTUSER.DAT,NTUser,UserAssist,userassist,"
            f"Software\\UserAssist,prog{i}.exe,RunCount: 1,,,"
            f",FALSE,FALSE,2024-01-01 00:00:00"
            for i in range(600)
        )
        self._write_csv(out_dir, "registry", header + rows)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
            include_all=True,
        )

        assert result["entries_returned"] == 600
        assert result["entries_capped"] is False

    @patch("mcp_server.tools.registry.run_tool")
    def test_empty_output_no_error(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        out_dir.mkdir()
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        # No CSV written

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        assert result["error"] is None
        assert result["total_entries"] == 0
        assert result["analyst_note"] is not None

    @patch("mcp_server.tools.registry.run_tool")
    def test_tool_failure_returns_error(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        batch = self._make_batch_file(tmp_path)

        mock_run.side_effect = RuntimeError("Tool exited 1.\nSTDERR: Hive locked")

        result = parse_registry(str(hive_dir), batch_file=str(batch))

        assert result["error"] is not None
        assert result["entries"] == []

    @patch("mcp_server.tools.registry.run_tool")
    def test_audit_log_written(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", CLEAN_CSV)

        with patch("mcp_server.tools._shared.AUDIT_FILE", tmp_path / "mcp.jsonl"):
            result = parse_registry(
                str(hive_dir),
                batch_file=str(batch),
                output_dir=str(out_dir),
            )

        log_path = tmp_path / "mcp.jsonl"
        assert log_path.exists()

        records = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        record = records[-1]
        assert record["tool"] == "RECmd"
        assert record["invocation_id"] == result["invocation_id"]
        assert record["parsed_record_count"] == 2

    @patch("mcp_server.tools.registry.run_tool")
    def test_return_schema_complete(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", CLEAN_CSV)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        required = [
            "invocation_id", "tool", "hive_dir", "batch_file",
            "run_ts_utc", "total_entries", "entries_returned",
            "entries_capped", "entries", "suspicious",
            "category_summary", "output_dir", "duration_ms",
            "error", "analyst_note",
        ]
        for key in required:
            assert key in result, f"Missing key: {key}"

    @patch("mcp_server.tools.registry.run_tool")
    def test_batch_file_path_in_cmd(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", CLEAN_CSV)

        parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        cmd_used = mock_run.call_args[0][0]
        assert "--bn" in cmd_used
        assert str(batch) in cmd_used

    @patch("mcp_server.tools.registry.run_tool")
    def test_entries_sorted_most_recent_first(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch = self._make_batch_file(tmp_path)

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "registry", SUSPICIOUS_CSV)

        result = parse_registry(
            str(hive_dir),
            batch_file=str(batch),
            output_dir=str(out_dir),
        )

        timestamps = [
            e["last_write_utc"] for e in result["entries"]
            if e.get("last_write_utc")
        ]
        assert timestamps == sorted(timestamps, reverse=True)
