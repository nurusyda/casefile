"""
test_memory.py — tests for parse_memory() MCP tool

Tests cover:
  • Plugin allowlist enforcement
  • Image path validation (missing, symlink, directory)
  • Successful pslist parsing against fixture
  • Real-world IOC detection (subject_srv.exe, csrss impersonator)
  • Cache hit / miss behavior
  • Audit log fields
  • Subprocess timeout
  • Missing vol binary
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mcp_server.tools.memory import (
    ALLOWED_PLUGINS,
    CACHE_SCHEMA_VERSION,
    MemoryToolError,
    parse_memory,
)


# ── Fixtures ────────────────────────────────────────────────────────────────────

# This is what `vol -f <image> windows.pslist` actually produced on the
# CRIMSON OSPREY base-rd-01 memory image (2018-08-30 13:51 UTC).
PSLIST_REAL = """\
Volatility 3 Framework 2.27.0

PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output
4	0	System	0x8c88aea4e040	135	-	N/A	False	2018-08-30 13:51:58.000000 UTC	N/A	Disabled
552	540	csrss.exe	0x8c88b0794580	13	-	0	False	2018-08-30 13:52:20.000000 UTC	N/A	Disabled
648	624	csrss.exe	0x8c88b2b42080	10	-	1	False	2018-08-30 13:52:20.000000 UTC	N/A	Disabled
4048	8200	csrss.exe	0x8c88b2d27580	11	-	3	False	2018-08-31 14:52:31.000000 UTC	N/A	Disabled
1096	740	subject_srv.ex	0x8c88b84e4080	11	-	0	True	2018-09-06 18:28:30.000000 UTC	N/A	Disabled
"""


@pytest.fixture
def memory_image(tmp_path: Path) -> Path:
    """Fake memory image file — content doesn't matter, only the path."""
    img = tmp_path / "fake-memory.img"
    img.write_bytes(b"FAKE_MEMORY_IMAGE_CONTENT_FOR_HASHING")
    return img


@pytest.fixture
def case_dir(tmp_path: Path, monkeypatch) -> Path:
    """Isolated CASEFILE_CASE_DIR per test."""
    case = tmp_path / "case"
    case.mkdir()
    monkeypatch.setenv("CASEFILE_CASE_DIR", str(case))
    monkeypatch.setenv("CASEFILE_EXAMINER", "casefile")
    return case


@pytest.fixture
def audit_redirect(tmp_path: Path):
    """Redirect audit log to tmp_path/mcp.jsonl."""
    audit_file = tmp_path / "mcp.jsonl"
    with patch("mcp_server.tools._shared.AUDIT_FILE", audit_file):
        yield audit_file


def _read_audit(audit_file: Path) -> list[dict]:
    if not audit_file.exists():
        return []
    return [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]


# ── Plugin allowlist ───────────────────────────────────────────────────────────

class TestPluginAllowlist:
    def test_invalid_plugin_rejected(self, memory_image, case_dir, audit_redirect):
        with pytest.raises(MemoryToolError, match="not in the allowlist"):
            parse_memory(str(memory_image), plugin="windows.dumpfiles")

    def test_invalid_plugin_logs_audit(self, memory_image, case_dir, audit_redirect):
        with pytest.raises(MemoryToolError):
            parse_memory(str(memory_image), plugin="evil.plugin")

        records = _read_audit(audit_redirect)
        assert len(records) == 1
        assert records[0]["returncode"] == -1
        assert records[0]["plugin_requested"] == "evil.plugin"
        assert records[0]["rejection_reason"] == "plugin_not_allowed"

    def test_dump_plugins_excluded(self):
        """Plugins that write files must NEVER be in the allowlist."""
        forbidden = {"windows.dumpfiles", "windows.memmap", "windows.procdump"}
        assert ALLOWED_PLUGINS.isdisjoint(forbidden)


# ── Image path validation ──────────────────────────────────────────────────────

class TestImagePathValidation:
    def test_missing_file_rejected(self, tmp_path, case_dir, audit_redirect):
        with pytest.raises(MemoryToolError, match="not found"):
            parse_memory(str(tmp_path / "nope.img"), plugin="windows.pslist")

    def test_directory_rejected(self, tmp_path, case_dir, audit_redirect):
        with pytest.raises(MemoryToolError, match="not a regular file"):
            parse_memory(str(tmp_path), plugin="windows.pslist")

    def test_symlink_rejected(self, tmp_path, memory_image, case_dir, audit_redirect):
        link = tmp_path / "link.img"
        link.symlink_to(memory_image)
        with pytest.raises(MemoryToolError, match="symlink"):
            parse_memory(str(link), plugin="windows.pslist")


# ── Successful parsing path ────────────────────────────────────────────────────

class TestParseMemorySuccess:
    @patch("mcp_server.tools.memory.subprocess.run")
    def test_pslist_returns_structured_json(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        result = parse_memory(str(memory_image), plugin="windows.pslist")

        assert result["tool"] == "Volatility3"
        assert result["plugin"] == "windows.pslist"
        assert result["error"] is None
        assert result["cached"] is False
        assert result["total_records"] == 5
        assert isinstance(result["records"], list)
        assert "image_sha256" in result
        assert len(result["image_sha256"]) == 64

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_subject_srv_found_in_real_pslist(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        """The CRIMSON OSPREY smoking gun — subject_srv was running."""
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        result = parse_memory(str(memory_image), plugin="windows.pslist")

        names = [r.get("ImageFileName", "") for r in result["records"]]
        assert any("subject_srv" in n for n in names), (
            f"subject_srv.exe not found in records. Got: {names}"
        )

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_csrss_impersonator_pid_4048(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        """The fake csrss in session 3 — confirms disk Prefetch finding."""
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        result = parse_memory(str(memory_image), plugin="windows.pslist")

        csrss_records = [r for r in result["records"]
                         if r.get("ImageFileName") == "csrss.exe"]
        assert len(csrss_records) == 3
        pids = {r["PID"] for r in csrss_records}
        assert "4048" in pids, f"PID 4048 (impersonator) missing. PIDs found: {pids}"

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_return_schema_complete(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        result = parse_memory(str(memory_image), plugin="windows.pslist")

        required = {
            "invocation_id", "tool", "plugin", "image_path", "image_sha256",
            "run_ts_utc", "total_records", "records", "duration_ms",
            "cached", "error", "analyst_note", "schema_version",
        }
        assert required.issubset(result.keys()), (
            f"Missing keys: {required - result.keys()}"
        )


# ── Audit log behavior ─────────────────────────────────────────────────────────

class TestAuditLog:
    @patch("mcp_server.tools.memory.subprocess.run")
    def test_audit_log_written_on_success(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        result = parse_memory(str(memory_image), plugin="windows.pslist")

        records = _read_audit(audit_redirect)
        assert len(records) == 1
        rec = records[0]
        assert rec["tool"] == "Volatility3"
        assert rec["invocation_id"] == result["invocation_id"]
        assert rec["plugin"] == "windows.pslist"
        assert rec["image_sha256"] == result["image_sha256"]
        assert rec["returncode"] == 0
        assert rec["parsed_record_count"] == 5

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_audit_log_includes_examiner(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        with patch.dict("os.environ", {"CASEFILE_EXAMINER": "casefile"}, clear=False):
            parse_memory(str(memory_image), plugin="windows.pslist")

        records = _read_audit(audit_redirect)
        assert records[0].get("examiner") == "casefile"


# ── Caching ────────────────────────────────────────────────────────────────────

class TestCaching:
    @patch("mcp_server.tools.memory.subprocess.run")
    def test_second_call_uses_cache(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        first = parse_memory(str(memory_image), plugin="windows.pslist")
        second = parse_memory(str(memory_image), plugin="windows.pslist")

        assert mock_run.call_count == 1, "Volatility ran twice — cache miss"
        assert first["cached"] is False
        assert second["cached"] is True
        assert first["total_records"] == second["total_records"]
        # Different invocation IDs even on cache hit
        assert first["invocation_id"] != second["invocation_id"]

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_use_cache_false_forces_rerun(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        parse_memory(str(memory_image), plugin="windows.pslist")
        parse_memory(str(memory_image), plugin="windows.pslist", use_cache=False)
        assert mock_run.call_count == 2

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_corrupt_cache_falls_through_to_rerun(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout=PSLIST_REAL, stderr=""
        )
        # First run populates cache
        first_result = parse_memory(str(memory_image), plugin="windows.pslist")
        # Corrupt the cache
        sha_short = first_result["image_sha256"][:16]
        cache_file = case_dir / "memory_cache" / sha_short / "windows.pslist.json"
        cache_file.write_text("{not valid json", encoding="utf-8")

        # Second call should re-run, not crash
        second = parse_memory(str(memory_image), plugin="windows.pslist")
        assert second["cached"] is False
        assert mock_run.call_count == 2


# ── Subprocess error paths ─────────────────────────────────────────────────────

class TestSubprocessErrors:
    @patch("mcp_server.tools.memory.subprocess.run")
    def test_volatility_nonzero_exit(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.return_value = SimpleNamespace(
            returncode=1, stdout="", stderr="No suitable address space"
        )
        with pytest.raises(MemoryToolError, match="No suitable address space"):
            parse_memory(str(memory_image), plugin="windows.pslist")

        records = _read_audit(audit_redirect)
        assert records[-1]["returncode"] == 1
        assert "No suitable address space" in records[-1]["stderr_excerpt"]

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_subprocess_timeout(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="vol", timeout=600)
        with pytest.raises(MemoryToolError, match="timed out"):
            parse_memory(str(memory_image), plugin="windows.pslist", timeout_sec=1)

        records = _read_audit(audit_redirect)
        assert records[-1]["timeout"] is True

    @patch("mcp_server.tools.memory.subprocess.run")
    def test_vol_binary_missing(
        self, mock_run, memory_image, case_dir, audit_redirect
    ):
        mock_run.side_effect = FileNotFoundError("vol")
        with pytest.raises(MemoryToolError, match="not found"):
            parse_memory(str(memory_image), plugin="windows.pslist")

        records = _read_audit(audit_redirect)
        assert records[-1]["rejection_reason"] == "vol_binary_missing"
