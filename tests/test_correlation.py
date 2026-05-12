"""Tests for mcp_server/tools/correlation.py — Block 8 Commit 1.

Coverage plan (32 tests):
  - TestDecideVerdict:       All 5 verdict paths + sub-cases + determinism
  - TestInputValidation:     Empty/None/whitespace process_name, missing case_dir
  - TestReturnSchema:        All required keys present, types correct
  - TestSupportingIds:       invocation_ids collected from present sources only
  - TestAuditLog:            Audit entry written with correct fields
  - TestSourceResultDataclass: to_dict serialisation behaviour
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.tools.correlation import (
    CorrelationToolError,
    SourceResult,
    _decide_verdict,
    correlate_evidence,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Isolated case directory with audit/ pre-created."""
    case = tmp_path / "case"
    case.mkdir()
    audit = case / "audit"
    audit.mkdir()
    monkeypatch.setenv("CASEFILE_CASE_DIR", str(case))
    monkeypatch.setenv("CASEFILE_EXAMINER", "test-examiner")
    # Redirect AUDIT_FILE to tmp_path so tests don't write to real repo
    audit_file = audit / "mcp.jsonl"
    monkeypatch.setattr("mcp_server.tools._shared.AUDIT_FILE", audit_file)
    return case


# --------------------------------------------------------------------------- #
# Helpers — build SourceResult combos for _decide_verdict()
# --------------------------------------------------------------------------- #

def _sr(source: str, present: bool = False, inv: str = "") -> SourceResult:
    return SourceResult(source=source, present=present, invocation_id=inv)


# --------------------------------------------------------------------------- #
# TestDecideVerdict — pure function, no I/O
# --------------------------------------------------------------------------- #

class TestDecideVerdict:
    """All 5 verdict paths + the CONFIRMED_RUNNING sub-cases."""

    def test_confirmed_running_all_sources(self):
        """Memory + disk execution evidence -> CONFIRMED_RUNNING."""
        verdict, reasoning = _decide_verdict(
            amcache=_sr("amcache", True),
            prefetch=_sr("prefetch", True),
            memory=_sr("memory", True),
            mft=_sr("mft", True),
        )
        assert verdict == "CONFIRMED_RUNNING"
        assert "memory" in reasoning.lower()

    def test_confirmed_running_memory_plus_mft_only(self):
        """Memory + MFT but no Amcache/Prefetch -> still CONFIRMED_RUNNING."""
        verdict, _ = _decide_verdict(
            amcache=_sr("amcache", False),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", True),
            mft=_sr("mft", True),
        )
        assert verdict == "CONFIRMED_RUNNING"

    def test_confirmed_running_memory_plus_amcache(self):
        """Memory + Amcache (no Prefetch) -> CONFIRMED_RUNNING."""
        verdict, _ = _decide_verdict(
            amcache=_sr("amcache", True),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", True),
            mft=_sr("mft", False),
        )
        assert verdict == "CONFIRMED_RUNNING"

    def test_memory_only(self):
        """Memory only, no disk artifacts -> MEMORY_ONLY."""
        verdict, reasoning = _decide_verdict(
            amcache=_sr("amcache", False),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", True),
            mft=_sr("mft", False),
        )
        assert verdict == "MEMORY_ONLY"
        assert "injection" in reasoning.lower() or "fileless" in reasoning.lower()

    def test_confirmed_historical_amcache_and_prefetch(self):
        """Amcache + Prefetch, no memory -> CONFIRMED_HISTORICAL."""
        verdict, reasoning = _decide_verdict(
            amcache=_sr("amcache", True),
            prefetch=_sr("prefetch", True),
            memory=_sr("memory", False),
            mft=_sr("mft", True),
        )
        assert verdict == "CONFIRMED_HISTORICAL"
        assert "not" in reasoning.lower() and "memory" in reasoning.lower()

    def test_confirmed_historical_prefetch_only(self):
        """Prefetch only (no Amcache, no memory) -> CONFIRMED_HISTORICAL."""
        verdict, _ = _decide_verdict(
            amcache=_sr("amcache", False),
            prefetch=_sr("prefetch", True),
            memory=_sr("memory", False),
            mft=_sr("mft", False),
        )
        assert verdict == "CONFIRMED_HISTORICAL"

    def test_confirmed_historical_amcache_only(self):
        """Amcache only (no Prefetch, no memory) -> CONFIRMED_HISTORICAL."""
        verdict, _ = _decide_verdict(
            amcache=_sr("amcache", True),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", False),
            mft=_sr("mft", False),
        )
        assert verdict == "CONFIRMED_HISTORICAL"

    def test_installed_never_ran(self):
        """MFT only, no execution evidence -> INSTALLED_NEVER_RAN."""
        verdict, reasoning = _decide_verdict(
            amcache=_sr("amcache", False),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", False),
            mft=_sr("mft", True),
        )
        assert verdict == "INSTALLED_NEVER_RAN"
        assert "never" in reasoning.lower() or "no" in reasoning.lower()

    def test_not_found(self):
        """Nothing present -> NOT_FOUND."""
        verdict, reasoning = _decide_verdict(
            amcache=_sr("amcache", False),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", False),
            mft=_sr("mft", False),
        )
        assert verdict == "NOT_FOUND"
        assert "not found" in reasoning.lower()

    def test_verdict_is_deterministic(self):
        """Same inputs -> same outputs (no randomness)."""
        args = dict(
            amcache=_sr("amcache", True),
            prefetch=_sr("prefetch", False),
            memory=_sr("memory", True),
            mft=_sr("mft", True),
        )
        v1, r1 = _decide_verdict(**args)
        v2, r2 = _decide_verdict(**args)
        assert v1 == v2
        assert r1 == r2


# --------------------------------------------------------------------------- #
# TestInputValidation
# --------------------------------------------------------------------------- #

class TestInputValidation:
    """Input validation for correlate_evidence()."""

    def test_empty_process_name_raises(self, case_dir):
        with pytest.raises(CorrelationToolError, match="non-empty string"):
            correlate_evidence(process_name="", case_dir=str(case_dir))

    def test_none_process_name_raises(self, case_dir):
        with pytest.raises(CorrelationToolError, match="non-empty string"):
            correlate_evidence(process_name=None, case_dir=str(case_dir))

    def test_whitespace_only_process_name_raises(self, case_dir):
        with pytest.raises(CorrelationToolError, match="blank"):
            correlate_evidence(process_name="   ", case_dir=str(case_dir))

    def test_missing_case_dir_raises(self, monkeypatch):
        monkeypatch.delenv("CASEFILE_CASE_DIR", raising=False)
        with pytest.raises(CorrelationToolError, match="case_dir"):
            correlate_evidence(process_name="test.exe")


# --------------------------------------------------------------------------- #
# TestReturnSchema
# --------------------------------------------------------------------------- #

class TestReturnSchema:
    """Return dict must contain all required keys with correct types."""

    REQUIRED_KEYS = {
        "process_name",
        "amcache",
        "prefetch",
        "memory",
        "mft",
        "verdict",
        "confidence",
        "verdict_reasoning",
        "supporting_invocation_ids",
        "invocation_id",
    }

    def test_all_required_keys_present(self, case_dir):
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert self.REQUIRED_KEYS.issubset(result.keys()), (
            f"Missing keys: {self.REQUIRED_KEYS - result.keys()}"
        )

    def test_verdict_is_valid_value(self, case_dir):
        from mcp_server.tools.correlation import VERDICTS
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert result["verdict"] in VERDICTS

    def test_confidence_is_valid_label(self, case_dir):
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert result["confidence"] in {"CONFIRMED", "INFERRED", "HYPOTHESIS"}

    def test_source_sections_have_present_key(self, case_dir):
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        for source in ("amcache", "prefetch", "memory", "mft"):
            assert "present" in result[source], f"{source} missing 'present' key"
            assert isinstance(result[source]["present"], bool)

    def test_supporting_invocation_ids_is_list(self, case_dir):
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert isinstance(result["supporting_invocation_ids"], list)

    def test_invocation_id_starts_with_correlation(self, case_dir):
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert result["invocation_id"].startswith("correlation_")

    def test_process_name_preserved(self, case_dir):
        result = correlate_evidence("subject_srv.exe", case_dir=str(case_dir))
        assert result["process_name"] == "subject_srv.exe"

    def test_process_name_stripped(self, case_dir):
        result = correlate_evidence("  test.exe  ", case_dir=str(case_dir))
        assert result["process_name"] == "test.exe"

    def test_verdict_reasoning_is_string(self, case_dir):
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert isinstance(result["verdict_reasoning"], str)
        assert len(result["verdict_reasoning"]) > 10  # not trivially empty


# --------------------------------------------------------------------------- #
# TestSupportingIds
# --------------------------------------------------------------------------- #

class TestSupportingIds:
    """supporting_invocation_ids collects IDs only from present sources."""

    def test_collects_ids_from_present_sources(self, case_dir):
        """When stubs return invocation_ids, they appear in the list."""
        fake_amcache = SourceResult(
            source="amcache", present=True, invocation_id="amcache_inv_001"
        )
        fake_prefetch = SourceResult(
            source="prefetch", present=False, invocation_id=""
        )
        fake_memory = SourceResult(
            source="memory", present=True, invocation_id="memory_inv_003"
        )
        fake_mft = SourceResult(source="mft", present=False, invocation_id="")

        with (
            patch(
                "mcp_server.tools.correlation._call_parse_amcache",
                return_value=fake_amcache,
            ),
            patch(
                "mcp_server.tools.correlation._call_parse_prefetch",
                return_value=fake_prefetch,
            ),
            patch(
                "mcp_server.tools.correlation._call_parse_memory",
                return_value=fake_memory,
            ),
            patch(
                "mcp_server.tools.correlation._call_parse_mft",
                return_value=fake_mft,
            ),
        ):
            result = correlate_evidence("test.exe", case_dir=str(case_dir))

        assert "amcache_inv_001" in result["supporting_invocation_ids"]
        assert "memory_inv_003" in result["supporting_invocation_ids"]
        assert len(result["supporting_invocation_ids"]) == 2

    def test_empty_when_no_sources_present(self, case_dir):
        """Stubs return no invocation_ids -> empty list."""
        result = correlate_evidence("test.exe", case_dir=str(case_dir))
        assert result["supporting_invocation_ids"] == []

    def test_excludes_id_from_non_present_source(self, case_dir):
        """present=False with non-empty invocation_id must NOT appear."""
        fake_amcache = SourceResult(
            source="amcache", present=False, invocation_id="ghost_inv_001"
        )
        fake_prefetch = SourceResult(source="prefetch", present=False)
        fake_memory = SourceResult(source="memory", present=False)
        fake_mft = SourceResult(source="mft", present=False)

        with (
            patch("mcp_server.tools.correlation._call_parse_amcache", return_value=fake_amcache),
            patch("mcp_server.tools.correlation._call_parse_prefetch", return_value=fake_prefetch),
            patch("mcp_server.tools.correlation._call_parse_memory", return_value=fake_memory),
            patch("mcp_server.tools.correlation._call_parse_mft", return_value=fake_mft),
        ):
            result = correlate_evidence("test.exe", case_dir=str(case_dir))

        assert "ghost_inv_001" not in result["supporting_invocation_ids"]
        assert result["supporting_invocation_ids"] == []


# --------------------------------------------------------------------------- #
# TestAuditLog
# --------------------------------------------------------------------------- #

class TestAuditLog:
    """Audit entry written to audit/mcp.jsonl on every invocation."""

    def test_audit_entry_written(self, case_dir):
        correlate_evidence("test.exe", case_dir=str(case_dir))
        audit_file = case_dir / "audit" / "mcp.jsonl"
        assert audit_file.exists(), "audit/mcp.jsonl not created"

        lines = [
            line.strip()
            for line in audit_file.read_text().splitlines()
            if line.strip()
        ]
        assert len(lines) >= 1

        entry = json.loads(lines[-1])
        assert entry["tool"] == "correlate_evidence"
        assert "verdict" in entry  # verdict is in extra, merged into record

    def test_audit_has_examiner(self, case_dir):
        correlate_evidence("test.exe", case_dir=str(case_dir))
        audit_file = case_dir / "audit" / "mcp.jsonl"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert entry["examiner"] == "test-examiner"

    def test_audit_has_invocation_id(self, case_dir):
        correlate_evidence("test.exe", case_dir=str(case_dir))
        audit_file = case_dir / "audit" / "mcp.jsonl"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert entry["invocation_id"].startswith("correlation_")

    def test_audit_has_duration(self, case_dir):
        correlate_evidence("test.exe", case_dir=str(case_dir))
        audit_file = case_dir / "audit" / "mcp.jsonl"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert "duration_ms" in entry
        assert isinstance(entry["duration_ms"], (int, float))


# --------------------------------------------------------------------------- #
# TestSourceResultDataclass
# --------------------------------------------------------------------------- #

class TestSourceResultDataclass:
    """SourceResult serialisation behaviour."""

    def test_to_dict_minimal(self):
        sr = SourceResult(source="amcache", present=False)
        d = sr.to_dict()
        assert d == {"present": False}

    def test_to_dict_with_details(self):
        sr = SourceResult(
            source="amcache",
            present=True,
            invocation_id="inv_001",
            details={"sha1": "abc123", "first_run": "2018-09-06"},
        )
        d = sr.to_dict()
        assert d["present"] is True
        assert d["invocation_id"] == "inv_001"
        assert d["sha1"] == "abc123"
        assert d["first_run"] == "2018-09-06"

    def test_to_dict_with_error(self):
        sr = SourceResult(source="memory", present=False, error="not_wired")
        d = sr.to_dict()
        assert d["error"] == "not_wired"

    def test_to_dict_omits_empty_invocation_id(self):
        sr = SourceResult(source="mft", present=True, invocation_id="")
        d = sr.to_dict()
        assert "invocation_id" not in d


# --------------------------------------------------------------------------- #
# TestAmcachePrefetchIntegration — real wired calls with mocked parsers
# --------------------------------------------------------------------------- #

class TestAmcachePrefetchIntegration:
    """Integration tests for _call_parse_amcache and _call_parse_prefetch.

    Parsers are mocked — these tests verify the wiring logic in correlation.py,
    not the parsers themselves (those have their own test suites).
    """

    # ── _call_parse_amcache ─────────────────────────────────────────────────

    def test_amcache_found(self, tmp_path):
        """parse_amcache returns entry matching process_name → present=True."""
        from mcp_server.tools.correlation import _call_parse_amcache

        # Create fake Amcache.hve so the existence check passes
        (tmp_path / "Amcache.hve").touch()

        fake_result = {
            "invocation_id": "amcache-inv-001",
            "error": None,
            "entries": [
                {
                    "name": "subject_srv.exe",
                    "full_path": "\\windows\\temp\\subject_srv.exe",
                    "sha1": "aabbcc1122",
                    "first_run_utc": "2018-09-06T10:00:00Z",
                },
                {
                    "name": "svchost.exe",
                    "full_path": "\\windows\\system32\\svchost.exe",
                    "sha1": "deadbeef",
                    "first_run_utc": "2018-01-01T00:00:00Z",
                },
            ],
        }

        with patch("mcp_server.tools.correlation.parse_amcache", return_value=fake_result):
            sr = _call_parse_amcache("subject_srv.exe", str(tmp_path))

        assert sr.present is True
        assert sr.invocation_id == "amcache-inv-001"
        assert sr.details["sha1"] == "aabbcc1122"
        assert sr.error is None

    def test_amcache_found_case_insensitive(self, tmp_path):
        """Match is case-insensitive: SUBJECT_SRV.EXE matches subject_srv.exe."""
        from mcp_server.tools.correlation import _call_parse_amcache

        (tmp_path / "Amcache.hve").touch()

        fake_result = {
            "invocation_id": "amcache-inv-002",
            "error": None,
            "entries": [
                {"name": "SUBJECT_SRV.EXE", "full_path": "", "sha1": "", "first_run_utc": ""},
            ],
        }

        with patch("mcp_server.tools.correlation.parse_amcache", return_value=fake_result):
            sr = _call_parse_amcache("subject_srv.exe", str(tmp_path))

        assert sr.present is True

    def test_amcache_not_found(self, tmp_path):
        """parse_amcache returns entries but none match → present=False, invocation_id set."""
        from mcp_server.tools.correlation import _call_parse_amcache

        (tmp_path / "Amcache.hve").touch()

        fake_result = {
            "invocation_id": "amcache-inv-003",
            "error": None,
            "entries": [
                {"name": "notepad.exe", "full_path": "", "sha1": "", "first_run_utc": ""},
            ],
        }

        with patch("mcp_server.tools.correlation.parse_amcache", return_value=fake_result):
            sr = _call_parse_amcache("definitely_not_real.exe", str(tmp_path))

        assert sr.present is False
        assert sr.invocation_id == "amcache-inv-003"
        assert sr.error is None

    def test_amcache_parser_error(self, tmp_path):
        """parse_amcache returns non-null error → present=False, error field set."""
        from mcp_server.tools.correlation import _call_parse_amcache

        (tmp_path / "Amcache.hve").touch()

        fake_result = {
            "invocation_id": "amcache-inv-004",
            "error": "AmcacheParser failed: dotnet not found",
            "entries": [],
        }

        with patch("mcp_server.tools.correlation.parse_amcache", return_value=fake_result):
            sr = _call_parse_amcache("subject_srv.exe", str(tmp_path))

        assert sr.present is False
        assert "dotnet" in sr.error

    def test_amcache_file_missing(self, tmp_path):
        """No Amcache.hve in case_dir → present=False, no error (just absent)."""
        from mcp_server.tools.correlation import _call_parse_amcache

        # Do NOT create Amcache.hve
        sr = _call_parse_amcache("subject_srv.exe", str(tmp_path))

        assert sr.present is False
        assert sr.error is None

    def test_amcache_parser_raises(self, tmp_path):
        """parse_amcache raises unexpectedly → present=False, error=str(exc)."""
        from mcp_server.tools.correlation import _call_parse_amcache

        (tmp_path / "Amcache.hve").touch()

        with patch(
            "mcp_server.tools.correlation.parse_amcache",
            side_effect=RuntimeError("unexpected crash"),
        ):
            sr = _call_parse_amcache("subject_srv.exe", str(tmp_path))

        assert sr.present is False
        assert "unexpected crash" in sr.error

    # ── _call_parse_prefetch ────────────────────────────────────────────────

    def test_prefetch_found(self, tmp_path):
        """parse_prefetch returns entry matching process_name → present=True."""
        from mcp_server.tools.correlation import _call_parse_prefetch

        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()

        fake_result = {
            "invocation_id": "prefetch-inv-001",
            "error": None,
            "entries": [
                {
                    "executable_name": "SUBJECT_SRV.EXE",
                    "last_run_utc": "2018-09-06T10:05:00Z",
                    "run_count": 3,
                    "source_file": "SUBJECT_SRV.EXE-ABCD1234.pf",
                },
                {
                    "executable_name": "SVCHOST.EXE",
                    "last_run_utc": "2018-09-06T08:00:00Z",
                    "run_count": 120,
                    "source_file": "SVCHOST.EXE-DEADBEEF.pf",
                },
            ],
        }

        with patch("mcp_server.tools.correlation.parse_prefetch", return_value=fake_result):
            sr = _call_parse_prefetch("subject_srv.exe", str(tmp_path))

        assert sr.present is True
        assert sr.invocation_id == "prefetch-inv-001"
        assert sr.details["run_count"] == 3
        assert sr.error is None

    def test_prefetch_not_found(self, tmp_path):
        """No matching entry → present=False, invocation_id set."""
        from mcp_server.tools.correlation import _call_parse_prefetch

        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()

        fake_result = {
            "invocation_id": "prefetch-inv-002",
            "error": None,
            "entries": [
                {"executable_name": "NOTEPAD.EXE", "last_run_utc": "", "run_count": 1, "source_file": ""},
            ],
        }

        with patch("mcp_server.tools.correlation.parse_prefetch", return_value=fake_result):
            sr = _call_parse_prefetch("definitely_not_real.exe", str(tmp_path))

        assert sr.present is False
        assert sr.invocation_id == "prefetch-inv-002"
        assert sr.error is None

    def test_prefetch_dir_missing(self, tmp_path):
        """No Prefetch/ directory → present=False, no error."""
        from mcp_server.tools.correlation import _call_parse_prefetch

        # Do NOT create Prefetch/
        sr = _call_parse_prefetch("subject_srv.exe", str(tmp_path))

        assert sr.present is False
        assert sr.error is None

    def test_prefetch_parser_raises(self, tmp_path):
        """parse_prefetch raises → present=False, error=str(exc)."""
        from mcp_server.tools.correlation import _call_parse_prefetch

        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()

        with patch(
            "mcp_server.tools.correlation.parse_prefetch",
            side_effect=RuntimeError("pyscca crash"),
        ):
            sr = _call_parse_prefetch("subject_srv.exe", str(tmp_path))

        assert sr.present is False
        assert "pyscca crash" in sr.error

    def test_verdict_confirmed_historical_when_both_present(self, tmp_path, monkeypatch):
        """amcache + prefetch both present, no memory → verdict = CONFIRMED_HISTORICAL."""
        monkeypatch.setattr("mcp_server.tools._shared.AUDIT_FILE", tmp_path / "mcp.jsonl")
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr("mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl")

        (tmp_path / "Amcache.hve").touch()
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()

        fake_amcache = {
            "invocation_id": "amcache-verdict-001",
            "error": None,
            "entries": [{"name": "subject_srv.exe", "full_path": "", "sha1": "", "first_run_utc": ""}],
        }
        fake_prefetch = {
            "invocation_id": "prefetch-verdict-001",
            "error": None,
            "entries": [{"executable_name": "subject_srv.exe", "last_run_utc": "", "run_count": 1, "source_file": ""}],
        }

        with (
            patch("mcp_server.tools.correlation.parse_amcache", return_value=fake_amcache),
            patch("mcp_server.tools.correlation.parse_prefetch", return_value=fake_prefetch),
        ):
            result = correlate_evidence("subject_srv.exe", case_dir=str(tmp_path))

        assert result["verdict"] == "CONFIRMED_HISTORICAL"
        assert result["amcache"]["present"] is True
        assert result["prefetch"]["present"] is True
        assert "amcache-verdict-001" in result["supporting_invocation_ids"]
        assert "prefetch-verdict-001" in result["supporting_invocation_ids"]
