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
