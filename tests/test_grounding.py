"""
tests/test_grounding.py
=======================
Tests for mcp_server/tools/grounding.py — Block 10 Phase 1.

Baseline: 296 tests (session end May 13, 2026). Count must increase.

Schema verified against live repo 2026-05-13:
  - finding dicts use "confidence" (not "label"), "finding_id" (not "label")
  - evidence_quotes schema: {"tool": str, "claim": str,
      "invocation_id"?: str, "audit_field"?: str, "audit_expected"?: str}
  - audit log entries: {invocation_id, tool, ts, returncode,
      parsed_record_count, ...extra fields merged at top level}

Run on live machine:
  pytest tests/test_grounding.py -v
  pytest tests/ -q 2>&1 | tail -3   # must be > 296
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.tools.grounding import (
    BASELINE_ASSUMPTION_PATTERNS,
    ClaimVerification,
    GroundingError,
    VerificationResult,
    _build_tool_index,
    _check_audit_field,
    _load_audit_log,
    assert_sources_attested,
    build_claim_accuracy_report,
    detect_baseline_assumptions,
    get_attested_sources,
    validate_evidence_quotes,
    verify_finding_claims,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_audit_log(tmp_path: Path, entries: list[dict]) -> str:
    """Write a JSONL audit log file and return its path string."""
    log_file = tmp_path / "mcp.jsonl"
    lines = [json.dumps(e) for e in entries]
    log_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return str(log_file)


def _audit_entry(
    invocation_id: str = "inv_001",
    tool: str = "parse_amcache",
    parsed_record_count: int = 1,
    **extra,
) -> dict:
    """Build a minimal valid audit log entry."""
    base = {
        "ts": "2026-05-13T10:00:00+00:00",
        "invocation_id": invocation_id,
        "tool": tool,
        "examiner": "testuser",
        "cmd": f"{tool}()",
        "returncode": 0,
        "stdout_lines": 0,
        "stderr_excerpt": "",
        "parsed_record_count": parsed_record_count,
        "duration_ms": 5,
    }
    base.update(extra)
    return base


def _confirmed_finding(
    finding_id: str = "F-testuser-001",
    evidence_quotes: list[dict] | None = None,
    narrative: str = "",
) -> dict:
    """Build a minimal CONFIRMED finding dict matching record_finding() schema."""
    return {
        "finding_id": finding_id,
        "status": "DRAFT",
        "confidence": "CONFIRMED",
        "title": "Test finding",
        "observation": "Observed something",
        "interpretation": narrative or "Interpreted something",
        "artifact_source": "/cases/test/amcache.hve",
        "supporting_tool": "parse_amcache",
        "evidence_quotes": evidence_quotes if evidence_quotes is not None else [],
    }


def _inferred_finding(
    finding_id: str = "F-testuser-002",
    evidence_quotes: list[dict] | None = None,
) -> dict:
    """Build a minimal INFERRED finding dict."""
    return {
        "finding_id": finding_id,
        "status": "DRAFT",
        "confidence": "INFERRED",
        "title": "Inferred finding",
        "observation": "X",
        "interpretation": "Y",
        "artifact_source": "/cases/test/prefetch",
        "supporting_tool": "parse_prefetch",
        "evidence_quotes": evidence_quotes if evidence_quotes is not None else [],
    }


def _quote(
    tool: str = "parse_amcache",
    claim: str = "amcache found suspicious entries",
    invocation_id: str | None = None,
    audit_field: str | None = None,
    audit_expected: str | None = None,
) -> dict:
    """Build an evidence_quote dict."""
    q: dict = {"tool": tool, "claim": claim}
    if invocation_id is not None:
        q["invocation_id"] = invocation_id
    if audit_field is not None:
        q["audit_field"] = audit_field
    if audit_expected is not None:
        q["audit_expected"] = audit_expected
    return q


# ---------------------------------------------------------------------------
# _load_audit_log
# ---------------------------------------------------------------------------

class TestLoadAuditLog:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(GroundingError, match="not found"):
            _load_audit_log(str(tmp_path / "nonexistent.jsonl"))

    def test_valid_single_entry(self, tmp_path):
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001")])
        index = _load_audit_log(log_path)
        assert "inv_001" in index
        assert index["inv_001"]["tool"] == "parse_amcache"

    def test_valid_multiple_entries(self, tmp_path):
        entries = [
            _audit_entry("inv_001", "parse_amcache"),
            _audit_entry("inv_002", "parse_prefetch"),
            _audit_entry("inv_003", "parse_memory"),
        ]
        log_path = _write_audit_log(tmp_path, entries)
        index = _load_audit_log(log_path)
        assert set(index.keys()) == {"inv_001", "inv_002", "inv_003"}

    def test_empty_lines_skipped(self, tmp_path):
        log_file = tmp_path / "mcp.jsonl"
        log_file.write_text(
            "\n" + json.dumps(_audit_entry("inv_001")) + "\n\n",
            encoding="utf-8",
        )
        index = _load_audit_log(str(log_file))
        assert "inv_001" in index

    def test_malformed_json_raises(self, tmp_path):
        log_file = tmp_path / "mcp.jsonl"
        log_file.write_text(
            json.dumps(_audit_entry("inv_001")) + "\n{bad json}\n",
            encoding="utf-8",
        )
        with pytest.raises(GroundingError, match="Malformed JSON"):
            _load_audit_log(str(log_file))

    def test_missing_invocation_id_raises(self, tmp_path):
        log_file = tmp_path / "mcp.jsonl"
        log_file.write_text(
            json.dumps({"tool": "parse_amcache", "returncode": 0}) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(GroundingError, match="missing 'invocation_id'"):
            _load_audit_log(str(log_file))

    def test_empty_file_returns_empty_index(self, tmp_path):
        log_file = tmp_path / "mcp.jsonl"
        log_file.write_text("", encoding="utf-8")
        index = _load_audit_log(str(log_file))
        assert index == {}

    def test_extra_fields_preserved(self, tmp_path):
        entry = _audit_entry("inv_001", suspicious_count=3, capped=False)
        log_path = _write_audit_log(tmp_path, [entry])
        index = _load_audit_log(log_path)
        assert index["inv_001"]["suspicious_count"] == 3
        assert index["inv_001"]["capped"] is False


# ---------------------------------------------------------------------------
# _build_tool_index
# ---------------------------------------------------------------------------

class TestBuildToolIndex:
    def test_groups_by_tool(self, tmp_path):
        entries = [
            _audit_entry("inv_001", "parse_amcache"),
            _audit_entry("inv_002", "parse_amcache"),
            _audit_entry("inv_003", "parse_prefetch"),
        ]
        log_path = _write_audit_log(tmp_path, entries)
        index = _load_audit_log(log_path)
        by_tool = _build_tool_index(index)
        assert len(by_tool["parse_amcache"]) == 2
        assert len(by_tool["parse_prefetch"]) == 1

    def test_empty_index_returns_empty(self):
        by_tool = _build_tool_index({})
        assert by_tool == {}


# ---------------------------------------------------------------------------
# _check_audit_field
# ---------------------------------------------------------------------------

class TestCheckAuditField:
    def test_gt_zero_satisfied(self):
        entry = _audit_entry("inv_001", suspicious_count=3)
        ok, note = _check_audit_field(entry, "suspicious_count", "> 0")
        assert ok is True
        assert "satisfies" in note

    def test_gt_zero_not_satisfied(self):
        entry = _audit_entry("inv_001", suspicious_count=0)
        ok, note = _check_audit_field(entry, "suspicious_count", "> 0")
        assert ok is False
        assert "does NOT satisfy" in note

    def test_gte_satisfied(self):
        entry = _audit_entry("inv_001", parsed_record_count=1)
        ok, _ = _check_audit_field(entry, "parsed_record_count", ">= 1")
        assert ok is True

    def test_equality_string(self):
        entry = _audit_entry("inv_001", verdict="CONFIRMED_RUNNING")
        ok, _ = _check_audit_field(entry, "verdict", "== CONFIRMED_RUNNING")
        assert ok is True

    def test_equality_mismatch(self):
        entry = _audit_entry("inv_001", verdict="NOT_FOUND")
        ok, _ = _check_audit_field(entry, "verdict", "== CONFIRMED_RUNNING")
        assert ok is False

    def test_boolean_true(self):
        entry = _audit_entry("inv_001", capped=True)
        ok, _ = _check_audit_field(entry, "capped", "true")
        assert ok is True

    def test_boolean_false_on_truthy_value(self):
        entry = _audit_entry("inv_001", capped=True)
        ok, _ = _check_audit_field(entry, "capped", "false")
        assert ok is False

    def test_substring_match(self):
        entry = _audit_entry("inv_001", verdict="CONFIRMED_RUNNING")
        ok, _ = _check_audit_field(entry, "verdict", "CONFIRMED")
        assert ok is True

    def test_missing_field_returns_false(self):
        entry = _audit_entry("inv_001")
        ok, note = _check_audit_field(entry, "nonexistent_field", "> 0")
        assert ok is False
        assert "not found" in note

    def test_nested_dot_path(self):
        entry = _audit_entry(
            "inv_001",
            **{"params": {"process_name": "subject_srv.exe"}},
        )
        ok, _ = _check_audit_field(entry, "params.process_name", "subject_srv.exe")
        assert ok is True

    def test_nested_path_missing_key(self):
        entry = _audit_entry("inv_001", **{"params": {"other": "x"}})
        ok, note = _check_audit_field(entry, "params.process_name", "subject_srv.exe")
        assert ok is False

    def test_numeric_comparison_on_non_numeric_returns_false(self):
        entry = _audit_entry("inv_001", verdict="CONFIRMED_RUNNING")
        ok, note = _check_audit_field(entry, "verdict", "> 0")
        assert ok is False


# ---------------------------------------------------------------------------
# validate_evidence_quotes
# ---------------------------------------------------------------------------

class TestValidateEvidenceQuotes:
    def test_confirmed_with_valid_quote_passes(self):
        finding = _confirmed_finding(evidence_quotes=[_quote()])
        validate_evidence_quotes(finding)  # no raise

    def test_confirmed_empty_quotes_raises(self):
        finding = _confirmed_finding(evidence_quotes=[])
        with pytest.raises(GroundingError, match="evidence_quotes is empty"):
            validate_evidence_quotes(finding)

    def test_inferred_empty_quotes_passes(self):
        finding = _inferred_finding(evidence_quotes=[])
        validate_evidence_quotes(finding)  # no raise

    def test_missing_tool_key_raises(self):
        bad_quote = {"claim": "something happened"}
        finding = _confirmed_finding(evidence_quotes=[bad_quote])
        with pytest.raises(GroundingError, match="missing required fields"):
            validate_evidence_quotes(finding)

    def test_missing_claim_key_raises(self):
        bad_quote = {"tool": "parse_amcache"}
        finding = _confirmed_finding(evidence_quotes=[bad_quote])
        with pytest.raises(GroundingError, match="missing required fields"):
            validate_evidence_quotes(finding)

    def test_empty_tool_string_raises(self):
        finding = _confirmed_finding(evidence_quotes=[_quote(tool="")])
        with pytest.raises(GroundingError, match="non-empty string"):
            validate_evidence_quotes(finding)

    def test_empty_claim_string_raises(self):
        finding = _confirmed_finding(evidence_quotes=[_quote(claim="")])
        with pytest.raises(GroundingError, match="non-empty string"):
            validate_evidence_quotes(finding)

    def test_empty_invocation_id_raises(self):
        finding = _confirmed_finding(evidence_quotes=[_quote(invocation_id="")])
        with pytest.raises(GroundingError, match="non-empty string"):
            validate_evidence_quotes(finding)

    def test_valid_invocation_id_passes(self):
        finding = _confirmed_finding(
            evidence_quotes=[_quote(invocation_id="inv_abc123")]
        )
        validate_evidence_quotes(finding)  # no raise

    def test_multiple_valid_quotes_pass(self):
        finding = _confirmed_finding(evidence_quotes=[_quote(), _quote(tool="parse_prefetch")])
        validate_evidence_quotes(finding)  # no raise

    def test_uses_id_key_if_finding_id_absent(self):
        """Finding stored on disk uses 'id' key — validate_evidence_quotes accepts it."""
        finding = {
            "id": "F-testuser-001",
            "confidence": "CONFIRMED",
            "evidence_quotes": [],
        }
        with pytest.raises(GroundingError, match="F-testuser-001"):
            validate_evidence_quotes(finding)


# ---------------------------------------------------------------------------
# verify_finding_claims
# ---------------------------------------------------------------------------

class TestVerifyFindingClaims:
    def test_tool_attested_grounded(self, tmp_path):
        """Tool appears in audit log → GROUNDED, passed=True."""
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001", "parse_amcache")])
        finding = _confirmed_finding(
            evidence_quotes=[_quote(tool="parse_amcache", invocation_id="inv_001")]
        )
        result = verify_finding_claims(finding, log_path)
        assert result.passed is True
        assert result.grounded == 1
        assert result.claims[0].status == "GROUNDED"

    def test_tool_by_name_only_grounded(self, tmp_path):
        """No invocation_id — tool-name attestation sufficient."""
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001", "parse_amcache")])
        finding = _confirmed_finding(
            evidence_quotes=[_quote(tool="parse_amcache")]  # no invocation_id
        )
        result = verify_finding_claims(finding, log_path)
        assert result.grounded == 1
        assert result.passed is True

    def test_invocation_id_not_found_ungrounded(self, tmp_path):
        """invocation_id missing from audit log → UNGROUNDED."""
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_OTHER")])
        finding = _confirmed_finding(
            evidence_quotes=[_quote(invocation_id="inv_MISSING")]
        )
        result = verify_finding_claims(finding, log_path)
        assert result.ungrounded == 1
        assert result.passed is True  # UNGROUNDED does not fail

    def test_tool_not_in_log_ungrounded(self, tmp_path):
        """Tool name not present in audit log → UNGROUNDED."""
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001", "parse_amcache")])
        finding = _confirmed_finding(
            evidence_quotes=[_quote(tool="parse_shimcache")]  # never called
        )
        result = verify_finding_claims(finding, log_path)
        assert result.ungrounded == 1

    def test_audit_field_check_grounded(self, tmp_path):
        """audit_field check passes → GROUNDED."""
        entry = _audit_entry("inv_001", "parse_amcache", suspicious_count=3)
        log_path = _write_audit_log(tmp_path, [entry])
        finding = _confirmed_finding(evidence_quotes=[
            _quote(
                tool="parse_amcache",
                invocation_id="inv_001",
                audit_field="suspicious_count",
                audit_expected="> 0",
            )
        ])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is True
        assert result.grounded == 1
        assert "field check passed" in result.claims[0].note

    def test_audit_field_check_contradicted(self, tmp_path):
        """audit_field check fails → CONTRADICTED, passed=False."""
        entry = _audit_entry("inv_001", "parse_amcache", suspicious_count=0)
        log_path = _write_audit_log(tmp_path, [entry])
        finding = _confirmed_finding(evidence_quotes=[
            _quote(
                tool="parse_amcache",
                invocation_id="inv_001",
                audit_field="suspicious_count",
                audit_expected="> 0",
            )
        ])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is False
        assert result.contradicted == 1
        assert "HALLUCINATION DETECTED" in result.claims[0].note

    def test_wrong_tool_for_invocation_id_contradicted(self, tmp_path):
        """invocation_id exists but tool name mismatches → CONTRADICTED."""
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001", "parse_amcache")])
        finding = _confirmed_finding(evidence_quotes=[
            _quote(tool="parse_prefetch", invocation_id="inv_001")
        ])
        result = verify_finding_claims(finding, log_path)
        assert result.contradicted == 1
        assert result.passed is False

    def test_inferred_no_quotes_inferred_labeled(self, tmp_path):
        """INFERRED finding with no quotes → INFERRED_LABELED, passed=True."""
        log_path = _write_audit_log(tmp_path, [])
        finding = _inferred_finding(evidence_quotes=[])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is True
        assert result.inferred_labeled == 1
        assert result.claims[0].status == "INFERRED_LABELED"

    def test_confirmed_no_quotes_ungrounded_fails(self, tmp_path):
        """CONFIRMED with no quotes → UNGROUNDED, passed=False."""
        log_path = _write_audit_log(tmp_path, [])
        finding = _confirmed_finding(evidence_quotes=[])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is False
        assert result.ungrounded == 1

    def test_multiple_quotes_all_grounded(self, tmp_path):
        """Multiple quotes, all attested → all GROUNDED."""
        entries = [
            _audit_entry("inv_001", "parse_amcache"),
            _audit_entry("inv_002", "parse_prefetch"),
        ]
        log_path = _write_audit_log(tmp_path, entries)
        finding = _confirmed_finding(evidence_quotes=[
            _quote(tool="parse_amcache", invocation_id="inv_001"),
            _quote(tool="parse_prefetch", invocation_id="inv_002",
                   claim="prefetch confirms execution"),
        ])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is True
        assert result.grounded == 2
        assert result.total_claims == 2

    def test_mixed_grounded_and_contradicted(self, tmp_path):
        """One GROUNDED, one CONTRADICTED → passed=False."""
        entries = [
            _audit_entry("inv_001", "parse_amcache", suspicious_count=3),
            _audit_entry("inv_002", "parse_prefetch", suspicious_count=0),
        ]
        log_path = _write_audit_log(tmp_path, entries)
        finding = _confirmed_finding(evidence_quotes=[
            _quote(tool="parse_amcache", invocation_id="inv_001",
                   audit_field="suspicious_count", audit_expected="> 0"),
            _quote(tool="parse_prefetch", invocation_id="inv_002",
                   claim="prefetch suspicious", audit_field="suspicious_count",
                   audit_expected="> 0"),
        ])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is False
        assert result.grounded == 1
        assert result.contradicted == 1

    def test_correlate_evidence_verdict_grounded(self, tmp_path):
        """Verify correlate_evidence verdict field from real audit schema."""
        entry = _audit_entry(
            "inv_corr_001",
            "correlate_evidence",
            parsed_record_count=2,
            **{
                "params": {"process_name": "subject_srv.exe", "case_dir": "/cases/test"},
                "sources_present": ["amcache", "prefetch"],
                "verdict": "CONFIRMED_RUNNING",
            },
        )
        log_path = _write_audit_log(tmp_path, [entry])
        finding = _confirmed_finding(evidence_quotes=[
            _quote(
                tool="correlate_evidence",
                invocation_id="inv_corr_001",
                claim="verdict is CONFIRMED_RUNNING",
                audit_field="verdict",
                audit_expected="== CONFIRMED_RUNNING",
            )
        ])
        result = verify_finding_claims(finding, log_path)
        assert result.passed is True
        assert result.grounded == 1

    def test_missing_audit_log_raises(self, tmp_path):
        finding = _confirmed_finding(evidence_quotes=[_quote()])
        with pytest.raises(GroundingError, match="not found"):
            verify_finding_claims(finding, str(tmp_path / "missing.jsonl"))

    def test_hallucination_rate_zero_all_grounded(self, tmp_path):
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001")])
        finding = _confirmed_finding(
            evidence_quotes=[_quote(invocation_id="inv_001")]
        )
        result = verify_finding_claims(finding, log_path)
        assert result.hallucination_rate == 0.0
        assert result.grounding_rate == 1.0

    def test_uses_id_key_for_finding_id(self, tmp_path):
        """Stored record uses 'id' — verifier still works."""
        log_path = _write_audit_log(tmp_path, [_audit_entry("inv_001")])
        finding = {
            "id": "F-testuser-001",
            "confidence": "CONFIRMED",
            "evidence_quotes": [_quote(invocation_id="inv_001")],
        }
        result = verify_finding_claims(finding, log_path)
        assert result.finding_id == "F-testuser-001"
        assert result.passed is True


# ---------------------------------------------------------------------------
# get_attested_sources
# ---------------------------------------------------------------------------

class TestGetAttestedSources:
    def test_returns_tool_name_set(self, tmp_path):
        entries = [
            _audit_entry("inv_001", "parse_amcache"),
            _audit_entry("inv_002", "parse_prefetch"),
            _audit_entry("inv_003", "parse_amcache"),  # duplicate
        ]
        log_path = _write_audit_log(tmp_path, entries)
        sources = get_attested_sources(log_path)
        assert sources == {"parse_amcache", "parse_prefetch"}

    def test_empty_log_returns_empty_set(self, tmp_path):
        log_path = _write_audit_log(tmp_path, [])
        assert get_attested_sources(log_path) == set()

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(GroundingError, match="not found"):
            get_attested_sources(str(tmp_path / "no.jsonl"))


# ---------------------------------------------------------------------------
# assert_sources_attested
# ---------------------------------------------------------------------------

class TestAssertSourcesAttested:
    def test_all_attested_no_warnings(self):
        finding = _confirmed_finding(evidence_quotes=[
            _quote(tool="parse_amcache"),
            _quote(tool="parse_prefetch", claim="prefetch check"),
        ])
        warnings = assert_sources_attested(finding, {"parse_amcache", "parse_prefetch"})
        assert warnings == []

    def test_unattested_tool_produces_warning(self):
        finding = _confirmed_finding(evidence_quotes=[
            _quote(tool="parse_shimcache", claim="shimcache check")
        ])
        warnings = assert_sources_attested(finding, {"parse_amcache"})
        assert len(warnings) == 1
        assert "parse_shimcache" in warnings[0]

    def test_no_quotes_no_warnings(self):
        finding = _inferred_finding(evidence_quotes=[])
        assert assert_sources_attested(finding, {"parse_amcache"}) == []

    def test_multiple_unattested(self):
        finding = _confirmed_finding(evidence_quotes=[
            _quote(tool="parse_shimcache", claim="a"),
            _quote(tool="parse_network", claim="b"),
        ])
        warnings = assert_sources_attested(finding, set())
        assert len(warnings) == 2


# ---------------------------------------------------------------------------
# detect_baseline_assumptions
# ---------------------------------------------------------------------------

class TestDetectBaselineAssumptions:
    def test_clean_narrative_no_warnings(self):
        narrative = "subject_srv.exe was found in C:\\Windows\\Temp by amcache."
        assert detect_baseline_assumptions(narrative) == []

    def test_normally_runs_from_detected(self):
        narrative = "This binary normally runs from C:\\Windows\\System32."
        warnings = detect_baseline_assumptions(narrative)
        assert any("normally runs from" in w for w in warnings)

    def test_case_insensitive(self):
        narrative = "The process NORMALLY RUNS FROM System32."
        assert len(detect_baseline_assumptions(narrative)) >= 1

    def test_typically_spawned_by_detected(self):
        narrative = "svchost.exe is typically spawned by services.exe."
        assert len(detect_baseline_assumptions(narrative)) >= 1

    def test_in_a_normal_environment_detected(self):
        narrative = "In a normal environment this path would be System32."
        assert len(detect_baseline_assumptions(narrative)) >= 1

    def test_by_default_detected(self):
        narrative = "By default, Windows stores these files in System32."
        assert len(detect_baseline_assumptions(narrative)) >= 1

    def test_multiple_patterns_multiple_warnings(self):
        narrative = (
            "The process normally runs from System32. "
            "In a normal environment this is not suspicious."
        )
        assert len(detect_baseline_assumptions(narrative)) >= 2

    def test_empty_narrative(self):
        assert detect_baseline_assumptions("") == []


# ---------------------------------------------------------------------------
# VerificationResult helpers
# ---------------------------------------------------------------------------

class TestVerificationResultHelpers:
    def _make_result(self, grounded=1, ungrounded=0, contradicted=0,
                     inferred_labeled=0, passed=True):
        total = grounded + ungrounded + contradicted + inferred_labeled
        return VerificationResult(
            finding_id="F-001",
            total_claims=total,
            grounded=grounded,
            ungrounded=ungrounded,
            contradicted=contradicted,
            inferred_labeled=inferred_labeled,
            passed=passed,
        )

    def test_hallucination_rate_zero(self):
        r = self._make_result(grounded=5)
        assert r.hallucination_rate == 0.0

    def test_hallucination_rate_nonzero(self):
        r = self._make_result(grounded=3, contradicted=1, passed=False)
        assert r.hallucination_rate == 0.25

    def test_grounding_rate_full(self):
        r = self._make_result(grounded=4)
        assert r.grounding_rate == 1.0

    def test_grounding_rate_partial(self):
        r = self._make_result(grounded=3, ungrounded=1)
        assert r.grounding_rate == 0.75

    def test_zero_claims_rates(self):
        r = VerificationResult(
            finding_id="F-000", total_claims=0,
            grounded=0, ungrounded=0, contradicted=0, inferred_labeled=0,
        )
        assert r.hallucination_rate == 0.0
        assert r.grounding_rate == 1.0

    def test_to_dict_structure(self):
        claim = ClaimVerification(
            claim_text="tool='parse_amcache'",
            status="GROUNDED",
            supporting_invocation_id="inv_001",
            note="Verified.",
        )
        r = VerificationResult(
            finding_id="F-001", total_claims=1, grounded=1,
            ungrounded=0, contradicted=0, inferred_labeled=0,
            claims=[claim], passed=True,
        )
        d = r.to_dict()
        assert d["finding_id"] == "F-001"
        assert d["passed"] is True
        assert d["hallucination_rate"] == 0.0
        assert d["grounding_rate"] == 1.0
        assert len(d["claims"]) == 1
        assert d["claims"][0]["status"] == "GROUNDED"


# ---------------------------------------------------------------------------
# build_claim_accuracy_report
# ---------------------------------------------------------------------------

class TestBuildClaimAccuracyReport:
    def _result(self, finding_id="F-001", grounded=1, ungrounded=0,
                contradicted=0, inferred_labeled=0, passed=True):
        total = grounded + ungrounded + contradicted + inferred_labeled
        return VerificationResult(
            finding_id=finding_id, total_claims=total,
            grounded=grounded, ungrounded=ungrounded,
            contradicted=contradicted, inferred_labeled=inferred_labeled,
            passed=passed,
        )

    def test_all_grounded(self):
        results = [self._result("F-001", grounded=3), self._result("F-002", grounded=2)]
        report = build_claim_accuracy_report(results)
        assert report["total_claims"] == 5
        assert report["grounded"] == 5
        assert report["hallucination_rate"] == 0.0
        assert report["grounding_rate"] == 1.0
        assert report["all_passed"] is True

    def test_one_contradicted(self):
        results = [
            self._result("F-001", grounded=3),
            self._result("F-002", grounded=1, contradicted=1, passed=False),
        ]
        report = build_claim_accuracy_report(results)
        assert report["contradicted"] == 1
        assert report["all_passed"] is False
        assert report["hallucination_rate"] == round(1 / 5, 4)

    def test_empty_results(self):
        report = build_claim_accuracy_report([])
        assert report["total_claims"] == 0
        assert report["grounding_rate"] == 1.0
        assert report["hallucination_rate"] == 0.0
        assert report["all_passed"] is True
        assert report["findings"] == []

    def test_findings_list_populated(self):
        results = [self._result("F-001"), self._result("F-002")]
        report = build_claim_accuracy_report(results)
        assert len(report["findings"]) == 2
        ids = {f["finding_id"] for f in report["findings"]}
        assert ids == {"F-001", "F-002"}


def test_check_audit_field_no_space_operator():
    """CR-4 regression: '>0' without space must parse as numeric, not substring match."""
    from mcp_server.tools.grounding import _check_audit_field
    entry = {"suspicious_count": 3}
    ok, msg = _check_audit_field(entry, "suspicious_count", ">0")
    assert ok is True, f"Expected True for 3 > 0, got: {msg}"
    ok2, msg2 = _check_audit_field(entry, "suspicious_count", ">=10")
    assert ok2 is False, f"Expected False for 3 >= 10, got: {msg2}"


def test_check_audit_field_stringified_boolean():
    """CR-5 regression: string 'false' must not be truthy when expected='true'."""
    from mcp_server.tools.grounding import _check_audit_field
    entry = {"capped": "false"}
    ok, _ = _check_audit_field(entry, "capped", "true")
    assert ok is False
    ok2, _ = _check_audit_field(entry, "capped", "false")
    assert ok2 is True


import pytest  # noqa: E402


@pytest.mark.parametrize("bad_quotes", ["not a list", "", 0, {}])
def test_record_finding_non_list_evidence_quotes_raises(tmp_path, monkeypatch, bad_quotes):
    """CR-7 regression: non-list evidence_quotes must raise GroundingSchemaError."""
    import mcp_server.tools.findings as _findings_mod
    import mcp_server.tools._shared as _shared_mod
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (tmp_path / "audit").mkdir()
    monkeypatch.setattr(_findings_mod, "_case_dir", lambda: case_dir)
    monkeypatch.setattr(_shared_mod, "AUDIT_FILE", tmp_path / "audit" / "mcp.jsonl")
    from mcp_server.tools.findings import record_finding
    from mcp_server.tools.grounding import GroundingSchemaError
    with pytest.raises(GroundingSchemaError, match="must be a list"):
        record_finding(
            title="T", observation="O", interpretation="I",
            confidence="CONFIRMED", artifact_source="/a", supporting_tool="parse_amcache",
            evidence_quotes=bad_quotes,
        )
