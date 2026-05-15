"""
tests/test_grounding_scripts.py
=================================
Tests for the three grounding post-processing scripts:
  - scripts/grounding_verify.py
  - scripts/grounding_recheck.py
  - scripts/grounding_correction_prompt.py

All tests use subprocess to invoke the scripts so module-level side effects
(sys.exit, env-var reads, top-level imports) are exercised exactly as ralph.sh
calls them.  No monkeypatching of sys.exit or importlib.reload gymnastics needed.

Fixtures build minimal but valid filesystem layouts in tmp_path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PYTHON = sys.executable

# Repo root: tests/ -> casefile/
REPO_ROOT = Path(__file__).resolve().parent.parent


def _script_path(relative: str) -> str:
    """Absolute path to a script in the repo.

    Tests run with cwd=tmp_path so relative paths like
    'scripts/grounding_verify.py' would resolve to tmp_path, not the repo.
    Always use the absolute path for the script argument.
    """
    return str(REPO_ROOT / relative)


def _run_script(script: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    """Run a grounding script as a subprocess and return the completed process.

    cwd is set to tmp_path which contains the mock mcp_server package.
    PYTHONPATH is prepended with cwd so the mock is on sys.path — Python 3.10
    does not add cwd to sys.path automatically for scripts run by absolute path.
    """
    env_with_path = dict(env)
    existing = env_with_path.get("PYTHONPATH", "")
    env_with_path["PYTHONPATH"] = str(cwd) + (":" + existing if existing else "")
    return subprocess.run(
        [PYTHON, _script_path(script)],
        capture_output=True,
        text=True,
        env=env_with_path,
        cwd=str(cwd),
    )


def _run_script_import_error(script: str, env: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    """Run script in an isolated env where mcp_server is NOT importable.

    Strips PYTHONPATH and site-packages so the real mcp_server package
    cannot be found — exercises the ImportError branch in each script.
    """
    empty_dir = tmp_path / "_empty_pypath"
    empty_dir.mkdir(exist_ok=True)
    isolated_env = {
        "CASE_DIR":      env["CASE_DIR"],
        "AUDIT_LOG":     env["AUDIT_LOG"],
        "FINDINGS_FILE": env["FINDINGS_FILE"],
        "CLAIM_REPORT":  env["CLAIM_REPORT"],
        "PATH":          os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME":          str(tmp_path),
        "PYTHONPATH":    str(empty_dir),  # empty → mcp_server not found → ImportError
    }
    return subprocess.run(
        [PYTHON, "-S", _script_path(script)],  # -S disables site-packages → ensures ImportError
        capture_output=True,
        text=True,
        env=isolated_env,
        cwd=str(tmp_path),
    )


def _base_env(tmp_path: Path) -> dict:
    """Minimal env that points all four env-vars at tmp_path layout."""
    case_dir = tmp_path / "case"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "audit").mkdir(exist_ok=True)
    (case_dir / "analysis").mkdir(exist_ok=True)
    return {
        **os.environ,
        "CASE_DIR": str(case_dir),
        "AUDIT_LOG": str(case_dir / "audit" / "mcp.jsonl"),
        "FINDINGS_FILE": str(case_dir / "findings.json"),
        "CLAIM_REPORT": str(case_dir / "analysis" / "claim_accuracy_report.json"),
    }


def _write_findings(env: dict, findings: list) -> None:
    Path(env["FINDINGS_FILE"]).write_text(json.dumps(findings), encoding="utf-8")


def _write_report(env: dict, report: dict) -> None:
    Path(env["CLAIM_REPORT"]).write_text(json.dumps(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# Shared mock helpers: inject a fake grounding module so tests don't need
# the real mcp_server package tree.
# ---------------------------------------------------------------------------

_MOCK_GROUNDING_CLEAN = textwrap.dedent("""\
    # mock mcp_server/tools/grounding.py — all claims GROUNDED
    from dataclasses import dataclass, field
    from typing import List

    @dataclass
    class ClaimVerification:
        claim_text: str
        status: str
        supporting_invocation_id: str | None
        note: str

    @dataclass
    class VerificationResult:
        finding_id: str
        total_claims: int
        grounded: int
        ungrounded: int
        contradicted: int
        claims: List[ClaimVerification] = field(default_factory=list)
        passed: bool = True

    def verify_finding_claims(finding, audit_log_path):
        fid = finding.get("id") or finding.get("finding_id", "<unknown>")
        return VerificationResult(
            finding_id=fid,
            total_claims=1,
            grounded=1,
            ungrounded=0,
            contradicted=0,
            claims=[ClaimVerification(
                claim_text="test claim",
                status="GROUNDED",
                supporting_invocation_id="inv_001",
                note="verified",
            )],
            passed=True,
        )

    def get_attested_sources(audit_log_path):
        return {"parse_amcache", "parse_prefetch"}

    def assert_sources_attested(finding, attested):
        return []

    def build_claim_accuracy_report(results):
        total = len(results)
        contradicted = sum(r.contradicted for r in results)
        grounded = sum(r.grounded for r in results)
        rate = (contradicted / (grounded + contradicted)) if (grounded + contradicted) else 0.0
        return {
            "total_findings": total,
            "total_claims": sum(r.total_claims for r in results),
            "grounded": grounded,
            "contradicted": contradicted,
            "hallucination_rate": rate,
            "findings": [
                {
                    "finding_id": r.finding_id,
                    "claims": [
                        {
                            "claim_text": c.claim_text,
                            "status": c.status,
                            "note": c.note,
                        }
                        for c in r.claims
                    ],
                }
                for r in results
            ],
        }
""")

_MOCK_GROUNDING_CONTRADICTED = textwrap.dedent("""\
    # mock mcp_server/tools/grounding.py — returns one CONTRADICTED claim
    from dataclasses import dataclass, field
    from typing import List

    @dataclass
    class ClaimVerification:
        claim_text: str
        status: str
        supporting_invocation_id: str | None
        note: str

    @dataclass
    class VerificationResult:
        finding_id: str
        total_claims: int
        grounded: int
        ungrounded: int
        contradicted: int
        claims: List[ClaimVerification] = field(default_factory=list)
        passed: bool = False

    def verify_finding_claims(finding, audit_log_path):
        fid = finding.get("id") or finding.get("finding_id", "<unknown>")
        return VerificationResult(
            finding_id=fid,
            total_claims=1,
            grounded=0,
            ungrounded=0,
            contradicted=1,
            claims=[ClaimVerification(
                claim_text="process ran at 10:22",
                status="CONTRADICTED",
                supporting_invocation_id=None,
                note="audit log shows no such timestamp",
            )],
            passed=False,
        )

    def get_attested_sources(audit_log_path):
        return set()

    def assert_sources_attested(finding, attested):
        return []

    def build_claim_accuracy_report(results):
        total = len(results)
        contradicted = sum(r.contradicted for r in results)
        grounded = sum(r.grounded for r in results)
        rate = (contradicted / (grounded + contradicted)) if (grounded + contradicted) else 1.0
        return {
            "total_findings": total,
            "total_claims": sum(r.total_claims for r in results),
            "grounded": grounded,
            "contradicted": contradicted,
            "hallucination_rate": rate,
            "findings": [
                {
                    "finding_id": r.finding_id,
                    "claims": [
                        {
                            "claim_text": c.claim_text,
                            "status": c.status,
                            "note": c.note,
                        }
                        for c in r.claims
                    ],
                }
                for r in results
            ],
        }
""")

_MOCK_GROUNDING_RAISES = textwrap.dedent("""\
    # mock mcp_server/tools/grounding.py — verify_finding_claims raises
    from dataclasses import dataclass, field
    from typing import List

    @dataclass
    class ClaimVerification:
        claim_text: str
        status: str
        supporting_invocation_id: str | None
        note: str

    @dataclass
    class VerificationResult:
        finding_id: str
        total_claims: int
        grounded: int
        ungrounded: int
        contradicted: int
        claims: List[ClaimVerification] = field(default_factory=list)
        passed: bool = True

    def verify_finding_claims(finding, audit_log_path):
        raise RuntimeError("simulated verifier crash")

    def get_attested_sources(audit_log_path):
        return set()

    def assert_sources_attested(finding, attested):
        return []

    def build_claim_accuracy_report(results):
        return {
            "total_findings": 0,
            "total_claims": 0,
            "grounded": 0,
            "contradicted": 0,
            "hallucination_rate": 0.0,
            "findings": [],
        }
""")


def _install_mock_grounding(cwd: Path, mock_source: str) -> None:
    """
    Write fake mcp_server/tools/grounding.py under cwd so the script's
    top-level 'from mcp_server.tools.grounding import ...' resolves to our mock.

    Limitation: only grounding.py is stubbed. If a grounding script ever imports
    another mcp_server.tools module (e.g. _shared, findings), the subprocess will
    crash with ModuleNotFoundError. Extend this function with additional stubs
    when that happens — do not suppress the failure.
    """
    pkg = cwd / "mcp_server" / "tools"
    pkg.mkdir(parents=True, exist_ok=True)
    (cwd / "mcp_server" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "grounding.py").write_text(mock_source, encoding="utf-8")


# ---------------------------------------------------------------------------
# grounding_verify.py tests
# ---------------------------------------------------------------------------

VERIFY_SCRIPT = "scripts/grounding_verify.py"


class TestGroundingVerifyNoFindingsFile:
    def test_missing_findings_file_exits_0(self, tmp_path):
        """No findings.json → script exits 0 (nothing to verify)."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 0
        assert "skipping" in (result.stdout + result.stderr).lower() or "No findings" in (result.stdout + result.stderr)

    def test_empty_findings_list_exits_0(self, tmp_path):
        """findings.json exists but is [] → exits 0."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 0


class TestGroundingVerifyImportError:
    def test_import_error_exits_1(self, tmp_path):
        """If grounding module is not importable, script must exit 1 (fatal)."""
        env = _base_env(tmp_path)
        # Use isolated env — real mcp_server on venv sys.path must not be found
        _write_findings(env, [{"id": "F-001", "title": "test"}])
        result = _run_script_import_error(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 1
        assert "IMPORT ERROR" in (result.stdout + result.stderr) or "FATAL" in (result.stdout + result.stderr)


class TestGroundingVerifyAllGrounded:
    def test_all_grounded_exits_0(self, tmp_path):
        """All claims GROUNDED → exit 0, report written."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"id": "F-001", "title": "test finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 0
        assert "GROUNDED" in (result.stdout + result.stderr)
        assert Path(env["CLAIM_REPORT"]).exists()

    def test_report_written_with_correct_keys(self, tmp_path):
        """Claim accuracy report contains required top-level keys."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"id": "F-001", "title": "test"}])
        _run_script(VERIFY_SCRIPT, env, tmp_path)
        report = json.loads(Path(env["CLAIM_REPORT"]).read_text())
        for key in ("total_findings", "total_claims", "grounded", "contradicted", "hallucination_rate"):
            assert key in report, f"missing key: {key}"

    def test_report_total_findings_matches_input(self, tmp_path):
        """Report total_findings == number of findings passed in."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        findings = [{"id": f"F-{i:03d}", "title": f"finding {i}"} for i in range(3)]
        _write_findings(env, findings)
        _run_script(VERIFY_SCRIPT, env, tmp_path)
        report = json.loads(Path(env["CLAIM_REPORT"]).read_text())
        assert report["total_findings"] == 3


class TestGroundingVerifyContradicted:
    def test_contradicted_exits_2(self, tmp_path):
        """CONTRADICTED claim → exit 2 (triggers correction loop)."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CONTRADICTED)
        _write_findings(env, [{"id": "F-001", "title": "bad finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 2

    def test_contradicted_logged_to_stdout(self, tmp_path):
        """CONTRADICTED claim text appears in stdout output."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CONTRADICTED)
        _write_findings(env, [{"id": "F-001", "title": "bad finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert "CONTRADICTED" in (result.stdout + result.stderr)

    def test_contradicted_report_written(self, tmp_path):
        """Report is still written even when CONTRADICTED."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CONTRADICTED)
        _write_findings(env, [{"id": "F-001", "title": "bad finding"}])
        _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert Path(env["CLAIM_REPORT"]).exists()

    def test_multiple_findings_one_contradicted_exits_2(self, tmp_path):
        """Even one CONTRADICTED among many findings triggers exit 2."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CONTRADICTED)
        findings = [{"id": f"F-{i:03d}", "title": f"finding {i}"} for i in range(4)]
        _write_findings(env, findings)
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 2


class TestGroundingVerifyExceptionCounting:
    def test_verify_exception_counts_as_contradicted(self, tmp_path):
        """verify_finding_claims() crash must exit 2, not 0 (CR-12 fix)."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_RAISES)
        _write_findings(env, [{"id": "F-001", "title": "finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        # Exception must be counted as contradicted → exit 2
        assert result.returncode == 2

    def test_verify_exception_logged(self, tmp_path):
        """verify_finding_claims() crash is logged to stdout."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_RAISES)
        _write_findings(env, [{"id": "F-001", "title": "finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert "failed" in (result.stdout + result.stderr).lower() or "verify_finding_claims" in (result.stdout + result.stderr)


class TestGroundingVerifyFindingIdFallback:
    def test_finding_id_key_used_when_id_missing(self, tmp_path):
        """Script handles 'finding_id' key when 'id' key absent."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"finding_id": "F-ALT-001", "title": "alt key finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 0

    def test_unknown_id_used_when_both_keys_absent(self, tmp_path):
        """Finding with no id or finding_id doesn't crash."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"title": "no id finding"}])
        result = _run_script(VERIFY_SCRIPT, env, tmp_path)
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# grounding_recheck.py tests
# ---------------------------------------------------------------------------

RECHECK_SCRIPT = "scripts/grounding_recheck.py"


class TestGroundingRecheckNoFindingsFile:
    def test_missing_findings_file_exits_0(self, tmp_path):
        """No findings.json → exit 0."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert result.returncode == 0


class TestGroundingRecheckImportError:
    def test_import_error_exits_1(self, tmp_path):
        """grounding module unavailable → exit 1 (fatal, same as verify)."""
        env = _base_env(tmp_path)
        _write_findings(env, [{"id": "F-001", "title": "test"}])
        result = _run_script_import_error(RECHECK_SCRIPT, env, tmp_path)
        assert result.returncode == 1
        assert "IMPORT ERROR" in (result.stdout + result.stderr)


class TestGroundingRecheckAllGrounded:
    def test_all_grounded_exits_0(self, tmp_path):
        """All claims GROUNDED → exit 0."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"id": "F-001", "title": "test"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert result.returncode == 0

    def test_report_written_on_clean(self, tmp_path):
        """Report is written when all grounded."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"id": "F-001", "title": "test"}])
        _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert Path(env["CLAIM_REPORT"]).exists()

    def test_hallucination_rate_in_output(self, tmp_path):
        """Output includes hallucination_rate summary line."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"id": "F-001", "title": "test"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert "hallucination_rate" in (result.stdout + result.stderr)


class TestGroundingRecheckContradicted:
    def test_contradicted_exits_2(self, tmp_path):
        """CONTRADICTED claims still present → exit 2."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CONTRADICTED)
        _write_findings(env, [{"id": "F-001", "title": "bad finding"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert result.returncode == 2

    def test_still_contradicted_logged(self, tmp_path):
        """STILL CONTRADICTED message appears in output."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CONTRADICTED)
        _write_findings(env, [{"id": "F-001", "title": "bad finding"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert "STILL CONTRADICTED" in (result.stdout + result.stderr) or "CONTRADICTED" in (result.stdout + result.stderr)


class TestGroundingRecheckExceptionCounting:
    def test_exception_counts_as_contradicted_exits_2(self, tmp_path):
        """verify_finding_claims() exception → exit 2, not 0 (CR-12 fix)."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_RAISES)
        _write_findings(env, [{"id": "F-001", "title": "finding"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert result.returncode == 2

    def test_exception_logged(self, tmp_path):
        """Exception during recheck is logged."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_RAISES)
        _write_findings(env, [{"id": "F-001", "title": "finding"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert "failed" in (result.stdout + result.stderr).lower()


class TestGroundingRecheckFindingIdFallback:
    def test_finding_id_key_fallback(self, tmp_path):
        """'finding_id' key accepted when 'id' absent."""
        env = _base_env(tmp_path)
        _install_mock_grounding(tmp_path, _MOCK_GROUNDING_CLEAN)
        _write_findings(env, [{"finding_id": "F-ALT", "title": "alt key"}])
        result = _run_script(RECHECK_SCRIPT, env, tmp_path)
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# grounding_correction_prompt.py tests
# ---------------------------------------------------------------------------

CORRECTION_SCRIPT = "scripts/grounding_correction_prompt.py"


class TestCorrectionPromptMissingReport:
    def test_missing_report_prints_generic_prompt(self, tmp_path):
        """No claim_accuracy_report.json → generic correction prompt printed."""
        env = _base_env(tmp_path)
        # Do not write report file
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert result.returncode == 0
        assert "CORRECTION REQUIRED" in (result.stdout + result.stderr)

    def test_missing_report_includes_task_complete_instruction(self, tmp_path):
        """Generic prompt instructs LLM to re-output TASK_COMPLETE."""
        env = _base_env(tmp_path)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "TASK_COMPLETE" in (result.stdout + result.stderr)


class TestCorrectionPromptBadJson:
    def test_corrupt_json_falls_back_to_generic(self, tmp_path):
        """Corrupt JSON in report → fallback prompt printed, exit 0."""
        env = _base_env(tmp_path)
        Path(env["CLAIM_REPORT"]).write_text("not valid json {{", encoding="utf-8")
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert result.returncode == 0
        assert "CORRECTION REQUIRED" in (result.stdout + result.stderr)

    def test_corrupt_json_fallback_mentions_get_findings(self, tmp_path):
        """Fallback prompt mentions get_findings() MCP call."""
        env = _base_env(tmp_path)
        Path(env["CLAIM_REPORT"]).write_text("{bad json", encoding="utf-8")
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "get_findings" in (result.stdout + result.stderr)


class TestCorrectionPromptContradictedClaims:
    def test_contradicted_claims_appear_in_output(self, tmp_path):
        """CONTRADICTED claims from report are listed in the prompt."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 1.0,
            "contradicted": 1,
            "findings": [
                {
                    "finding_id": "F-001",
                    "claims": [
                        {
                            "claim_text": "process ran at 10:22",
                            "status": "CONTRADICTED",
                            "note": "audit log shows no such timestamp",
                        }
                    ],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert result.returncode == 0
        assert "GROUNDING CORRECTION REQUIRED" in (result.stdout + result.stderr)
        assert "F-001" in (result.stdout + result.stderr)
        assert "process ran at 10:22" in (result.stdout + result.stderr)

    def test_contradiction_note_appears_in_output(self, tmp_path):
        """The 'note' for each CONTRADICTED claim is included."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 1.0,
            "contradicted": 1,
            "findings": [
                {
                    "finding_id": "F-002",
                    "claims": [
                        {
                            "claim_text": "file was deleted",
                            "status": "CONTRADICTED",
                            "note": "MFT shows file still present",
                        }
                    ],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "MFT shows file still present" in (result.stdout + result.stderr)

    def test_hallucination_rate_shown_in_output(self, tmp_path):
        """Hallucination rate from report appears in correction prompt."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 0.5,
            "contradicted": 2,
            "findings": [
                {
                    "finding_id": "F-003",
                    "claims": [
                        {
                            "claim_text": "claim A",
                            "status": "CONTRADICTED",
                            "note": "wrong value",
                        }
                    ],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "0.5" in (result.stdout + result.stderr) or "Hallucination rate" in (result.stdout + result.stderr)

    def test_record_finding_instruction_present(self, tmp_path):
        """Prompt instructs LLM to call record_finding() via MCP."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 1.0,
            "contradicted": 1,
            "findings": [
                {
                    "finding_id": "F-004",
                    "claims": [{"claim_text": "x", "status": "CONTRADICTED", "note": "y"}],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "record_finding" in (result.stdout + result.stderr)

    def test_task_complete_instruction_present(self, tmp_path):
        """Prompt ends with instruction to re-output TASK_COMPLETE."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 1.0,
            "contradicted": 1,
            "findings": [
                {
                    "finding_id": "F-005",
                    "claims": [{"claim_text": "x", "status": "CONTRADICTED", "note": "y"}],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "TASK_COMPLETE" in (result.stdout + result.stderr)

    def test_multiple_contradicted_claims_all_listed(self, tmp_path):
        """Multiple CONTRADICTED claims across findings are all listed."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 1.0,
            "contradicted": 2,
            "findings": [
                {
                    "finding_id": "F-001",
                    "claims": [
                        {"claim_text": "claim alpha", "status": "CONTRADICTED", "note": "bad A"},
                    ],
                },
                {
                    "finding_id": "F-002",
                    "claims": [
                        {"claim_text": "claim beta", "status": "CONTRADICTED", "note": "bad B"},
                    ],
                },
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert "claim alpha" in (result.stdout + result.stderr)
        assert "claim beta" in (result.stdout + result.stderr)
        assert "F-001" in (result.stdout + result.stderr)
        assert "F-002" in (result.stdout + result.stderr)


class TestCorrectionPromptNoContradictedOnlyUngrounded:
    def test_ungrounded_claims_surfaced_when_no_contradicted(self, tmp_path):
        """When no CONTRADICTED, UNGROUNDED claims are shown instead."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 0.0,
            "contradicted": 0,
            "findings": [
                {
                    "finding_id": "F-001",
                    "claims": [
                        {
                            "claim_text": "ungrounded claim here",
                            "status": "UNGROUNDED",
                            "note": "no audit entry",
                        }
                    ],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert result.returncode == 0
        assert "UNGROUNDED" in (result.stdout + result.stderr) or "ungrounded claim here" in (result.stdout + result.stderr)

    def test_no_contradicted_or_ungrounded_still_exits_0(self, tmp_path):
        """Report with no CONTRADICTED or UNGROUNDED → exits 0 cleanly."""
        env = _base_env(tmp_path)
        report = {
            "hallucination_rate": 0.0,
            "contradicted": 0,
            "findings": [
                {
                    "finding_id": "F-001",
                    "claims": [
                        {"claim_text": "clean claim", "status": "GROUNDED", "note": "ok"},
                    ],
                }
            ],
        }
        _write_report(env, report)
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        assert result.returncode == 0


class TestCorrectionPromptCaseDirEnvVar:
    def test_uses_case_dir_env_var(self, tmp_path):
        """Script reads CASE_DIR to locate report, not hardcoded path."""
        # Set CASE_DIR to a subdirectory — report is in that subdir's analysis/
        case_dir = tmp_path / "mycase"
        case_dir.mkdir()
        (case_dir / "analysis").mkdir()
        report_path = case_dir / "analysis" / "claim_accuracy_report.json"
        report_path.write_text(
            json.dumps({"hallucination_rate": 0.0, "contradicted": 0, "findings": []}),
            encoding="utf-8",
        )
        env = {**os.environ, "CASE_DIR": str(case_dir)}
        result = _run_script(CORRECTION_SCRIPT, env, tmp_path)
        # Should not fall back to missing-report generic prompt — report was found
        assert result.returncode == 0
        # No "could not read" error
        assert "Could not read" not in (result.stdout + result.stderr)
