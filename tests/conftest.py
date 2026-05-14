"""
tests/conftest.py — session-wide test fixtures for CaseFile.

Ensures environment variables set during ralph.sh runs (e.g.
CASEFILE_CASE_ROOT, CASEFILE_EXAMINER) do not leak into tests and
cause path-confinement failures or wrong case-dir resolution.
"""
import os
import pytest


@pytest.fixture(autouse=True)
def _clear_casefile_env(monkeypatch):
    """Clear CaseFile runtime env vars before every test.

    Prevents shell-session exports (e.g. CASEFILE_CASE_ROOT=~/cases/SRL-2018)
    from activating path confinement in _verify_exact_value_in_csv and
    _resolve_case_dir during pytest runs.
    """
    for var in ("CASEFILE_CASE_ROOT", "CASEFILE_CASE_DIR", "CASEFILE_EXAMINER",
                "AUDIT_LOG", "FINDINGS_FILE", "CLAIM_REPORT", "CASE_DIR"):
        monkeypatch.delenv(var, raising=False)
