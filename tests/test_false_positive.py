"""
tests/test_false_positive.py — Negative-control / false-positive suite.

Validates that on BENIGN (synthetic clean) evidence the system produces:
- Zero fabricated malicious findings
- Non-malicious correlation verdicts for benign binaries
- Zero suspicious flags across all parser types
- Path-sensitive (not name-blind) csrss.exe flagging
- Measured false-positive rate of 0.0%

Run:
    pytest tests/test_false_positive.py -v
"""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

# Make the repo root importable when running from tests/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Parser imports ───────────────────────────────────────────────────────────
from mcp_server.tools.amcache import (
    _flag_suspicious as _amcache_flag_suspicious,
    _inject_source_column as _amcache_inject_source,
    _parse_amcache_csv,
    parse_amcache,
)

# pyscca / libscca is an optional dependency — guard prefetch imports so the
# entire test suite doesn't fail to collect when it's absent.
try:
    from mcp_server.tools.prefetch import (
        _flag_suspicious as _prefetch_flag_suspicious,
        _parse_prefetch_csv,
        parse_prefetch,
    )
    PREFETCH_AVAILABLE = True
except ImportError:
    PREFETCH_AVAILABLE = False

from mcp_server.tools.event_logs import (
    _flag_suspicious as _evtx_flag_suspicious,
    _parse_evtx_csv,
    parse_event_logs,
)
from mcp_server.tools.registry import (
    _flag_suspicious as _registry_flag_suspicious,
    _parse_recmd_csv,
    parse_registry,
)
from mcp_server.tools.mft import (
    _flag_suspicious as _mft_flag_suspicious,
    _parse_mft_csv,
    parse_mft,
)

# ── Findings imports ─────────────────────────────────────────────────────────
from mcp_server.tools.findings import record_finding

# ── Correlation imports ──────────────────────────────────────────────────────
from mcp_server.tools.correlation import (
    detect_host_type,
    correlate_evidence,
)

# ── Paths to clean fixtures ──────────────────────────────────────────────────
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "clean"
AMCACHE_CLEAN_PATH   = FIXTURES_DIR / "amcache_clean.csv"
PREFETCH_CLEAN_PATH  = FIXTURES_DIR / "prefetch_clean.csv"
REGISTRY_CLEAN_PATH  = FIXTURES_DIR / "registry_clean.csv"
EVTLOGS_CLEAN_PATH   = FIXTURES_DIR / "eventlogs_clean.csv"
MFT_CLEAN_PATH       = FIXTURES_DIR / "mft_clean.csv"

ALL_CLEAN_PATHS = [
    AMCACHE_CLEAN_PATH,
    PREFETCH_CLEAN_PATH,
    REGISTRY_CLEAN_PATH,
    EVTLOGS_CLEAN_PATH,
    MFT_CLEAN_PATH,
]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS                                                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _load_csv_text(path: Path) -> str:
    """Read a fixture CSV file as raw text."""
    return path.read_text(encoding="utf-8")


def _count_csv_rows(text: str) -> int:
    """Count data rows (excluding header) in CSV text."""
    return max(0, sum(1 for l in text.strip().splitlines() if l.strip()) - 1)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  FIXTURE FILE INTEGRITY                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestFixtureIntegrity:
    """Ensure all clean fixture files exist and have the expected schemas."""

    @pytest.mark.parametrize("path", ALL_CLEAN_PATHS)
    def test_fixture_exists(self, path: Path):
        assert path.exists(), f"Missing clean fixture: {path}"

    @pytest.mark.parametrize("path", ALL_CLEAN_PATHS)
    def test_fixture_not_empty(self, path: Path):
        text = _load_csv_text(path)
        rows = _count_csv_rows(text)
        assert rows > 0, f"Fixture {path.name} has zero data rows"

    def test_total_rows_across_fixtures(self):
        total = sum(_count_csv_rows(_load_csv_text(p)) for p in ALL_CLEAN_PATHS)
        assert total == 25, f"Expected 25 total benign rows, got {total}"

    def test_amcache_has_correct_columns(self):
        text = _load_csv_text(AMCACHE_CLEAN_PATH)
        reader = csv.DictReader(io.StringIO(text))
        expected = {
            "Name", "FullPath", "SHA1", "FileKeyLastWriteTimestamp",
            "LinkDate", "Size", "Publisher", "ProductName",
            "FileDescription", "ProgramId", "FileId", "Language",
        }
        assert expected.issubset(set(reader.fieldnames or []))

    def test_prefetch_has_correct_columns(self):
        text = _load_csv_text(PREFETCH_CLEAN_PATH)
        reader = csv.DictReader(io.StringIO(text))
        expected = {
            "ExecutableName", "SourceFilePath", "SourceFileName",
            "RunCount", "LastRun", "RunTime1", "FilesLoaded",
            "Directories", "VolumeName", "VolumeSerial",
            "VolumeCreated", "Hash", "Size",
        }
        assert expected.issubset(set(reader.fieldnames or []))

    def test_registry_has_correct_columns(self):
        text = _load_csv_text(REGISTRY_CLEAN_PATH)
        reader = csv.DictReader(io.StringIO(text))
        expected = {
            "HivePath", "HiveType", "Description", "Category",
            "KeyPath", "ValueName", "ValueData", "ValueData2",
            "ValueData3", "Comment", "Recursive", "DeletedRecord",
            "LastWriteTimestamp",
        }
        assert expected.issubset(set(reader.fieldnames or []))

    def test_eventlogs_has_correct_columns(self):
        text = _load_csv_text(EVTLOGS_CLEAN_PATH)
        reader = csv.DictReader(io.StringIO(text))
        expected = {
            "Channel", "Computer", "EventId", "TimeCreated",
            "UserId", "UserName", "MapDescription",
            "PayloadData1", "PayloadData2", "PayloadData3",
            "PayloadData4", "PayloadData5", "PayloadData6",
            "ExecutableInfo", "RemoteHost", "Keywords",
            "RecordNumber", "SourceFile",
        }
        assert expected.issubset(set(reader.fieldnames or []))

    def test_mft_has_correct_columns(self):
        text = _load_csv_text(MFT_CLEAN_PATH)
        reader = csv.DictReader(io.StringIO(text))
        expected = {
            "EntryNumber", "SequenceNumber", "InUse",
            "ParentEntryNumber", "ParentSequenceNumber", "ParentPath",
            "FileName", "Extension", "FileSize", "ReferenceCount",
            "ReparseTarget", "IsDirectory", "HasAds", "IsAds",
            "SI<FN", "uSecZeros", "Copied", "SiFlags", "NameType",
            "Created0x10", "Created0x30",
            "LastModified0x10", "LastModified0x30",
            "LastRecordChange0x10", "LastRecordChange0x30",
            "LastAccess0x10", "LastAccess0x30",
            "UpdateSequenceNumber", "LogfileSequenceNumber",
            "SecurityId", "ObjectIdFileDroid", "LoggedUtilStream",
            "ZoneIdContents", "SourceFile",
            "ResidentDataBase64", "ResidentDataHex", "ResidentDataASCII",
        }
        assert expected.issubset(set(reader.fieldnames or []))


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TEST 1 — correlate_evidence returns non-malicious verdict for benign binary║
# ╚══════════════════════════════════════════════════════════════════════════════╝

BENIGN_ACCEPTABLE_VERDICTS = {"NOT_FOUND", "INSTALLED_NEVER_RAN", "CONFIRMED_HISTORICAL"}


class TestCorrelateEvidenceBenign:
    """correlate_evidence('svchost.exe') on clean corpus returns non-malicious verdict.

    CONFIRMED_RUNNING is excluded because benign svchost present in Amcache +
    Prefetch would yield CONFIRMED_HISTORICAL (no memory image), which IS acceptable
    — it just means "was on disk and executed historically." The malignant
    CONFIRMED_RUNNING requires memory + disk together; with only disk artifacts
    present, the system returns CONFIRMED_HISTORICAL or weaker.
    """

    @patch("mcp_server.tools.correlation.audit_log")
    def test_svchost_verdict_not_malicious(self, mock_audit_log, tmp_path, monkeypatch):
        """svchost.exe with clean amcache entries → non-CONFIRMED_RUNNING verdict."""
        monkeypatch.setenv("CASEFILE_EXAMINER", "test-fp")
        monkeypatch.delenv("CASEFILE_MEMORY_IMAGE", raising=False)
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr(
            "mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl"
        )

        (tmp_path / "Amcache.hve").touch()
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()

        amcache_text = _load_csv_text(AMCACHE_CLEAN_PATH)
        amcache_entries = _parse_amcache_csv(
            _amcache_inject_source(amcache_text, "InventoryApplicationFile")
        )
        svchost_amcache = [e for e in amcache_entries if e["name"] == "svchost.exe"]

        prefetch_text = _load_csv_text(PREFETCH_CLEAN_PATH)
        prefetch_entries = _parse_prefetch_csv(prefetch_text)
        svchost_prefetch = [
            e for e in prefetch_entries
            if e["executable_name"].lower() == "svchost.exe"
        ]

        fake_amcache_result = {
            "invocation_id": "amcache-fp-001",
            "error": None,
            "entries": svchost_amcache,
            "suspicious": [],
        }
        fake_prefetch_result = {
            "invocation_id": "prefetch-fp-001",
            "error": None,
            "entries": svchost_prefetch,
            "suspicious": [],
        }

        with (
            patch("mcp_server.tools.correlation.parse_amcache", return_value=fake_amcache_result),
            patch("mcp_server.tools.correlation.parse_prefetch", return_value=fake_prefetch_result),
        ):
            result = correlate_evidence("svchost.exe", case_dir=str(tmp_path))

        assert result["verdict"] in BENIGN_ACCEPTABLE_VERDICTS, (
            f"svchost.exe on clean corpus should NOT get CONFIRMED_RUNNING. "
            f"Got: {result['verdict']} — reasoning: {result['verdict_reasoning']}"
        )

    @patch("mcp_server.tools.correlation.audit_log")
    def test_explorer_verdict_not_malicious(self, mock_audit_log, tmp_path, monkeypatch):
        """explorer.exe with only MFT entry → INSTALLED_NEVER_RAN or NOT_FOUND."""
        monkeypatch.setenv("CASEFILE_EXAMINER", "test-fp")
        monkeypatch.delenv("CASEFILE_MEMORY_IMAGE", raising=False)
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr(
            "mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl"
        )

        (tmp_path / "MFT").touch()

        mft_text = _load_csv_text(MFT_CLEAN_PATH)
        mft_entries = _parse_mft_csv(mft_text)
        explorer_mft = [e for e in mft_entries if e["filename"] == "explorer.exe"]

        fake_mft_result = {
            "invocation_id": "mft-fp-001",
            "error": None,
            "entries": explorer_mft,
            "suspicious": [],
        }

        with patch("mcp_server.tools.correlation.parse_mft", return_value=fake_mft_result):
            result = correlate_evidence("explorer.exe", case_dir=str(tmp_path))

        assert result["verdict"] in BENIGN_ACCEPTABLE_VERDICTS, (
            f"explorer.exe on MFT-only corpus must be non-malicious. "
            f"Got: {result['verdict']}"
        )

    @patch("mcp_server.tools.correlation.audit_log")
    def test_unknown_process_on_clean_corpus_is_not_found(self, mock_audit_log, tmp_path, monkeypatch):
        """A process not in any clean fixture → NOT_FOUND verdict."""
        monkeypatch.setenv("CASEFILE_EXAMINER", "test-fp")
        monkeypatch.delenv("CASEFILE_MEMORY_IMAGE", raising=False)
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr(
            "mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl"
        )

        # Mock all four parser calls so correlate_evidence runs without real tools
        empty_amcache = {"invocation_id": "mock-amcache", "error": None, "entries": [], "suspicious": []}
        empty_prefetch = {"invocation_id": "mock-prefetch", "error": None, "entries": [], "suspicious": []}
        empty_memory = {"invocation_id": "mock-memory", "error": None, "records": []}
        empty_mft = {"invocation_id": "mock-mft", "error": None, "entries": [], "suspicious": []}

        with (
            patch("mcp_server.tools.correlation.parse_amcache", return_value=empty_amcache),
            patch("mcp_server.tools.correlation.parse_prefetch", return_value=empty_prefetch),
            patch("mcp_server.tools.correlation.parse_memory", return_value=empty_memory),
            patch("mcp_server.tools.correlation.parse_mft", return_value=empty_mft),
        ):
            result = correlate_evidence("definitely_not_real.exe", case_dir=str(tmp_path))

        assert result["verdict"] == "NOT_FOUND", (
            f"Unknown process on empty corpus must be NOT_FOUND. "
            f"Got: {result['verdict']}"
        )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TEST 2 — Zero suspicious flags on clean corpus                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestZeroSuspiciousFlags:
    """Every parser's _flag_suspicious returns [] on its clean fixture."""

    def test_amcache_flag_suspicious_empty(self):
        text = _load_csv_text(AMCACHE_CLEAN_PATH)
        tagged = _amcache_inject_source(text, "InventoryApplicationFile")
        entries = _parse_amcache_csv(tagged)
        flagged = _amcache_flag_suspicious(entries)
        assert flagged == [], (
            f"Amcache flag_suspicious on clean corpus returned: "
            f"{[(f['name'], f['suspicion_reasons']) for f in flagged]}"
        )

    @pytest.mark.skipif(not PREFETCH_AVAILABLE, reason="pyscca not installed")
    def test_prefetch_flag_suspicious_empty(self):
        text = _load_csv_text(PREFETCH_CLEAN_PATH)
        entries = _parse_prefetch_csv(text)
        flagged = _prefetch_flag_suspicious(entries)
        assert flagged == [], (
            f"Prefetch flag_suspicious on clean corpus returned: "
            f"{[(f['executable_name'], f['suspicion_reasons']) for f in flagged]}"
        )

    def test_eventlogs_flag_suspicious_empty(self):
        text = _load_csv_text(EVTLOGS_CLEAN_PATH)
        entries = _parse_evtx_csv(text)
        flagged = _evtx_flag_suspicious(entries)
        assert flagged == [], (
            f"EventLogs flag_suspicious on clean corpus returned: "
            f"{[(f.get('event_id'), f['suspicion_reasons']) for f in flagged]}"
        )

    def test_registry_flag_suspicious_empty(self):
        text = _load_csv_text(REGISTRY_CLEAN_PATH)
        entries = _parse_recmd_csv(text)
        flagged = _registry_flag_suspicious(entries)
        assert flagged == [], (
            f"Registry flag_suspicious on clean corpus returned: "
            f"{[(f['value_name'], f['suspicion_reasons']) for f in flagged]}"
        )

    def test_mft_flag_suspicious_empty(self):
        text = _load_csv_text(MFT_CLEAN_PATH)
        entries = _parse_mft_csv(text)
        flagged = _mft_flag_suspicious(entries)
        assert flagged == [], (
            f"MFT flag_suspicious on clean corpus returned: "
            f"{[(f['filename'], f['suspicion_reasons']) for f in flagged]}"
        )

    def test_no_ioc_match_on_clean_amcache(self):
        """No IOC match fires on benign amcache rows (no STUN.exe, no malware SHA1s)."""
        text = _load_csv_text(AMCACHE_CLEAN_PATH)
        tagged = _amcache_inject_source(text, "InventoryApplicationFile")
        entries = _parse_amcache_csv(tagged)
        known_malicious_iocs = ["STUN.exe", "pssdnsvc", "subject_srv.exe",
                                "procdump.exe", "msadvapi2_64.exe"]
        for entry in entries:
            assert entry["name"] not in known_malicious_iocs, (
                f"Clean fixture contains known IOC name: {entry['name']}"
            )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TEST 3 — detect_host_type on clean case layout                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestDetectHostTypeClean:
    """detect_host_type on a clean-case layout returns a sane classification."""

    @patch("mcp_server.tools.correlation.audit_log")
    def test_workstation_with_amcache(self, mock_audit, tmp_path):
        (tmp_path / "Amcache.hve").touch()
        result = detect_host_type(str(tmp_path))
        assert result["host_type"] in {"WORKSTATION", "UNKNOWN"}, (
            f"Clean layout with Amcache should be WORKSTATION. "
            f"Got: {result['host_type']}"
        )
        assert "invocation_id" in result
        assert isinstance(result["indicators"], list)
        assert isinstance(result["recommendation"], str)

    @patch("mcp_server.tools.correlation.audit_log")
    def test_unknown_empty_dir(self, mock_audit, tmp_path):
        result = detect_host_type(str(tmp_path))
        assert result["host_type"] == "UNKNOWN"
        assert "recommendation" in result

    @patch("mcp_server.tools.correlation.audit_log")
    def test_no_error_on_valid_path(self, mock_audit, tmp_path):
        result = detect_host_type(str(tmp_path))
        # No 'error' key expected — detect_host_type returns host_type,
        # indicators, recommendation, invocation_id
        assert "host_type" in result


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TEST 4 — record_finding guard on clean data                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestRecordFindingGuard:
    """record_finding cannot mint CONFIRMED from clean data without evidence_quotes.

    All tests redirect AUDIT_FILE to tmp_path to avoid polluting audit/mcp.jsonl.
    """

    def test_confirmed_without_evidence_quotes_warns(self, tmp_path, monkeypatch):
        """CONFIRMED finding with no evidence_quotes → grounding_warning."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr(
            "mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl"
        )
        monkeypatch.setenv("CASEFILE_CASE_DIR", str(tmp_path))
        monkeypatch.setenv("CASEFILE_EXAMINER", "test-fp")
        monkeypatch.delenv("CASEFILE_CASE_ROOT", raising=False)

        result = record_finding(
            title="Clean Corpus Finding",
            observation="svchost.exe present in Amcache at System32",
            interpretation="Normal Windows service host — benign",
            confidence="CONFIRMED",
            artifact_source=str(AMCACHE_CLEAN_PATH),
            supporting_tool="parse_amcache",
            # Deliberately omit evidence_quotes
        )
        assert result["status"] == "DRAFT"
        assert result["grounding_warning"] is not None, (
            "CONFIRMED without evidence_quotes MUST produce grounding_warning"
        )
        assert "evidence_quotes" in result["grounding_warning"].lower()

    def test_inferred_without_evidence_quotes_passes(self, tmp_path, monkeypatch):
        """INFERRED finding without evidence_quotes is accepted without warning."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr(
            "mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl"
        )
        monkeypatch.setenv("CASEFILE_CASE_DIR", str(tmp_path))
        monkeypatch.setenv("CASEFILE_EXAMINER", "test-fp")
        monkeypatch.delenv("CASEFILE_CASE_ROOT", raising=False)

        result = record_finding(
            title="Clean Corpus Observation",
            observation="explorer.exe has normal run count in Prefetch",
            interpretation="Normal user shell activity — benign",
            confidence="INFERRED",
            artifact_source=str(PREFETCH_CLEAN_PATH),
            supporting_tool="parse_prefetch",
        )
        assert result["status"] == "DRAFT"
        assert result["grounding_warning"] is None

    def test_confirmed_with_evidence_quotes_accepted(self, tmp_path, monkeypatch):
        """CONFIRMED with valid evidence_quotes → accepted, no warning."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        monkeypatch.setattr(
            "mcp_server.tools._shared.AUDIT_FILE", audit_dir / "mcp.jsonl"
        )
        monkeypatch.setenv("CASEFILE_CASE_DIR", str(tmp_path))
        monkeypatch.setenv("CASEFILE_EXAMINER", "test-fp")
        monkeypatch.delenv("CASEFILE_CASE_ROOT", raising=False)

        result = record_finding(
            title="svchost.exe on disk",
            observation="svchost.exe found in Amcache at C:\\Windows\\System32",
            interpretation="Normal Windows service host binary",
            confidence="CONFIRMED",
            artifact_source=str(AMCACHE_CLEAN_PATH),
            supporting_tool="parse_amcache",
            evidence_quotes=[
                {
                    "tool": "AmcacheParser",
                    "invocation_id": "amcache-fp-001",
                    "claim": "svchost.exe at System32 path",
                    "exact_value": "svchost.exe",
                    "confidence": "HIGH",
                }
            ],
        )
        assert result["status"] == "DRAFT"
        assert result["grounding_warning"] is None, (
            f"CONFIRMED with evidence_quotes should not warn. "
            f"Got: {result['grounding_warning']}"
        )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TEST 5 — CSRSS path-sensitivity                                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestCsrssPathSensitivity:
    r"""csrss.exe at System32 is clean; csrss.exe at Temp\Perfmon is suspicious.

    This proves the flagging logic is path-sensitive, not name-blind.
    A name-blind system would flag ALL csrss.exe instances regardless of path.
    """

    def test_csrss_at_system32_not_flagged_amcache(self):
        """csrss.exe at C:\\Windows\\System32 must NOT be flagged."""
        text = _load_csv_text(AMCACHE_CLEAN_PATH)
        tagged = _amcache_inject_source(text, "InventoryApplicationFile")
        entries = _parse_amcache_csv(tagged)
        csrss = [e for e in entries if e["name"] == "csrss.exe"]
        assert len(csrss) == 1, "Expected one csrss.exe row in clean amcache"
        flagged = _amcache_flag_suspicious(csrss)
        assert flagged == [], (
            f"csrss.exe at System32 incorrectly flagged: "
            f"{[(f['name'], f['suspicion_reasons']) for f in flagged]}"
        )

    @pytest.mark.skipif(not PREFETCH_AVAILABLE, reason="pyscca not installed")
    def test_csrss_at_system32_not_flagged_prefetch(self):
        """CSRSS.EXE at C:\\Windows\\System32 in Prefetch must NOT be flagged."""
        text = _load_csv_text(PREFETCH_CLEAN_PATH)
        entries = _parse_prefetch_csv(text)
        csrss = [e for e in entries if e["executable_name"].lower() == "csrss.exe"]
        assert len(csrss) == 1, "Expected one CSRSS.EXE row in clean prefetch"
        flagged = _prefetch_flag_suspicious(csrss)
        assert flagged == [], (
            f"CSRSS.EXE at System32 incorrectly flagged in prefetch: "
            f"{[(f['executable_name'], f['suspicion_reasons']) for f in flagged]}"
        )

    def test_csrss_at_system32_not_flagged_mft(self):
        """csrss.exe at System32 in MFT must NOT be flagged."""
        text = _load_csv_text(MFT_CLEAN_PATH)
        entries = _parse_mft_csv(text)
        csrss = [e for e in entries if e["filename"] == "csrss.exe"]
        assert len(csrss) == 1, "Expected one csrss.exe row in clean MFT"
        flagged = _mft_flag_suspicious(csrss)
        assert flagged == [], (
            f"csrss.exe at System32 incorrectly flagged in MFT: "
            f"{[(f['filename'], f['suspicion_reasons']) for f in flagged]}"
        )

    def test_csrss_at_temp_perfmon_IS_flagged_amcache(self):
        r"""csrss.exe at C:\Windows\Temp\Perfmon IS flagged — path-sensitive."""
        # Build a single-row CSV matching the compromised-case pattern
        csv_text = r"""Name,FullPath,SHA1,FileKeyLastWriteTimestamp,LinkDate,Size,Publisher,ProductName,FileDescription,ProgramId,FileId,Language
csrss.exe,C:\Windows\Temp\Perfmon\csrss.exe,0300c7833bfba831b67f9291097655cb162263fd,2018-09-06 18:28:30,,45056,,,,{SRL001},,
"""
        tagged = _amcache_inject_source(csv_text, "InventoryApplicationFile")
        entries = _parse_amcache_csv(tagged)
        flagged = _amcache_flag_suspicious(entries)
        assert len(flagged) > 0, (
            "csrss.exe at Temp\\Perfmon MUST be flagged — "
            "system binary masquerading in non-standard path"
        )
        reasons = flagged[0].get("suspicion_reasons", [])
        assert any(
            "path" in r.lower() or "temp" in r.lower() or "unsigned" in r.lower()
            or "no publisher" in r.lower() or "non-system32" in r.lower()
            for r in reasons
        ), f"Flagged csrss.exe should cite path or signing issue. Reasons: {reasons}"

    def test_csrss_at_temp_perfmon_IS_flagged_mft(self):
        r"""csrss.exe at Temp\Perfmon in MFT IS flagged."""
        csv_text = r"""EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ResidentDataBase64,ResidentDataHex,ResidentDataASCII
999,1,True,80,2,.\Windows\Temp\Perfmon,csrss.exe,.exe,45056,1,,False,False,False,False,False,False,Archive,Windows,2018-09-06 18:28:30,2018-09-06 18:28:30,2018-09-06 18:28:30,2018-09-06 18:28:30,2018-09-06 18:28:30,2018-09-06 18:28:30,2018-09-06 18:28:30,2018-09-06 18:28:30,,12345,,,,,/cases/MFT,,,
"""
        entries = _parse_mft_csv(csv_text)
        flagged = _mft_flag_suspicious(entries)
        assert len(flagged) > 0, (
            "csrss.exe at Temp\\Perfmon in MFT MUST be flagged"
        )
        reasons = flagged[0].get("suspicion_reasons", [])
        assert any(
            "temp" in r.lower() or "path" in r.lower() or "non-system32" in r.lower()
            for r in reasons
        ), f"Flagged MFT csrss.exe should cite path issue. Reasons: {reasons}"

    @pytest.mark.skipif(not PREFETCH_AVAILABLE, reason="pyscca not installed")
    def test_csrss_at_temp_perfmon_IS_flagged_prefetch(self):
        r"""CSRSS.EXE at Temp\Perfmon in Prefetch IS flagged."""
        csv_text = r"""ExecutableName,SourceFilePath,SourceFileName,RunCount,LastRun,RunTime1,FilesLoaded,Directories,VolumeName,VolumeSerial,VolumeCreated,Hash,Size
CSRSS.EXE,C:\Windows\Temp\Perfmon\csrss.exe,CSRSS.EXE-FF001122.pf,78,2018-09-06 18:30:00,,C:\WINDOWS\TEMP\PERFMON\CSRSS.EXE,C:\WINDOWS\TEMP\PERFMON,\DEVICE\HARDDISKVOLUME2,ABCD1234,2023-01-01 00:00:00,FF001122,45056
"""
        entries = _parse_prefetch_csv(csv_text)
        flagged = _prefetch_flag_suspicious(entries)
        assert len(flagged) > 0, (
            "CSRSS.EXE at Temp\\Perfmon in Prefetch MUST be flagged"
        )
        reasons = flagged[0].get("suspicion_reasons", [])
        assert any(
            "temp" in r.lower() or "path" in r.lower()
            or "masquerad" in r.lower() or "non-system32" in r.lower()
            for r in reasons
        ), f"Flagged prefetch CSRSS should cite path/masquerade. Reasons: {reasons}"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  TEST 6 — False-positive rate computation                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestFalsePositiveRate:
    """Compute FP rate = flagged_rows / total_rows across all clean fixtures.

    The rate must be 0.0 — every parser must return zero suspicious flags
    on its corresponding clean fixture.
    """

    def test_false_positive_rate_is_zero(self):
        results = {}

        # Amcache
        amcache_text = _load_csv_text(AMCACHE_CLEAN_PATH)
        amcache_total = _count_csv_rows(amcache_text)
        tagged = _amcache_inject_source(amcache_text, "InventoryApplicationFile")
        amcache_flagged = len(_amcache_flag_suspicious(_parse_amcache_csv(tagged)))
        results["amcache"] = (amcache_total, amcache_flagged)

        # Prefetch (optional — pyscca may not be installed)
        if PREFETCH_AVAILABLE:
            prefetch_text = _load_csv_text(PREFETCH_CLEAN_PATH)
            prefetch_total = _count_csv_rows(prefetch_text)
            prefetch_flagged = len(_prefetch_flag_suspicious(_parse_prefetch_csv(prefetch_text)))
            results["prefetch"] = (prefetch_total, prefetch_flagged)

        # Event Logs
        evtx_text = _load_csv_text(EVTLOGS_CLEAN_PATH)
        evtx_total = _count_csv_rows(evtx_text)
        evtx_flagged = len(_evtx_flag_suspicious(_parse_evtx_csv(evtx_text)))
        results["event_logs"] = (evtx_total, evtx_flagged)

        # Registry
        reg_text = _load_csv_text(REGISTRY_CLEAN_PATH)
        reg_total = _count_csv_rows(reg_text)
        reg_flagged = len(_registry_flag_suspicious(_parse_recmd_csv(reg_text)))
        results["registry"] = (reg_total, reg_flagged)

        # MFT
        mft_text = _load_csv_text(MFT_CLEAN_PATH)
        mft_total = _count_csv_rows(mft_text)
        mft_flagged = len(_mft_flag_suspicious(_parse_mft_csv(mft_text)))
        results["mft"] = (mft_total, mft_flagged)

        # Summary
        total_rows = sum(t for t, _ in results.values())
        total_flagged = sum(f for _, f in results.values())

        # Build per-parser report for assertion messages
        report_lines = []
        for parser, (total, flagged) in sorted(results.items()):
            rate = flagged / total if total > 0 else 0.0
            report_lines.append(f"  {parser}: {flagged}/{total} flagged ({rate:.1%})")
        report = "\n".join(report_lines)

        assert total_flagged == 0, (
            f"Expected ZERO flagged rows across all clean fixtures.\n"
            f"Breakdown:\n{report}\n"
            f"Total: {total_flagged}/{total_rows} flagged"
        )

        fp_rate = total_flagged / total_rows if total_rows > 0 else float("nan")
        assert fp_rate == 0.0, (
            f"False-positive rate must be 0.0. Got: {fp_rate:.4f}"
        )

    def test_total_clean_rows_is_25(self):
        """Sanity check — the clean corpus has exactly 25 benign rows."""
        total = sum(_count_csv_rows(_load_csv_text(p)) for p in ALL_CLEAN_PATHS)
        assert total == 25, f"Clean corpus should have 25 rows. Got: {total}"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  INTEGRATION TESTS — parser parse_*() with clean fixtures as mock output   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class TestParserIntegrationClean:
    """End-to-end test: parsers produce zero suspicious entries from clean fixture output.

    All tests redirect AUDIT_FILE to tmp_path to avoid polluting the real
    audit/mcp.jsonl with test data.
    """

    def _write_fake_csv(self, out_dir: Path, filename: str, content: str) -> None:
        """Write a CSV file with the exact filename the external tool produces.

        ``filename`` must be the complete filename (e.g. ``"Amcache_InventoryApplicationFile.csv"``),
        NOT a prefix — each EZ tool produces a different naming convention.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / filename).write_text(content, encoding="utf-8")

    @patch("mcp_server.tools.amcache.run_tool")
    def test_parse_amcache_clean_no_suspicious(self, mock_run, tmp_path):
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"REGF")
        out_dir = tmp_path / "amcache_out"
        audit_file = tmp_path / "audit" / "mcp.jsonl"
        audit_file.parent.mkdir()

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        clean_text = _load_csv_text(AMCACHE_CLEAN_PATH)
        # AmcacheParser --csvf Amcache → Amcache_InventoryApplicationFile.csv
        self._write_fake_csv(out_dir, "Amcache_InventoryApplicationFile.csv", clean_text)

        with patch("mcp_server.tools._shared.AUDIT_FILE", audit_file):
            with patch.dict("os.environ", {"CASEFILE_EXAMINER": "test-fp"}, clear=False):
                result = parse_amcache(str(hive), output_dir=str(out_dir))

        assert result["error"] is None
        assert mock_run.called, "run_tool mock was not invoked"
        assert len(result["entries"]) > 0, "CSV fixture must be parsed"
        assert result["suspicious"] == [], (
            f"parse_amcache on clean fixture must have empty suspicious. "
            f"Got: {len(result['suspicious'])} flagged"
        )

    @patch("mcp_server.tools.event_logs.run_tool")
    def test_parse_event_logs_clean_no_suspicious(self, mock_run, tmp_path):
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        out_dir = tmp_path / "evtx_out"
        audit_file = tmp_path / "audit" / "mcp.jsonl"
        audit_file.parent.mkdir()

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        clean_text = _load_csv_text(EVTLOGS_CLEAN_PATH)
        # EvtxECmd --csvf evtx.csv → evtx.csv
        self._write_fake_csv(out_dir, "evtx.csv", clean_text)

        with patch("mcp_server.tools._shared.AUDIT_FILE", audit_file):
            with patch.dict("os.environ", {"CASEFILE_EXAMINER": "test-fp"}, clear=False):
                result = parse_event_logs(str(evtx_dir), output_dir=str(out_dir))

        assert result["error"] is None
        assert mock_run.called, "run_tool mock was not invoked"
        assert len(result["entries"]) > 0, "CSV fixture must be parsed"
        assert result["suspicious"] == [], (
            f"parse_event_logs on clean fixture must have empty suspicious. "
            f"Got: {len(result['suspicious'])} flagged"
        )

    @patch("mcp_server.tools.mft.run_tool")
    def test_parse_mft_clean_no_suspicious(self, mock_run, tmp_path):
        mft_file = tmp_path / "MFT"
        mft_file.write_bytes(b"FILE" + b"\x00" * 1020)
        out_dir = tmp_path / "mft_out"
        audit_file = tmp_path / "audit" / "mcp.jsonl"
        audit_file.parent.mkdir()

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        clean_text = _load_csv_text(MFT_CLEAN_PATH)
        # MFTECmd --csvf mft → mft_MFTECmd_Output.csv (matches mft_*.csv glob)
        self._write_fake_csv(out_dir, "mft_MFTECmd_Output.csv", clean_text)

        with patch("mcp_server.tools._shared.AUDIT_FILE", audit_file):
            with patch.dict("os.environ", {"CASEFILE_EXAMINER": "test-fp"}, clear=False):
                # Use include_all=True so clean (non-suspicious, non-timestomped)
                # entries are returned and can be verified
                result = parse_mft(str(mft_file), output_dir=str(out_dir),
                                   include_all=True)

        assert result["error"] is None
        assert mock_run.called, "run_tool mock was not invoked"
        assert len(result["entries"]) > 0, "CSV fixture must be parsed"
        assert result["suspicious"] == [], (
            f"parse_mft on clean fixture must have empty suspicious. "
            f"Got: {len(result['suspicious'])} flagged"
        )

    @patch("mcp_server.tools.registry.run_tool")
    def test_parse_registry_clean_no_suspicious(self, mock_run, tmp_path):
        hive_dir = tmp_path / "registry"
        hive_dir.mkdir()
        out_dir = tmp_path / "registry_out"
        batch_file = tmp_path / "Kroll_Batch.reb"
        batch_file.write_text("# fake batch for testing\n")
        audit_file = tmp_path / "audit" / "mcp.jsonl"
        audit_file.parent.mkdir()

        mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        clean_text = _load_csv_text(REGISTRY_CLEAN_PATH)
        # RECmd --csvf registry.csv → registry.csv
        self._write_fake_csv(out_dir, "registry.csv", clean_text)

        with patch("mcp_server.tools._shared.AUDIT_FILE", audit_file):
            with patch.dict("os.environ", {"CASEFILE_EXAMINER": "test-fp"}, clear=False):
                result = parse_registry(
                    str(hive_dir),
                    batch_file=str(batch_file),
                    output_dir=str(out_dir),
                )

        assert result["error"] is None
        assert mock_run.called, "run_tool mock was not invoked"
        assert len(result["entries"]) > 0, "CSV fixture must be parsed"
        assert result["suspicious"] == [], (
            f"parse_registry on clean fixture must have empty suspicious. "
            f"Got: {len(result['suspicious'])} flagged"
        )


@pytest.mark.skipif(not PREFETCH_AVAILABLE, reason="pyscca not installed")
class TestPrefetchCleanIntegration:
    """Prefetch integration tests — requires pyscca mock.

    Redirects AUDIT_FILE to tmp_path to avoid polluting audit/mcp.jsonl.
    """

    def setup_method(self):
        import unittest.mock as _mock
        import mcp_server.tools.prefetch as _pf
        self._pyscca_patcher = _mock.patch.object(_pf, "pyscca", new=object())
        self._pyscca_patcher.start()

    def teardown_method(self):
        self._pyscca_patcher.stop()

    @patch("mcp_server.tools.prefetch._parse_pf_file")
    def test_parse_prefetch_clean_no_suspicious(self, mock_parse, tmp_path):
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        audit_file = tmp_path / "audit" / "mcp.jsonl"
        audit_file.parent.mkdir()

        # Build clean entries from the fixture
        clean_text = _load_csv_text(PREFETCH_CLEAN_PATH)
        clean_entries = _parse_prefetch_csv(clean_text)

        # Create .pf files for each entry
        pf_entries = []
        for e in clean_entries:
            pf_file = pf_dir / (e.get("source_file", f"{e['executable_name']}-TEST.pf"))
            pf_file.write_bytes(b"fake")
            pf_entries.append(e)

        mock_parse.side_effect = pf_entries

        with patch("mcp_server.tools._shared.AUDIT_FILE", audit_file):
            with patch.dict("os.environ", {"CASEFILE_EXAMINER": "test-fp"}, clear=False):
                result = parse_prefetch(str(pf_dir))

        assert result["error"] is None
        assert mock_parse.called, "_parse_pf_file mock was not invoked"
        assert len(result["entries"]) > 0, "CSV fixture must be parsed"
        assert result["suspicious"] == [], (
            f"parse_prefetch on clean fixture must have empty suspicious. "
            f"Got: {len(result['suspicious'])} flagged"
        )
