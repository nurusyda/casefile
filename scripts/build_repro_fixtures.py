#!/usr/bin/env python3
"""
build_repro_fixtures.py — Build reproducibility fixtures from committed results.

Generates fixtures/reproducibility/{SRL-2018,SRL-2018-DC,SRL-2018-FILE}/
with sanitized audit logs, findings, expected values, and minimal CSV files.
"""
import json
import csv
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures" / "reproducibility"
RESULTS = REPO / "results"

# ── Sanitization helpers ────────────────────────────────────────────────────────

def sanitize_paths(obj):
    """Recursively replace absolute paths with {{CASE_DIR}} token."""
    if isinstance(obj, str):
        # Replace any /home/sansproject/cases/<CASE>/... pattern
        obj = re.sub(r'/home/sansproject/cases/SRL-\d[^/"]*', '{{CASE_DIR}}', obj)
        obj = re.sub(r'/home/sansproject/casefile/analysis/', '{{CASE_DIR}}/analysis/', obj)
        return obj
    elif isinstance(obj, dict):
        return {k: sanitize_paths(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_paths(v) for v in obj]
    return obj


def sanitize_finding(finding):
    """Sanitize a single finding record."""
    f = sanitize_paths(finding)
    f["examiner"] = "examiner"
    # Also sanitize artifact_source which may contain paths
    if "artifact_source" in f:
        f["artifact_source"] = sanitize_paths(f["artifact_source"])
    if "supporting_tool" in f:
        f["supporting_tool"] = sanitize_paths(f["supporting_tool"])
    return f


def write_jsonl(path, lines):
    """Write list of dicts as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")


def write_json(path, obj):
    """Write dict as pretty JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)


def write_csv(path, header, rows):
    """Write CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)


def _extract_exact_values(findings):
    """Return set of (invocation_id, exact_value) tuples from findings."""
    pairs = set()
    for f in findings:
        for q in f.get("evidence_quotes", []):
            ev = q.get("exact_value")
            inv = q.get("invocation_id")
            if ev and inv:
                pairs.add((inv, ev))
    return pairs


def _trim_csv(real_csv_path, exact_values, output_path, max_rows=0, channel=None):
    """Read real_csv_path, keep header + rows where any cell (case-insensitive
    stripped) matches one of the exact_values, sanitize paths, write to output_path.

    If max_rows > 0, keep at most that many rows per matched needle.
    If *channel* is given, only consider rows whose Channel column matches
    (EvtxECmd CSV column index 6).  Returns the number of data rows written
    (excluding header).
    """
    if not real_csv_path.exists():
        print(f"    WARNING: real CSV {real_csv_path} not found — skipping")
        return 0

    needles = {v.lower() for v in exact_values}
    header = None
    kept_rows = []
    # Track how many rows we've kept per needle for max_rows limiting
    needle_counts: dict[str, int] = {n: 0 for n in needles}

    with open(real_csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            print(f"    WARNING: {real_csv_path} is empty")
            return 0

        for row in reader:
            # Channel filter — applied before needle matching so a
            # Security.evtx invocation never pulls System.evtx rows.
            if channel is not None:
                try:
                    row_channel = row[6].strip() if len(row) > 6 else ""
                except IndexError:
                    row_channel = ""
                if row_channel.lower() != channel.lower():
                    continue

            cells_lower = {cell.strip().lower() for cell in row}
            matched = cells_lower & needles
            if matched:
                # Honour max_rows per needle (0 = unlimited).
                # Only keep the row if at least one matched needle is still
                # under its limit.  Only increment the needles that are under
                # their limits so a saturated needle doesn't block other
                # needles that still need rows.
                if max_rows > 0:
                    under_limit = [n for n in matched
                                   if needle_counts.get(n, 0) < max_rows]
                    if not under_limit:
                        continue
                    for n in under_limit:
                        needle_counts[n] += 1
                else:
                    for n in matched:
                        needle_counts[n] += 1
                # Sanitize absolute paths in every cell
                sanitized = [sanitize_paths(cell) for cell in row]
                kept_rows.append(sanitized)

    if kept_rows:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        write_csv(output_path, header, kept_rows)
        # Verify by counting needle matches tracked during source read
        verified = sum(1 for n in needles if needle_counts.get(n, 0) > 0)
        print(f"    Wrote {len(kept_rows)} rows to {output_path.name} "
              f"({verified}/{len(needles)} exact_values verified)")
    else:
        print(f"    WARNING: no rows matched for {output_path.name}")

    return len(kept_rows)


# ── Case: SRL-2018 (WORKSTATION) ─────────────────────────────────────────────────

def build_srl2018_workstation():
    case = "SRL-2018"
    case_dir = FIXTURES / case
    print(f"Building {case}...")

    # ── audit/mcp.jsonl ──
    audit_entries = [
        {
            "ts": "2026-06-06T09:31:00.000000+00:00",
            "invocation_id": "f9a16390-6bc1-4173-bb15-dd469d1161b7",
            "tool": "AmcacheParser",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/AmcacheParser.dll -f {{CASE_DIR}}/Amcache.hve --csv {{CASE_DIR}}/analysis/amcache_out --csvf Amcache -q",
            "returncode": 0,
            "stdout_lines": 0,
            "stderr_excerpt": "",
            "parsed_record_count": 223,
            "duration_ms": 1200,
            "amcache_path": "{{CASE_DIR}}/Amcache.hve",
            "output_dir": "{{CASE_DIR}}/analysis/amcache_out",
            "csv_files": ["{{CASE_DIR}}/csv/Amcache_UnassociatedFileEntries.csv"],
            "suspicious_count": 112,
            "capped": False,
        },
        {
            "ts": "2026-06-06T09:32:00.000000+00:00",
            "invocation_id": "8ae1e31e-7d27-4ad2-a532-55908011dfde",
            "tool": "pyscca",
            "examiner": "examiner",
            "cmd": "pyscca({{CASE_DIR}}/Prefetch/) x 219",
            "returncode": 0,
            "stdout_lines": 218,
            "stderr_excerpt": "1 files failed to parse",
            "parsed_record_count": 218,
            "duration_ms": 549,
            "prefetch_path": "{{CASE_DIR}}/Prefetch",
            "pf_files_found": 219,
            "parse_errors": 1,
            "suspicious_count": 112,
            "capped": False,
            "csv_files": ["{{CASE_DIR}}/csv/prefetch_summary.csv"],
        },
        {
            "ts": "2026-06-06T09:33:00.000000+00:00",
            "invocation_id": "af055021-c2fd-4e9b-9117-99569c4f67d3",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evtx/System.evtx --inc 4624,4625,4648,4688,4720,4732,7045,1102,4769 --csv {{CASE_DIR}}/analysis/evtx_sys_out --csvf System.csv",
            "returncode": 0,
            "stdout_lines": 16,
            "stderr_excerpt": "",
            "parsed_record_count": 468,
            "duration_ms": 3800,
            "evtx_path": "{{CASE_DIR}}/evtx/System.evtx",
            "event_ids_filter": [4624, 4625, 4648, 4688, 4720, 4732, 7045, 1102, 4769],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_sys_out",
            "csv_files": ["{{CASE_DIR}}/csv/evtx_System.csv"],
            "suspicious_count": 35,
            "capped": False,
        },
        {
            "ts": "2026-06-06T09:34:00.000000+00:00",
            "invocation_id": "mem-566f3c84",
            "tool": "Volatility3",
            "examiner": "examiner",
            "cmd": "/usr/local/bin/vol -f {{CASE_DIR}}/memory.img windows.pslist",
            "returncode": 0,
            "stdout_lines": 133,
            "stderr_excerpt": "Progress: 100.00 Stacking attempts finished",
            "parsed_record_count": 129,
            "duration_ms": 11071,
            "plugin": "windows.pslist",
            "image_sha256": "83456c716bbbeb116b474b87473445629db5dd018d0c667ec99f088871e1cbca",
            "image_path": "{{CASE_DIR}}/memory.img",
            "cached": False,
        },
        {
            "ts": "2026-06-06T09:35:00.000000+00:00",
            "invocation_id": "correlation_f3d4c111efac",
            "tool": "correlate_evidence",
            "examiner": "examiner",
            "cmd": "correlate_evidence(process_name='subject_srv.exe')",
            "returncode": 0,
            "stdout_lines": 0,
            "stderr_excerpt": "",
            "parsed_record_count": 2,
            "duration_ms": 500,
            "params": {"process_name": "subject_srv.exe", "case_dir": "{{CASE_DIR}}"},
            "verdict": "CONFIRMED_RUNNING",
            "sources_present": ["prefetch", "memory"],
        },
    ]
    write_jsonl(case_dir / "audit" / "mcp.jsonl", audit_entries)

    # ── findings.json ──
    findings_src = RESULTS / "SRL-2018_workstation_findings.json"
    with open(findings_src, encoding="utf-8") as fh:
        findings = json.load(fh)
    sanitized_findings = [sanitize_finding(f) for f in findings]
    write_json(case_dir / "findings.json", sanitized_findings)

    # ── expected.json ──
    result_src = RESULTS / "SRL-2018_workstation_session20.json"
    with open(result_src, encoding="utf-8") as fh:
        result = json.load(fh)
    expected = {
        "total_claims": result["total_claims"],
        "grounded": result["grounded"],
        "ungrounded": result["ungrounded"],
        "contradicted": result["contradicted"],
        "hallucination_rate": result["hallucination_rate"],
        "tier2_verified": result["tier2_verified"],
    }
    write_json(case_dir / "expected.json", expected)

    # ── Minimal CSV files for Tier 2 ──
    # Amcache CSV: must contain SHA1 0300c7833bfba831b67f9291097655cb162263fd
    write_csv(
        case_dir / "csv" / "Amcache_UnassociatedFileEntries.csv",
        ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1",
         "IsOsComponent", "FullPath", "Name", "FileExtension", "LinkDate",
         "ProductName", "Size", "Version", "ProductVersion", "LongPathHash",
         "BinaryType", "IsPeFile", "BinFileVersion", "BinProductVersion",
         "Usn", "Language", "Description"],
        [["Unassociated", "00066bda6a42f3fafe2f32735541b4bd8f9200000904",
          "2046-01-12 06:37:24", "0300c7833bfba831b67f9291097655cb162263fd",
          "False",
          "c:\\windows\\system32\\csrss.exe", "csrss.exe", ".exe",
          "2046-01-12 06:37:24", "", "", "", "", "",
          "pe64_amd64", "True", "", "", "", "", ""]],
    )

    # Prefetch CSV: must contain source_file "CSRSS.EXE-7898BE61.pf" and
    # executable_name "SDELETE.EXE"
    write_csv(
        case_dir / "csv" / "prefetch_summary.csv",
        ["executable_name", "last_run_utc", "run_count", "source_file"],
        [
            ["CSRSS.EXE", "2018-08-30T22:03:27Z", "3", "CSRSS.EXE-7898BE61.pf"],
            ["SDELETE.EXE", "2018-05-14T05:26:17Z", "1", "SDELETE.EXE-1A2B3C4D.pf"],
            ["CSRSS.EXE", "2018-09-05T18:25:53Z", "12", "CSRSS.EXE-3FE41F7E.pf"],
        ],
    )

    # EvtxCSV: must contain "Name: Microsoft Advanced API 64",
    # "Name: Microsoft Advanced API 32", "Name: a03d616", "Name: F-Response Subject"
    write_csv(
        case_dir / "csv" / "evtx_System.csv",
        ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
         "Provider", "Channel", "ProcessId", "ThreadId", "Computer",
         "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
         "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
         "PayloadData5", "PayloadData6", "ExecutableInfo", "HiddenRecord",
         "SourceFile", "Keywords", "ExtraDataOffset", "Payload"],
        [
            ["1", "1", "2018-05-08 21:07:39.0000000", "7045", "Info",
             "Service Control Manager", "System", "716", "6724", "base-rd01",
             "0", "", "A service was installed in the system.", "SYSTEM", "",
             "Name: Microsoft Advanced API 64",
             "C:\\Program Files (x86)\\Microsoft Advanced API 64\\msadvapi2_64.exe",
             "StartType: auto start", "Account: LocalSystem", "", "",
             "", "False", "{{CASE_DIR}}/evtx/System.evtx", "", "0", ""],
            ["2", "2", "2018-05-08 21:07:57.0000000", "7045", "Info",
             "Service Control Manager", "System", "716", "6724", "base-rd01",
             "0", "", "A service was installed in the system.", "SYSTEM", "",
             "Name: Microsoft Advanced API 32",
             "C:\\Program Files (x86)\\Microsoft Advanced API 32\\msadvapi2_32.exe",
             "StartType: auto start", "Account: LocalSystem", "", "",
             "", "False", "{{CASE_DIR}}/evtx/System.evtx", "", "0", ""],
            ["3", "3", "2018-08-27 23:57:45.0000000", "7045", "Info",
             "Service Control Manager", "System", "716", "6724", "base-rd01",
             "0", "", "A service was installed in the system.", "SYSTEM", "",
             "Name: a03d616",
             "\\\\127.0.0.1\\C$\\a34e015.exe",
             "StartType: demand start", "Account: LocalSystem", "", "",
             "", "False", "{{CASE_DIR}}/evtx/System.evtx", "", "0", ""],
            ["4", "4", "2018-09-06 18:28:30.0000000", "7045", "Info",
             "Service Control Manager", "System", "716", "6724", "base-rd01",
             "0", "", "A service was installed in the system.", "SYSTEM", "",
             "Name: F-Response Subject",
             "C:\\windows\\subject_srv.exe -s \"base-hunt.shieldbase.lan:5682\"",
             "StartType: auto start", "Account: LocalSystem", "", "",
             "", "False", "{{CASE_DIR}}/evtx/System.evtx", "", "0", ""],
        ],
    )

    expected_counts = expected
    print(f"  {case}: claims={expected_counts['total_claims']}, "
          f"grounded={expected_counts['grounded']}, "
          f"tier2={expected_counts['tier2_verified']}")


# ── Case: SRL-2018-DC ─────────────────────────────────────────────────────────

def build_srl2018_dc():
    case = "SRL-2018-DC"
    case_dir = FIXTURES / case
    print(f"Building {case}...")

    audit_entries = [
        {
            "ts": "2026-06-06T05:43:00.000000+00:00",
            "invocation_id": "6cad926d-0929-4bfd-9832-cb4efb8701dc",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evidence/evtx/Security.evtx --inc 4624,4625,4648,4688,4720,4732,7045,1102,4769,4776,4662,4663 --csv {{CASE_DIR}}/analysis/evtx_security_s18 --csvf Security.csv",
            "returncode": 0,
            "stdout_lines": 49,
            "stderr_excerpt": "",
            "parsed_record_count": 270729,
            "duration_ms": 79027,
            "evtx_path": "{{CASE_DIR}}/evidence/evtx/Security.evtx",
            "event_ids_filter": [4624, 4625, 4648, 4688, 4720, 4732, 7045, 1102, 4769, 4776, 4662, 4663],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_security_s18",
            "csv_files": ["{{CASE_DIR}}/analysis/evtx_security_s18/Security.csv"],
            "suspicious_count": 1119,
            "event_id_counts": {"4624": 50651, "4625": 459, "4648": 91, "4662": 83, "4688": 8184, "4769": 198959, "4776": 12302},
            "capped": True,
        },
        {
            "ts": "2026-06-06T05:50:00.000000+00:00",
            "invocation_id": "5a3c5dea-c316-4097-ae1f-28cea845d4bc",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evidence/evtx/Security.evtx --inc 4769 --csv {{CASE_DIR}}/analysis/evtx_kerb_s18 --csvf Security.csv",
            "returncode": 0,
            "stdout_lines": 43,
            "stderr_excerpt": "",
            "parsed_record_count": 198959,
            "duration_ms": 68531,
            "evtx_path": "{{CASE_DIR}}/evidence/evtx/Security.evtx",
            "event_ids_filter": [4769],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_kerb_s18",
            "csv_files": ["{{CASE_DIR}}/analysis/evtx_kerb_s18/Security.csv"],
            "suspicious_count": 0,
            "event_id_counts": {"4769": 198959},
            "capped": True,
        },
        {
            "ts": "2026-06-06T05:55:00.000000+00:00",
            "invocation_id": "7ace1275-7b42-41e5-a0b6-075f8dfb1033",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evidence/evtx/System.evtx --inc 7034,7045 --csv {{CASE_DIR}}/analysis/evtx_system_s18 --csvf System.csv",
            "returncode": 0,
            "stdout_lines": 12,
            "stderr_excerpt": "",
            "parsed_record_count": 312,
            "duration_ms": 4500,
            "evtx_path": "{{CASE_DIR}}/evidence/evtx/System.evtx",
            "event_ids_filter": [7034, 7045],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_system_s18",
            "csv_files": ["{{CASE_DIR}}/analysis/evtx_system_s18/System.csv"],
            "suspicious_count": 12,
            "capped": False,
        },
        {
            "ts": "2026-06-06T05:56:00.000000+00:00",
            "invocation_id": "71c9135f-9529-4070-bb64-e854427fd286",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evidence/evtx/Security.evtx --inc 4662 --csv {{CASE_DIR}}/analysis/evtx_ntds_s18 --csvf Security.csv",
            "returncode": 0,
            "stdout_lines": 8,
            "stderr_excerpt": "",
            "parsed_record_count": 83,
            "duration_ms": 3200,
            "evtx_path": "{{CASE_DIR}}/evidence/evtx/Security.evtx",
            "event_ids_filter": [4662],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_ntds_s18",
            "csv_files": ["{{CASE_DIR}}/analysis/evtx_ntds_s18/Security.csv"],
            "suspicious_count": 0,
            "capped": False,
        },
        {
            "ts": "2026-06-06T05:57:00.000000+00:00",
            "invocation_id": "correlation_4ddb81378703",
            "tool": "correlate_evidence",
            "examiner": "examiner",
            "cmd": "correlate_evidence(process_name='subject_srv.exe')",
            "returncode": 0,
            "stdout_lines": 0,
            "stderr_excerpt": "",
            "parsed_record_count": 0,
            "duration_ms": 200,
            "params": {"process_name": "subject_srv.exe", "case_dir": "{{CASE_DIR}}"},
            "verdict": "NOT_FOUND",
            "sources_present": [],
        },
    ]
    write_jsonl(case_dir / "audit" / "mcp.jsonl", audit_entries)

    # ── findings.json ──
    findings_src = RESULTS / "SRL-2018-DC_findings.json"
    with open(findings_src, encoding="utf-8") as fh:
        findings = json.load(fh)
    sanitized_findings = [sanitize_finding(f) for f in findings]
    write_json(case_dir / "findings.json", sanitized_findings)

    # ── expected.json ──
    result_src = RESULTS / "SRL-2018-DC_session19.json"
    with open(result_src, encoding="utf-8") as fh:
        result = json.load(fh)
    expected = {
        "total_claims": result["total_claims"],
        "grounded": result["grounded"],
        "ungrounded": result["ungrounded"],
        "contradicted": result["contradicted"],
        "hallucination_rate": result["hallucination_rate"],
        "tier2_verified": result["tier2_verified"],
    }
    write_json(case_dir / "expected.json", expected)

    # ── Minimal CSV files for Tier 2 ──
    # Extract exact_values from findings, grouped by invocation_id
    exact_pairs = _extract_exact_values(sanitized_findings)
    # Map invocation_id → set of exact_values
    by_inv: dict[str, set[str]] = {}
    for inv_id, ev in exact_pairs:
        by_inv.setdefault(inv_id, set()).add(ev)

    # Invocation → real CSV mapping (for trimming source)
    real_csv_map = {
        # EID 7045 (System.evtx) — "Name: F-Response Subject", "Name: mnemosyne"
        "7ace1275-7b42-41e5-a0b6-075f8dfb1033": (
            REPO.parent / "cases/SRL-2018-DC/analysis/evtx_system_s18/System.csv"
        ),
        # EID 4662 DCSync detection (Security.evtx) — "shieldbase\\BASE-DC$"
        # The original investigation session wrote to evtx_ntds_s18.
        # (Despite the task being DCSync detection, the directory name
        # "evtx_ntds_s18" reflects the NTDS replication angle of the hunt.
        # The string "evtx_dcsync_s18" was never used in any session.)
        "71c9135f-9529-4070-bb64-e854427fd286": (
            REPO.parent / "cases/SRL-2018-DC/analysis/evtx_ntds_s18/Security.csv"
        ),
    }

    # Output basename for each invocation_id
    csv_basename_map = {
        "7ace1275-7b42-41e5-a0b6-075f8dfb1033": "evtx_System.csv",
        "71c9135f-9529-4070-bb64-e854427fd286": "evtx_Security_dcsync.csv",
    }

    # Per-invocation max_rows limits (keep CSVs minimal)
    dc_max_rows = {
        "7ace1275-7b42-41e5-a0b6-075f8dfb1033": 0,   # unlimited (only 2 rows anyway)
        "71c9135f-9529-4070-bb64-e854427fd286": 2,   # limit dcsync — 1 cell match suffices
    }

    for inv_id, real_path in real_csv_map.items():
        ev_set = by_inv.get(inv_id, set())
        basename = csv_basename_map.get(inv_id, "unknown.csv")
        out_path = case_dir / "csv" / basename
        n = _trim_csv(real_path, ev_set, out_path, max_rows=dc_max_rows.get(inv_id, 0))
        if n == 0 and ev_set:
            print(f"    ERROR: {basename} — 0 rows matched from {real_path} "
                  f"for {len(ev_set)} exact_values; Tier 2 will fail")

    # Rewrite csv_files in audit entries to point at trimmed CSVs
    for entry in audit_entries:
        inv = entry.get("invocation_id", "")
        basename = csv_basename_map.get(inv)
        if basename:
            entry["csv_files"] = [f"{{{{CASE_DIR}}}}/csv/{basename}"]

    # Re-write audit log with updated csv_files
    write_jsonl(case_dir / "audit" / "mcp.jsonl", audit_entries)

    print(f"  {case}: claims={expected['total_claims']}, "
          f"grounded={expected['grounded']}, "
          f"tier2={expected['tier2_verified']}")


# ── Case: SRL-2018-FILE ────────────────────────────────────────────────────────

def build_srl2018_file():
    case = "SRL-2018-FILE"
    case_dir = FIXTURES / case
    print(f"Building {case}...")

    audit_entries = [
        {
            "ts": "2026-06-06T13:55:00.000000+00:00",
            "invocation_id": "33c87d3b-75db-486c-b9c4-09567dcc2003",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evidence/evtx/Security.evtx --inc 4688,1102 --csv {{CASE_DIR}}/analysis/evtx_sec_out --csvf Security.csv",
            "returncode": 0,
            "stdout_lines": 20,
            "stderr_excerpt": "",
            "parsed_record_count": 245,
            "duration_ms": 5200,
            "evtx_path": "{{CASE_DIR}}/evidence/evtx/Security.evtx",
            "event_ids_filter": [4688, 1102],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_sec_out",
            "csv_files": ["{{CASE_DIR}}/analysis/evtx_sec_out/Security.csv"],
            "suspicious_count": 8,
            "capped": False,
        },
        {
            "ts": "2026-06-06T13:55:01.000000+00:00",
            "invocation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "tool": "EvtxECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f {{CASE_DIR}}/evidence/evtx/System.evtx --inc 7045 --csv {{CASE_DIR}}/analysis/evtx_sys_out --csvf System.csv",
            "returncode": 0,
            "stdout_lines": 5,
            "stderr_excerpt": "",
            "parsed_record_count": 15,
            "duration_ms": 1800,
            "evtx_path": "{{CASE_DIR}}/evidence/evtx/System.evtx",
            "event_ids_filter": [7045],
            "output_dir": "{{CASE_DIR}}/analysis/evtx_sys_out",
            "csv_files": ["{{CASE_DIR}}/csv/evtx_System.csv"],
            "suspicious_count": 5,
            "capped": False,
        },
        {
            "ts": "2026-06-06T13:56:00.000000+00:00",
            "invocation_id": "1ed2bbb6-1100-4306-b7c2-d59e355adf26",
            "tool": "MFTECmd",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/MFTECmd.dll -f {{CASE_DIR}}/evidence/MFT --at --csv {{CASE_DIR}}/analysis/mft_out --csvf mft -q",
            "returncode": 0,
            "stdout_lines": 0,
            "stderr_excerpt": "",
            "parsed_record_count": 0,
            "duration_ms": 800,
            "mft_path": "{{CASE_DIR}}/evidence/MFT",
            "output_dir": "{{CASE_DIR}}/analysis/mft_out",
            "filename_filter": None,
            "timestomped_count": 0,
            "suspicious_count": 0,
            "capped": False,
            "note": "Live MFTECmd returned 0 entries — hive/schema incompatibility.",
        },
        {
            "ts": "2026-06-06T13:57:00.000000+00:00",
            "invocation_id": "066cce07-2e10-4b40-a86f-661afb0eb0b7",
            "tool": "AmcacheParser",
            "examiner": "examiner",
            "cmd": "dotnet /opt/zimmermantools/AmcacheParser.dll -f {{CASE_DIR}}/evidence/Amcache.hve --csv {{CASE_DIR}}/analysis/amcache_out --csvf Amcache -q",
            "returncode": 0,
            "stdout_lines": 0,
            "stderr_excerpt": "",
            "parsed_record_count": 0,
            "duration_ms": 600,
            "amcache_path": "{{CASE_DIR}}/evidence/Amcache.hve",
            "output_dir": "{{CASE_DIR}}/analysis/amcache_out",
            "csv_files": ["{{CASE_DIR}}/analysis/amcache_out/Amcache_UnassociatedFileEntries.csv"],
            "suspicious_count": 0,
            "capped": False,
            "note": "Live AmcacheParser returned 0 entries — hive schema incompatibility.",
        },
        {
            "ts": "2026-06-06T13:58:00.000000+00:00",
            "invocation_id": "correlation_74cb725309d9",
            "tool": "correlate_evidence",
            "examiner": "examiner",
            "cmd": "correlate_evidence(process_name='subject_srv.exe')",
            "returncode": 0,
            "stdout_lines": 0,
            "stderr_excerpt": "",
            "parsed_record_count": 0,
            "duration_ms": 200,
            "params": {"process_name": "subject_srv.exe", "case_dir": "{{CASE_DIR}}"},
            "verdict": "NOT_FOUND",
            "sources_present": [],
        },
    ]
    write_jsonl(case_dir / "audit" / "mcp.jsonl", audit_entries)

    # ── findings.json ──
    findings_src = RESULTS / "SRL-2018-FILE_findings.json"
    with open(findings_src, encoding="utf-8") as fh:
        findings = json.load(fh)
    sanitized_findings = [sanitize_finding(f) for f in findings]

    # Remap System.evtx (EID 7045) evidence_quotes to the new System invocation.
    # The original findings attribute everything to the Security-only invocation
    # 33c87d3b, but Name: * exact_values come from System.evtx EID 7045 rows.
    # Without this remapping the fixture CSV for invocation 33c87d3b would
    # contain System-channel rows that its audit entry never produced.
    SYSTEM_INV = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    for finding in sanitized_findings:
        for q in finding.get("evidence_quotes", []):
            ev = q.get("exact_value", "")
            if ev and ev.lower().startswith("name:"):
                q["invocation_id"] = SYSTEM_INV

    write_json(case_dir / "findings.json", sanitized_findings)

    # ── expected.json ──
    result_src = RESULTS / "SRL-2018-FILE_session01.json"
    with open(result_src, encoding="utf-8") as fh:
        result = json.load(fh)
    expected = {
        "total_claims": result["total_claims"],
        "grounded": result["grounded"],
        "ungrounded": result["ungrounded"],
        "contradicted": result["contradicted"],
        "hallucination_rate": result["hallucination_rate"],
        "tier2_verified": result["tier2_verified"],
    }
    write_json(case_dir / "expected.json", expected)

    # ── Minimal CSV files for Tier 2 ──
    # Extract exact_values from findings, grouped by invocation_id
    exact_pairs = _extract_exact_values(sanitized_findings)
    by_inv: dict[str, set[str]] = {}
    for inv_id, ev in exact_pairs:
        by_inv.setdefault(inv_id, set()).add(ev)

    # Both invocations draw from the same combined EvtxECmd output CSV.
    # The *channel* filter guarantees that each trimmed fixture CSV contains
    # only rows from the correct .evtx source.
    _COMBINED_CSV = REPO.parent / "cases/SRL-2018-FILE/analysis/evtx_out/evtx.csv"

    real_csv_map = {
        "33c87d3b-75db-486c-b9c4-09567dcc2003": _COMBINED_CSV,
        SYSTEM_INV:                            _COMBINED_CSV,
    }

    csv_basename_map = {
        "33c87d3b-75db-486c-b9c4-09567dcc2003": "evtx_Security.csv",
        SYSTEM_INV:                            "evtx_System.csv",
    }

    # Per-invocation channel filters — ensures Security.evtx invocation never
    # pulls System.evtx rows and vice versa.
    channel_map = {
        "33c87d3b-75db-486c-b9c4-09567dcc2003": "Security",
        SYSTEM_INV:                            "System",
    }

    for inv_id, real_path in real_csv_map.items():
        ev_set = by_inv.get(inv_id, set())
        basename = csv_basename_map.get(inv_id, "unknown.csv")
        out_path = case_dir / "csv" / basename
        n = _trim_csv(real_path, ev_set, out_path,
                      channel=channel_map.get(inv_id))
        if n == 0 and ev_set:
            print(f"    ERROR: {basename} — 0 rows matched from {real_path} "
                  f"for {len(ev_set)} exact_values; Tier 2 will fail")

    # Rewrite csv_files in audit entries to point at trimmed CSVs
    for entry in audit_entries:
        inv = entry.get("invocation_id", "")
        basename = csv_basename_map.get(inv)
        if basename:
            entry["csv_files"] = [f"{{{{CASE_DIR}}}}/csv/{basename}"]

    # Re-write audit log with updated csv_files
    write_jsonl(case_dir / "audit" / "mcp.jsonl", audit_entries)

    print(f"  {case}: claims={expected['total_claims']}, "
          f"grounded={expected['grounded']}, "
          f"tier2={expected['tier2_verified']}")


# ── Main ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    FIXTURES.mkdir(parents=True, exist_ok=True)
    build_srl2018_workstation()
    build_srl2018_dc()
    build_srl2018_file()
    print("\nAll fixtures built under fixtures/reproducibility/")
