#!/usr/bin/env python3
"""Generate docs/dataset.md from live case artifacts.

Reads:
  - ${CASEFILE_CASE_ROOT}/source.sha256
  - ${CASEFILE_CASE_ROOT}/findings.json
  - ${CASEFILE_CASE_ROOT}/audit/mcp.jsonl
  - ${CASEFILE_CASE_ROOT}/analysis/claim_accuracy_report.json  <- written by grounding_verify.py
  - reports/accuracy_report_SRL2018.json

Writes:
  - docs/dataset.md

Run after every ralph.sh:
  python3 scripts/generate_dataset_doc.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
REPORTS_DIR = REPO_ROOT / "reports"
ACCURACY_REPORT = REPORTS_DIR / "accuracy_report_SRL2018.json"

case_root_raw = os.environ.get("CASEFILE_CASE_ROOT", os.path.expanduser("~/cases/SRL-2018"))
CASE_ROOT = Path(case_root_raw).resolve()
if not CASE_ROOT.exists():
    raise SystemExit(f"Invalid CASEFILE_CASE_ROOT: {case_root_raw}")

SOURCE_SHA256 = CASE_ROOT / "source.sha256"
FINDINGS_JSON = CASE_ROOT / "findings.json"
AUDIT_JSONL = CASE_ROOT / "audit" / "mcp.jsonl"
# grounding_verify.py writes to analysis/, not audit/
CLAIM_ACCURACY = CASE_ROOT / "analysis" / "claim_accuracy_report.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        print(f"[!] JSON parse error in {path}: {exc}", file=sys.stderr)
        return None


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def _sha256_line(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "not computed"


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def collect_evidence_provenance() -> dict:
    sha_line = _sha256_line(SOURCE_SHA256)
    parts = sha_line.split(None, 1)
    return {
        "sha256": parts[0] if parts else "unknown",
        "filename": parts[1].strip() if len(parts) > 1 else "unknown",
        "case_root": str(CASE_ROOT),
    }


def collect_finding_stats() -> dict:
    data = _read_json(FINDINGS_JSON)
    if not data:
        return {}
    findings = data if isinstance(data, list) else data.get("findings", [])
    counts: Counter = Counter()
    source_counts: Counter = Counter()
    for f in findings:
        level = f.get("confidence_level") or f.get("confidence", "UNKNOWN")
        counts[level] += 1
        for src in f.get("sources", []):
            source_counts[src] += 1
    return {
        "total": len(findings),
        "by_confidence": dict(counts),
        "by_source": dict(source_counts),
    }


def collect_audit_stats() -> dict:
    records = _read_jsonl(AUDIT_JSONL)
    if not records:
        return {}
    tool_counts: Counter = Counter()
    total_records = 0
    total_ms = 0
    for r in records:
        tool = r.get("tool", "unknown")
        tool_counts[tool] += 1
        total_records += r.get("parsed_record_count", 0) or 0
        total_ms += r.get("duration_ms", 0) or 0
    return {
        "total_invocations": len(records),
        "by_tool": dict(tool_counts),
        "total_parsed_records": total_records,
        "total_duration_ms": total_ms,
    }


def collect_grounding_stats() -> dict:
    """Read analysis/claim_accuracy_report.json written by grounding_verify.py."""
    data = _read_json(CLAIM_ACCURACY)
    if not data:
        return {}
    return {
        "total_claims": data.get("total_claims", 0),
        "grounded": data.get("grounded", 0),
        "ungrounded": data.get("ungrounded", 0),
        "contradicted": data.get("contradicted", 0),
        "hallucination_rate": data.get("hallucination_rate", 0.0),
        "tier2_verified": data.get("tier2_verified", 0),
        "tier2_failed": data.get("tier2_failed", 0),
        "generated_at": data.get("generated_at", "unknown"),
    }


def collect_checkpoint_stats() -> dict:
    data = _read_json(ACCURACY_REPORT)
    if not data:
        return {}
    checkpoints = data.get("checkpoints", [])
    passed = sum(1 for c in checkpoints if c.get("casefile_result") == "PASS")
    baseline = sum(1 for c in checkpoints if c.get("baseline_result") == "PASS")
    return {
        "total": len(checkpoints),
        "casefile_pass": passed,
        "baseline_pass": baseline,
        "checkpoints": checkpoints,
        "report_date": data.get("generated_at", data.get("date", "unknown")),
    }


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_markdown(
    prov: dict,
    findings: dict,
    audit: dict,
    grounding: dict,
    checkpoints: dict,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# CaseFile -- Dataset Documentation",
        "",
        f"*Auto-generated {now} by `scripts/generate_dataset_doc.py`.*",
        "*Do not edit manually -- re-run after each ralph.sh investigation.*",
        "",
        "---",
        "",
        "## 1. Evidence Dataset",
        "",
        "### Source Image",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Case | CRIMSON OSPREY (SRL-2018, BASE-RD-01) |",
        f"| File | `{prov.get('filename', 'unknown')}` |",
        f"| SHA-256 | `{prov.get('sha256', 'not computed')}` |",
        f"| Case root | `{prov.get('case_root', 'unknown')}` |",
        "| Source | SANS FOR508 SRL-2018 (real forensic challenge image) |",
        "",
        "### Evidence Provenance",
        "",
        "The source disk image is a forensically acquired Windows system from the",
        "SANS FOR508 SRL-2018 challenge dataset. Chain of custody is maintained by:",
        "",
        "- SHA-256 hash verified at ingest (`scripts/ingest.sh`)",
        "- All analysis performed on extracted copies in `analysis/`, never the original",
        "- Evidence directory is write-blocked via `.claude/settings.json` deny rules",
        "- Every tool invocation recorded to `audit/mcp.jsonl` with timestamps",
        "",
        "---",
        "",
        "## 2. Artifact Inventory",
        "",
        "Artifacts extracted from the disk image by `scripts/ingest.sh`:",
        "",
        "| Artifact | Tool Used | Format |",
        "|---|---|---|",
        "| Windows Registry hives (SYSTEM, SOFTWARE, SECURITY, SAM) | RECmd (EZ Tools) | CSV |",
        "| Amcache.hve + transaction logs | RECmd (EZ Tools) | CSV |",
        "| Prefetch files (`*.pf`) | pyscca library | Parsed JSON |",
        "| Windows Event Logs (`*.evtx`) | EvtxECmd (EZ Tools) | CSV |",
        "| Master File Table (`$MFT`) | MFTECmd (EZ Tools) | CSV |",
        "| Memory image (`*.img`) | Volatility 3 | JSON per plugin |",
        "",
        "---",
        "",
        "## 3. Investigation Results",
        "",
    ]

    if findings:
        total = findings.get("total", 0)
        by_conf = findings.get("by_confidence", {})
        confirmed = by_conf.get("CONFIRMED", 0)
        inferred = by_conf.get("INFERRED", 0)
        speculative = by_conf.get("SPECULATIVE", 0)

        lines += [
            "### Findings Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Total findings recorded | {total} |",
            f"| CONFIRMED (multi-source corroboration) | {confirmed} |",
            f"| INFERRED (single-source) | {inferred} |",
            f"| SPECULATIVE | {speculative} |",
            "",
        ]

        if findings.get("by_source"):
            lines += [
                "### Findings by Source Artifact",
                "",
                "| Source | Finding Count |",
                "|---|---|",
            ]
            for src, count in sorted(
                findings["by_source"].items(), key=lambda x: -x[1]
            ):
                lines.append(f"| {src} | {count} |")
            lines.append("")
    else:
        lines += ["*No findings.json found -- run ralph.sh to investigate.*", ""]

    lines += [
        "---",
        "",
        "## 4. Grounding & Hallucination Metrics",
        "",
    ]

    if grounding:
        total_claims = grounding.get("total_claims", 0)
        grounded = grounding.get("grounded", 0)
        ungrounded = grounding.get("ungrounded", 0)
        contradicted = grounding.get("contradicted", 0)
        hallu_rate = grounding.get("hallucination_rate", 0.0)
        t2_verified = grounding.get("tier2_verified", 0)
        t2_failed = grounding.get("tier2_failed", 0)
        as_of = grounding.get("generated_at", "unknown")

        lines += [
            f"*As of: {as_of}*",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Total claims analyzed | {total_claims} |",
            f"| Tier 1 grounded (tool-attested) | {grounded} |",
            f"| Ungrounded | {ungrounded} |",
            f"| Contradicted (value mismatch) | {contradicted} |",
            f"| **Hallucination rate** | **{hallu_rate:.1%}** |",
            f"| Tier 2 verified (CSV value confirmed) | {t2_verified} |",
            f"| Tier 2 failed | {t2_failed} |",
            "",
            "**Tier 1** -- every claim must be traceable to a specific tool invocation",
            "ID in `audit/mcp.jsonl`.",
            "",
            "**Tier 2** -- opens the actual CSV output and confirms the exact value",
            "cited in the claim exists in the data. Fires when `csv_files` is present",
            "in the audit entry (Amcache, Registry, Event Logs, MFT).",
            "",
        ]
    else:
        lines += [
            "*`analysis/claim_accuracy_report.json` not yet generated.*",
            "*Run `ralph.sh` -- `scripts/grounding_verify.py` writes this at completion.*",
            "",
        ]

    lines += [
        "---",
        "",
        "## 5. Accuracy Benchmarks (CFA-Bench Methodology)",
        "",
    ]

    if checkpoints:
        cp_total = checkpoints.get("total", 0)
        cf_pass = checkpoints.get("casefile_pass", 0)
        bl_pass = checkpoints.get("baseline_pass", 0)
        report_date = checkpoints.get("report_date", "unknown")

        lines += [
            f"*Accuracy report dated: {report_date}*",
            "",
            "| System | Checkpoints Passed | Score |",
            "|---|---|---|",
            f"| **CaseFile** | {cf_pass} / {cp_total} | **{(cf_pass/cp_total):.0%}** |" if cp_total else f"| **CaseFile** | {cf_pass} / {cp_total} | **N/A** |",
            f"| Protocol SIFT (baseline) | {bl_pass} / {cp_total} | {(bl_pass/cp_total):.0%} |" if cp_total else f"| Protocol SIFT (baseline) | {bl_pass} / {cp_total} | N/A |",
            "",
            "### Checkpoint Detail",
            "",
            "| # | Checkpoint | CaseFile | Baseline |",
            "|---|---|---|---|",
        ]
        for i, cp in enumerate(checkpoints.get("checkpoints", []), 1):
            desc = cp.get("description", cp.get("name", f"CP{i}"))
            cf = "PASS" if cp.get("casefile_result") == "PASS" else "FAIL"
            bl = "PASS" if cp.get("baseline_result") == "PASS" else "FAIL"
            lines.append(f"| {i} | {desc} | {cf} | {bl} |")
        lines.append("")
    else:
        lines += ["*`reports/accuracy_report_SRL2018.json` not found.*", ""]

    lines += [
        "---",
        "",
        "## 6. Tool Invocation Statistics",
        "",
    ]

    if audit:
        total_inv = audit.get("total_invocations", 0)
        total_parsed = audit.get("total_parsed_records", 0)
        total_ms = audit.get("total_duration_ms", 0)

        lines += [
            "| Metric | Value |",
            "|---|---|",
            f"| Total MCP tool invocations | {total_inv:,} |",
            f"| Total artifact records parsed | {total_parsed:,} |",
            f"| Total analysis time | {total_ms / 1000:.1f}s |",
            "",
            "### Invocations by Tool",
            "",
            "| Tool | Invocations |",
            "|---|---|",
        ]
        for tool, count in sorted(
            audit.get("by_tool", {}).items(), key=lambda x: -x[1]
        ):
            lines.append(f"| `{tool}` | {count} |")
        lines.append("")
    else:
        lines += ["*`audit/mcp.jsonl` not found -- run ralph.sh to populate.*", ""]

    lines += [
        "---",
        "",
        "## 7. Known Attacker TTPs Found",
        "",
        "| TTP | ATT&CK ID | Evidence Sources |",
        "|---|---|---|",
        "| Masquerading -- fake CSRSS.EXE in Temp\\\\Perfmon | T1036.005 | Amcache, MFT, Memory |",
        "| Fake signed Microsoft services (msadvapi2_*.exe) | T1036.004 | Amcache |",
        "| Credential dumping via procdump.exe | T1003.001 | Prefetch, Amcache, MFT |",
        "| Timestomping (SI creation date < FN creation date) | T1070.006 | MFT SI<FN flag |",
        "| Log clearing (wevtutil cl) | T1070.001 | Prefetch |",
        "| Secure deletion (sdelete64) | T1070.004 | Amcache, Prefetch |",
        "| C2 beaconing 172.16.6.12:445 every 12 min | T1071.002 | Memory netscan |",
        "| Lateral movement via Dashlane cover path | T1021 | Prefetch (tdungan path) |",
        "| Hex-named Cobalt Strike payload | T1027 | Amcache (40-char hex filename) |",
        "",
        "---",
        "",
        "## 8. Reproducibility",
        "",
        "```bash",
        "# 1. Extract artifacts from E01 disk image",
        "bash scripts/ingest.sh /path/to/base-rd-01-cdrive.E01 SRL-2018",
        "",
        "# 2. Set environment",
        "export CASEFILE_CASE_ROOT=~/cases/SRL-2018",
        "export CASEFILE_CASE_DIR=~/cases/SRL-2018",
        "export CASEFILE_EXAMINER=sansproject",
        "",
        "# 3. Run autonomous investigation",
        "bash ralph.sh ~/cases/SRL-2018 2>&1 | tee /tmp/ralph_run.log",
        "",
        "# 4. Regenerate this document",
        "python3 scripts/generate_dataset_doc.py",
        "```",
        "",
        "Expected runtime: 45-90 minutes depending on image size and memory analysis.",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(f"[*] Reading case artifacts from: {CASE_ROOT}")

    prov = collect_evidence_provenance()
    findings = collect_finding_stats()
    audit = collect_audit_stats()
    grounding = collect_grounding_stats()
    checkpoints = collect_checkpoint_stats()

    if not grounding:
        print(
            f"[!] No claim_accuracy_report.json at:\n"
            f"    {CLAIM_ACCURACY}\n"
            f"    Run ralph.sh first -- grounding_verify.py writes this at completion.",
            file=sys.stderr,
        )

    md = render_markdown(prov, findings, audit, grounding, checkpoints)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    out = DOCS_DIR / "dataset.md"
    out.write_text(md, encoding="utf-8")

    print(f"[+] Written: {out}")
    print(f"    Findings: {findings.get('total', 0)} total, "
          f"{findings.get('by_confidence', {}).get('CONFIRMED', 0)} CONFIRMED")
    print(f"    Claims:   {grounding.get('total_claims', 0)} total, "
          f"hallucination_rate={grounding.get('hallucination_rate', 0):.1%}")
    print(f"    Audit:    {audit.get('total_invocations', 0)} tool invocations, "
          f"{audit.get('total_parsed_records', 0):,} records parsed")
    print(f"    Checkpoints: {checkpoints.get('casefile_pass', 0)}/{checkpoints.get('total', 0)} passed")

    return 0


if __name__ == "__main__":
    sys.exit(main())
