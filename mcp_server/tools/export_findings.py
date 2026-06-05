"""
export_findings — MCP tool for exporting CaseFile findings in SIEM-compatible formats.

Supported formats:
  ecs   — Elastic Common Schema v8.x
  ocsf  — Open Cybersecurity Schema Framework v1.3 (Finding class)

Usage (via MCP):
  export_findings(format="ecs", status_filter="APPROVED")
  export_findings(format="ocsf", status_filter=None)
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from mcp_server.tools._shared import audit_log

# ---------------------------------------------------------------------------
# ATT&CK database — loaded once at module level
# ---------------------------------------------------------------------------

_ATTACK_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "attack_v15.json"
_ATTACK_DB: dict = {}
if _ATTACK_PATH.exists():
    try:
        _ATTACK_DB = json.loads(_ATTACK_PATH.read_text())
    except Exception:
        pass

# ---------------------------------------------------------------------------
# ECS field mapping
# ---------------------------------------------------------------------------

_ECS_SEVERITY_MAP = {
    "CRITICAL": 99,
    "HIGH": 73,
    "MEDIUM": 47,
    "LOW": 21,
    "INFORMATIONAL": 1,
}


def _finding_to_ecs(finding: dict, case_id: str) -> dict:
    """Convert a CaseFile finding to ECS v8 Finding event."""
    now = datetime.now(timezone.utc).isoformat()
    confidence = finding.get("confidence", "MEDIUM").upper()
    severity_label = finding.get("severity", "MEDIUM").upper()
    mitre_ids = finding.get("mitre_ids", [])

    event: dict = {
        "@timestamp": finding.get("timestamp", now),
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "finding",
            "category": ["threat"],
            "type": ["indicator"],
            "id": finding.get("finding_id", str(uuid.uuid4())),
            "created": finding.get("created_at", now),
            "dataset": "casefile.findings",
            "module": "casefile",
            "provider": "CaseFile",
            "severity": _ECS_SEVERITY_MAP.get(severity_label, 47),
            "risk_score": _ECS_SEVERITY_MAP.get(severity_label, 47),
            "url": f"https://github.com/nurusyda/casefile",
        },
        "message": finding.get("observation", ""),
        "labels": {
            "case_id": case_id,
            "provenance": finding.get("provenance", "UNKNOWN"),
            "status": finding.get("status", "DRAFT"),
            "confidence": confidence,
        },
        "tags": ["casefile", "dfir"],
        "finding": {
            "title": finding.get("title", ""),
            "description": finding.get("interpretation", ""),
            "type": "threat",
            "severity": {
                "code": _ECS_SEVERITY_MAP.get(severity_label, 47),
                "name": severity_label,
            },
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": [
                {"id": t, "name": _ATTACK_DB.get(t, {}).get("name", t)}
                for t in mitre_ids
                if not (t.count(".") > 0)
            ],
            "subtechnique": [
                {"id": t, "name": _ATTACK_DB.get(t, {}).get("name", t)}
                for t in mitre_ids
                if t.count(".") > 0
            ],
        },
        "observer": {
            "product": "CaseFile",
            "vendor": "CaseFile DFIR",
            "version": "1.0.0",
        },
        "related": {
            "hosts": [case_id],
        },
    }

    # IOCs
    iocs = finding.get("iocs", [])
    if iocs:
        event["indicator"] = {"type": "unknown", "description": "; ".join(iocs)}

    # Audit trail link — use labels namespace, not event.original (ECS schema compliance)
    inv_ids = finding.get("supporting_invocation_ids", [])
    if inv_ids:
        event["labels"]["supporting_invocations"] = json.dumps(inv_ids)

    return event


# ---------------------------------------------------------------------------
# OCSF field mapping (Finding class — class_uid 2004)
# ---------------------------------------------------------------------------

_OCSF_SEVERITY_MAP = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1,
    "UNKNOWN": 0,
}

_OCSF_STATUS_MAP = {
    "APPROVED": 1,   # New
    "DRAFT": 0,      # Unknown
    "REJECTED": 99,  # Other
}


def _iso_to_ms(iso_str: str) -> int:
    """Convert ISO 8601 string to epoch milliseconds, fallback to now."""
    try:
        return int(datetime.fromisoformat(iso_str).timestamp() * 1000)
    except Exception:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _finding_to_ocsf(finding: dict, case_id: str) -> dict:
    """Convert a CaseFile finding to OCSF v1.3 Finding (class_uid=2004)."""
    observation_ms = _iso_to_ms(finding.get("timestamp") or "")
    created_ms = _iso_to_ms(finding.get("created_at") or "") or observation_ms
    ts_ms = observation_ms

    severity_label = finding.get("severity", "MEDIUM").upper()
    mitre_ids = finding.get("mitre_ids", [])
    status = finding.get("status", "DRAFT").upper()
    uid = finding.get("finding_id") or str(uuid.uuid4())

    event: dict = {
        "class_uid": 2004,
        "class_name": "Security Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "type_name": "Security Finding: Create",
        "time": ts_ms,
        "severity_id": _OCSF_SEVERITY_MAP.get(severity_label, 0),
        "severity": severity_label.capitalize(),
        "status_id": _OCSF_STATUS_MAP.get(status, 0),
        "status": status.capitalize(),
        "message": finding.get("observation", ""),
        "metadata": {
            "version": "1.3.0",
            "product": {
                "name": "CaseFile",
                "vendor_name": "CaseFile DFIR",
                "version": "1.0.0",
                "url_string": "https://github.com/nurusyda/casefile",
            },
            "profiles": ["security_control"],
            "uid": uid,
        },
        "finding": {
            "title": finding.get("title", ""),
            "desc": finding.get("interpretation", ""),
            "uid": uid,
            "created_time": created_ms,
            "src_url": "https://github.com/nurusyda/casefile",
            "supporting_data": {
                "provenance": finding.get("provenance", "UNKNOWN"),
                "confidence": finding.get("confidence", "MEDIUM"),
                "case_id": case_id,
                "supporting_invocation_ids": finding.get("supporting_invocation_ids", []),
            },
        },
        "remediation": {
            "desc": finding.get("context", ""),
        },
    }

    # ATT&CK techniques → OCSF attack object
    if mitre_ids:
        event["attacks"] = [
            {
                "technique": {
                    "uid": t,
                    "name": _ATTACK_DB.get(t, {}).get("name", t),
                    "src_url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/",
                },
                "tactics": [
                    {"name": tac.replace("-", " ").title()}
                    for tac in _ATTACK_DB.get(t, {}).get("tactics", [])
                ],
                "version": "15",
            }
            for t in mitre_ids
        ]

    # IOCs → observable array
    iocs = finding.get("iocs", [])
    if iocs:
        event["observables"] = [
            {"name": ioc, "type_id": 0, "type": "Other"}
            for ioc in iocs
        ]

    return event


# ---------------------------------------------------------------------------
# MCP tool entrypoint
# ---------------------------------------------------------------------------

def export_findings(
    format: Literal["ecs", "ocsf"] = "ecs",
    status_filter: str | None = "APPROVED",
    output_path: str | None = None,
    invocation_id: str | None = None,
) -> dict:
    """
    Export CaseFile findings in SIEM-compatible format.

    Args:
        format: Output format — "ecs" (Elastic Common Schema v8) or
                "ocsf" (Open Cybersecurity Schema Framework v1.3).
        status_filter: Only export findings with this status. Pass None to
                       export all findings. Default: "APPROVED".
        output_path: Optional path to write the export JSON. If not given,
                     writes to <case_dir>/exports/findings_<format>.json.

    Returns:
        dict with keys: format, exported_count, output_path, events (list)
    """
    _start_time = time.monotonic()
    case_dir = Path(
        os.environ.get("CASEFILE_CASE_DIR") or os.path.expanduser("~/cases/active")
    )
    _evidence_root = Path("/mnt/evidence")
    if _evidence_root.exists() and case_dir.resolve().is_relative_to(_evidence_root.resolve()):
        return {
            "format": format,
            "exported_count": 0,
            "output_path": None,
            "events": [],
            "error": "Export denied: case directory is inside evidence path /mnt/evidence.",
        }
    _case_yaml = case_dir / "CASE.yaml"
    case_id = case_dir.name
    if _case_yaml.exists():
        try:
            import yaml as _yaml
            _meta = _yaml.safe_load(_case_yaml.read_text()) or {}
            case_id = _meta.get("case_id", case_dir.name)
        except ImportError:
            pass
        except Exception:
            pass

    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        return {
            "format": format,
            "exported_count": 0,
            "output_path": None,
            "events": [],
            "error": "findings.json not found in the case directory",
        }

    try:
        raw = json.loads(findings_path.read_text())
        findings = raw.get("findings", []) if isinstance(raw, dict) else raw
    except (json.JSONDecodeError, OSError) as e:
        return {
            "format": format,
            "exported_count": 0,
            "output_path": None,
            "events": [],
            "error": f"Cannot read findings.json: {e}",
        }

    # Apply status filter
    if status_filter:
        findings = [
            f for f in findings
            if isinstance(f, dict) and f.get("status", "").upper() == status_filter.upper()
        ]

    # Convert
    if format == "ecs":
        events = [_finding_to_ecs(f, case_id) for f in findings if isinstance(f, dict)]
    elif format == "ocsf":
        events = [_finding_to_ocsf(f, case_id) for f in findings if isinstance(f, dict)]
    else:
        return {
            "format": format,
            "exported_count": 0,
            "output_path": None,
            "events": [],
            "error": f"Unknown format '{format}'. Use 'ecs' or 'ocsf'.",
        }

    # Write output
    if output_path is None:
        export_dir = case_dir / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(export_dir / f"findings_{format}.json")
    else:
        resolved = Path(output_path).resolve()
        case_root = case_dir.resolve()
        if case_root not in resolved.parents and resolved != case_root:
            return {
                "format": format,
                "exported_count": 0,
                "output_path": None,
                "events": [],
                "error": f"output_path must be within case directory: {case_dir}",
            }

    try:
        Path(output_path).resolve().write_text(json.dumps(events, indent=2))
    except OSError as e:
        return {
            "format": format,
            "exported_count": len(events),
            "output_path": None,
            "events": events,
            "error": f"Could not write to {output_path}: {e}",
        }

    _duration_ms = int((time.monotonic() - _start_time) * 1000)
    audit_log(
        tool="export_findings",
        invocation_id=invocation_id or str(uuid.uuid4()),
        cmd=f"export_findings(format={format!r}, status_filter={status_filter!r})",
        returncode=0,
        stdout_lines=len(events),
        stderr_excerpt="",
        parsed_record_count=len(events),
        duration_ms=_duration_ms,
        extra={"output_path": output_path, "export_format": format},
    )

    try:
        _rel_path = str(Path(output_path).relative_to(case_dir))
    except ValueError:
        _rel_path = Path(output_path).name
    return {
        "format": format,
        "exported_count": len(events),
        "output_path": _rel_path,
        "events": events,
    }
