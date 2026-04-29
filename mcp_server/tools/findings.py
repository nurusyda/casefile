"""
mcp_server/tools/findings.py — Investigation state machine for CaseFile.
"""
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mcp_server.tools._shared import audit_log

BLOCKED_COMMANDS = frozenset({
    "rm", "rmdir", "dd", "mkfs", "format", "shred", "wipe",
    "chmod", "chown", "mv", "truncate", "fdisk", "parted",
    "approve",
})


def _case_dir() -> Path:
    raw = os.environ.get("CASEFILE_CASE_DIR", str(Path.home() / "cases" / "active"))
    p = Path(raw).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _examiner() -> str:
    return os.environ.get("CASEFILE_EXAMINER", "casefile")


def _next_finding_id(case_dir: Path) -> str:
    findings_file = case_dir / "findings.json"
    if findings_file.exists():
        try:
            data = json.loads(findings_file.read_text(encoding="utf-8"))
            n = len(data) + 1
        except Exception:
            n = 1
    else:
        n = 1
    return f"F-{_examiner()}-{n:03d}"


def _next_timeline_id(case_dir: Path) -> str:
    tl_file = case_dir / "timeline.json"
    if tl_file.exists():
        try:
            data = json.loads(tl_file.read_text(encoding="utf-8"))
            n = len(data) + 1
        except Exception:
            n = 1
    else:
        n = 1
    return f"T-{_examiner()}-{n:03d}"


def _write_json(path: Path, data: list) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def record_finding(
    title: str,
    observation: str,
    interpretation: str,
    confidence: str,
    artifact_source: str,
    supporting_tool: str,
    mitre_technique: Optional[str] = None,
) -> dict:
    """Stage a forensic finding as DRAFT."""
    if confidence not in ("CONFIRMED", "INFERRED"):
        confidence = "INFERRED"

    case_dir = _case_dir()
    findings_file = case_dir / "findings.json"
    findings: list = []
    if findings_file.exists():
        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            findings = []

    finding_id = _next_finding_id(case_dir)
    invocation_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "id": finding_id,
        "status": "DRAFT",
        "title": title,
        "observation": observation,
        "interpretation": interpretation,
        "confidence": confidence,
        "artifact_source": artifact_source,
        "supporting_tool": supporting_tool,
        "mitre_technique": mitre_technique,
        "examiner": _examiner(),
        "created_at": now,
        "approved_at": None,
        "approved_by": None,
    }

    findings.append(record)
    _write_json(findings_file, findings)

    audit_log(
        tool="record_finding",
        invocation_id=invocation_id,
        cmd="record_finding (in-process)",
        returncode=0,
        stdout_lines=1,
        stderr_excerpt="",
        parsed_record_count=1,
        duration_ms=0,
        extra={
            "finding_id": finding_id,
            "status": "DRAFT",
            "confidence": confidence,
            "examiner": _examiner(),
        },
    )

    return {
        "finding_id": finding_id,
        "status": "DRAFT",
        "message": f"Finding staged as DRAFT. Run `casefile approve {finding_id}` to approve.",
        "record": record,
    }


def get_findings(
    status: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """Retrieve staged findings from the active case."""
    case_dir = _case_dir()
    findings_file = case_dir / "findings.json"
    findings: list = []
    if findings_file.exists():
        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            findings = []

    if status:
        filtered = [f for f in findings if f.get("status") == status.upper()]
    else:
        filtered = findings

    total_draft = sum(1 for f in findings if f.get("status") == "DRAFT")
    total_approved = sum(1 for f in findings if f.get("status") == "APPROVED")

    return {
        "total": len(findings),
        "total_draft": total_draft,
        "total_approved": total_approved,
        "returned": min(len(filtered), limit),
        "findings": filtered[:limit],
    }


def record_timeline_event(
    timestamp: str,
    description: str,
    artifact_source: str,
    event_type: str,
    supporting_tool: str,
    confidence: Optional[str] = "CONFIRMED",
) -> dict:
    """Stage a timeline event as DRAFT."""
    if confidence not in ("CONFIRMED", "INFERRED"):
        confidence = "INFERRED"

    case_dir = _case_dir()
    tl_file = case_dir / "timeline.json"
    events: list = []
    if tl_file.exists():
        try:
            events = json.loads(tl_file.read_text(encoding="utf-8"))
        except Exception:
            events = []

    event_id = _next_timeline_id(case_dir)
    invocation_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "id": event_id,
        "status": "DRAFT",
        "timestamp": timestamp,
        "description": description,
        "artifact_source": artifact_source,
        "event_type": event_type,
        "supporting_tool": supporting_tool,
        "confidence": confidence,
        "examiner": _examiner(),
        "created_at": now,
    }

    events.append(record)
    _write_json(tl_file, events)

    audit_log(
        tool="record_timeline_event",
        invocation_id=invocation_id,
        cmd="record_timeline_event (in-process)",
        returncode=0,
        stdout_lines=1,
        stderr_excerpt="",
        parsed_record_count=1,
        duration_ms=0,
        extra={
            "finding_id": event_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "examiner": _examiner(),
        },
    )

    return {
        "event_id": event_id,
        "status": "DRAFT",
        "message": f"Timeline event staged as DRAFT. Run `casefile approve {event_id}` to approve.",
        "record": record,
    }
