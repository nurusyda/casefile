"""
mcp_server/tools/findings.py — Investigation state machine for CaseFile.
"""
import hashlib
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
    "approve_finding",
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


def approve_finding(finding_id: str) -> dict:
    """Approve a DRAFT finding — HUMAN-ONLY gate.

    This function is intentionally excluded from the agent's callable tools
    via BLOCKED_COMMANDS. It must only be invoked by a human examiner.

    Looks up finding_id in findings.json, flips status DRAFT -> APPROVED,
    stamps approved_at / approved_by from CASEFILE_EXAMINER, computes a
    SHA-256 content hash for chain-of-custody, appends a record to
    approvals.jsonl, and writes an audit log entry on EVERY code path
    (success and failure) for full invocation traceability.

    Returns the updated finding record on success, or an error dict.
    """
    invocation_id = str(uuid.uuid4())
    examiner = _examiner()

    def _audit(returncode: int, error: str = "") -> None:
        audit_log(
            tool="approve_finding",
            invocation_id=invocation_id,
            cmd="approve_finding (in-process)",
            returncode=returncode,
            stdout_lines=0 if returncode != 0 else 1,
            stderr_excerpt=error[:500],
            parsed_record_count=0 if returncode != 0 else 1,
            duration_ms=0,
            extra={"finding_id": finding_id, "examiner": examiner},
        )

    case_dir = _case_dir()
    findings_file = case_dir / "findings.json"

    if not findings_file.exists():
        err = f"No findings file found. Finding {finding_id!r} does not exist."
        _audit(1, err)
        return {"error": err, "finding_id": finding_id}

    try:
        data: list = json.loads(findings_file.read_text(encoding="utf-8"))
    except Exception as exc:
        err = f"Failed to read findings.json: {exc}"
        _audit(1, err)
        return {"error": err, "finding_id": finding_id}

    match = next((f for f in data if f.get("id") == finding_id), None)
    if match is None:
        err = f"Finding {finding_id!r} not found."
        _audit(1, err)
        return {"error": err, "finding_id": finding_id}

    if match.get("status") == "APPROVED":
        err = f"Finding {finding_id!r} is already APPROVED."
        _audit(1, err)
        return {"error": err, "finding_id": finding_id, "record": match}

    if match.get("status") != "DRAFT":
        err = f"Finding {finding_id!r} has unexpected status {match.get('status')!r}. Expected DRAFT."
        _audit(1, err)
        return {"error": err, "finding_id": finding_id}

    now = datetime.now(timezone.utc).isoformat()
    match["status"] = "APPROVED"
    match["approved_at"] = now
    match["approved_by"] = examiner

    content_hash = hashlib.sha256(
        json.dumps(match, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    match["content_hash"] = content_hash

    _write_json(findings_file, data)

    approvals_file = case_dir / "approvals.jsonl"
    with approvals_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": now, "finding_id": finding_id, "approved_by": examiner, "content_hash": content_hash}) + "\n")

    _audit(0)

    return {
        "finding_id": finding_id,
        "status": "APPROVED",
        "approved_by": examiner,
        "approved_at": now,
        "content_hash": content_hash,
        "message": f"Finding {finding_id} approved by {examiner}.",
        "record": match,
    }
