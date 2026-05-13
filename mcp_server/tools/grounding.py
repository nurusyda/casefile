"""
mcp_server/tools/grounding.py
==============================
Block 10 — Anti-Hallucination Grounding Infrastructure (Phase 1, P0)

Verified against live repo on 2026-05-13:
  - audit_log() stores: ts, invocation_id, tool, examiner, cmd, returncode,
    stdout_lines, stderr_excerpt, parsed_record_count, duration_ms, + extra fields
  - correlate_evidence extra: params.{process_name,case_dir}, sources_present, verdict
  - amcache extra: amcache_path, output_dir, csv_files, suspicious_count, capped
  - record_finding() stores record with keys: id, status, title, observation,
    interpretation, confidence ("CONFIRMED"/"INFERRED"), artifact_source,
    supporting_tool, mitre_technique, examiner, created_at, approved_at, approved_by
  - record_finding() RETURNS dict with top-level key "finding_id" (not "id")

IMPORTANT — what the audit log can and cannot prove:
  CAN prove: a tool was called (invocation_id present), which sources were
    present (sources_present list), verdict reached, suspicious_count,
    parsed_record_count, csv_files paths
  CANNOT prove: specific field values inside parsed records (paths, PIDs,
    hashes) — those live in CSV files referenced by csv_files in the entry

Phase 1 (this file) implements:
  1. validate_evidence_quotes()    — schema check before record_finding()
  2. verify_finding_claims()       — Tier 1: invocation attestation + metadata
  3. get_attested_sources()        — set of tool names with audit entries
  4. assert_sources_attested()     — detects findings citing uncalled tools
  5. detect_baseline_assumptions() — training-data contamination guard
  6. build_claim_accuracy_report() — aggregate accuracy report helper

Phase 2 (future): Tier 2 value verification — read csv_files from the audit
  entry and verify exact field values against parsed CSV content.

Design principles (must not violate):
  - No LLM in the verification path. Every function here is deterministic.
  - Read-only access to audit/mcp.jsonl. Never write or mutate it.
  - Raises GroundingError on structural problems; returns VerificationResult
    with passed=False on claim failures — caller chooses enforcement policy.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GroundingError(Exception):
    """Raised when grounding infrastructure cannot run verification at all.

    Distinct from a claim-level failure (VerificationResult with passed=False).
    GroundingError = structural problem: missing file, malformed audit log,
    bad finding schema. The caller must not proceed with the finding.
    """


class GroundingSchemaError(GroundingError):
    """Raised specifically for evidence_quotes schema violations.

    Subclass of GroundingError so callers can distinguish:
      - GroundingSchemaError: malformed quote fields — always re-raise
      - GroundingError (base): policy violations (e.g. CONFIRMED without quotes)
        — may be downgraded to warning depending on enforcement phase
    """


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ClaimVerification:
    """Verification result for a single evidence_quote claim."""

    claim_text: str
    """Human-readable description of the claim being checked."""

    status: Literal["GROUNDED", "UNGROUNDED", "CONTRADICTED", "INFERRED_LABELED"]
    """
    GROUNDED         — claim confirmed against audit log metadata.
    UNGROUNDED       — tool or invocation_id not found in audit log,
                       or checked audit_field is absent — cannot confirm.
    CONTRADICTED     — tool found but audit_field value does not match
                       audit_expected. Detected hallucination.
    INFERRED_LABELED — finding is INFERRED with no quotes. Acceptable.
    """

    supporting_invocation_id: Optional[str]
    """The invocation_id looked up, or None if tool-name-only attestation."""

    note: str
    """Explanation for accuracy report and self-correction protocol."""


@dataclass
class VerificationResult:
    """Aggregate verification result for one finding."""

    finding_id: str
    total_claims: int
    grounded: int
    ungrounded: int
    contradicted: int
    inferred_labeled: int
    claims: list[ClaimVerification] = field(default_factory=list)
    passed: bool = True
    """
    passed=True  — no CONTRADICTED claims. Finding may proceed to approval.
    passed=False — at least one CONTRADICTED claim. Must be revised.
    UNGROUNDED claims do not set passed=False but appear in the report.
    """

    @property
    def hallucination_rate(self) -> float:
        """Fraction of claims that are CONTRADICTED. Target: 0.0."""
        if self.total_claims == 0:
            return 0.0
        return self.contradicted / self.total_claims

    @property
    def grounding_rate(self) -> float:
        """Fraction of claims that are GROUNDED."""
        if self.total_claims == 0:
            return 1.0
        return self.grounded / self.total_claims

    def to_dict(self) -> dict:
        """Serializable form for the accuracy report JSON."""
        return {
            "finding_id": self.finding_id,
            "total_claims": self.total_claims,
            "grounded": self.grounded,
            "ungrounded": self.ungrounded,
            "contradicted": self.contradicted,
            "inferred_labeled": self.inferred_labeled,
            "grounding_rate": round(self.grounding_rate, 4),
            "hallucination_rate": round(self.hallucination_rate, 4),
            "passed": self.passed,
            "claims": [
                {
                    "claim_text": c.claim_text,
                    "status": c.status,
                    "supporting_invocation_id": c.supporting_invocation_id,
                    "note": c.note,
                }
                for c in self.claims
            ],
        }


# ---------------------------------------------------------------------------
# Evidence quote schema (Phase 1)
# ---------------------------------------------------------------------------
#
# Minimum required fields per quote: "tool", "claim"
#
# Optional fields:
#   "invocation_id"  — cite a specific audit entry (UUID string)
#   "audit_field"    — dot-notation path into the audit entry to check
#                      e.g. "suspicious_count", "params.process_name",
#                           "sources_present", "verdict"
#   "audit_expected" — expected value / operator:
#                      "> 0"   numeric greater-than
#                      ">= 1"  numeric greater-than-or-equal
#                      "== X"  equality (string or numeric)
#                      "true" / "false"  boolean
#                      anything else → substring match in str(value)
#
# Phase 2 (future) will add:
#   "csv_field"    — column name in parser CSV output
#   "exact_value"  — exact value to verify in CSV rows

REQUIRED_QUOTE_FIELDS: frozenset[str] = frozenset({"tool", "claim"})


# ---------------------------------------------------------------------------
# Audit log readers
# ---------------------------------------------------------------------------

def _load_audit_log(audit_log_path: str) -> dict[str, dict]:
    """Read audit/mcp.jsonl, return dict keyed by invocation_id.

    Raises GroundingError if:
      - File does not exist
      - Any non-empty line is not valid JSON
      - Any entry is missing invocation_id
    """
    path = Path(audit_log_path)
    if not path.exists():
        raise GroundingError(
            f"Audit log not found: {audit_log_path!r}. "
            "Run at least one MCP tool call before verifying findings."
        )

    index: dict[str, dict] = {}
    for lineno, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GroundingError(
                f"Malformed JSON at {audit_log_path}:{lineno}: {exc}"
            ) from exc
        inv_id = entry.get("invocation_id")
        if not inv_id:
            raise GroundingError(
                f"Audit log entry at line {lineno} is missing 'invocation_id'. "
                f"Entry (first 120 chars): {line[:120]!r}"
            )
        index[inv_id] = entry

    return index


def _build_tool_index(audit_index: dict[str, dict]) -> dict[str, list[dict]]:
    """Group audit entries by tool name."""
    by_tool: dict[str, list[dict]] = {}
    for entry in audit_index.values():
        tool = entry.get("tool", "")
        by_tool.setdefault(tool, []).append(entry)
    return by_tool


# ---------------------------------------------------------------------------
# Audit field value checker
# ---------------------------------------------------------------------------

def _check_audit_field(
    entry: dict,
    audit_field: str,
    audit_expected: str,
) -> tuple[bool, str]:
    """Check whether entry[audit_field] satisfies audit_expected.

    Supports dot-notation for nested fields (e.g. "params.process_name").

    Returns (satisfied: bool, note: str).
    """
    current: object = entry
    for part in audit_field.split("."):
        if isinstance(current, dict):
            if part not in current:
                return False, (
                    f"Field {audit_field!r} not found in audit entry. "
                    f"Top-level keys: {sorted(entry.keys())}"
                )
            current = current[part]
        else:
            return False, (
                f"Cannot descend into {type(current).__name__} "
                f"at part {part!r} of field path {audit_field!r}."
            )

    value = current
    expected = audit_expected.strip()

    # Numeric / equality operators — tolerate optional whitespace after op (CR-4).
    m = re.match(r"^(==|!=|>=|<=|>|<)\s*(.+)$", expected)
    if m:
        op, rhs = m.group(1), m.group(2).strip()
        if op in {">", ">=", "<", "<="}:
            try:
                threshold = float(rhs)
                actual = float(value)  # type: ignore[arg-type]
                ok = {">": actual > threshold, ">=": actual >= threshold,
                      "<": actual < threshold, "<=": actual <= threshold}[op]
                return ok, (
                    f"{audit_field} = {value!r} "
                    f"{'satisfies' if ok else 'does NOT satisfy'} {expected!r}"
                )
            except (TypeError, ValueError):
                return False, (
                    f"Cannot compare {audit_field} = {value!r} "
                    f"numerically with {expected!r}"
                )
        if op in {"==", "!="}:
            match = str(value) == rhs
            if op == "!=":
                match = not match
            return match, (
                f"{audit_field} = {value!r} "
                f"{op} expected {rhs!r} -> {'PASS' if match else 'FAIL'}"
            )

    # Boolean — CR-5: normalise string representations; use bool() for numerics
    if expected.lower() == "true":
        if isinstance(value, (int, float)):
            actual_bool = bool(value)
        else:
            actual_bool = str(value).lower() not in ("false", "0", "0.0", "", "none", "null")
        return actual_bool, f"{audit_field} = {value!r} (expected truthy)"
    if expected.lower() == "false":
        if isinstance(value, (int, float)):
            actual_bool = bool(value)
        else:
            actual_bool = str(value).lower() not in ("false", "0", "0.0", "", "none", "null")
        return not actual_bool, f"{audit_field} = {value!r} (expected falsy)"

    # Substring / string containment
    match = expected.lower() in str(value).lower()
    return match, (
        f"{audit_field} = {value!r} "
        f"{'contains' if match else 'does not contain'} {expected!r}"
    )


# ---------------------------------------------------------------------------
# validate_evidence_quotes — called before record_finding writes to disk
# ---------------------------------------------------------------------------

def validate_evidence_quotes(finding: dict) -> None:
    """Structural validation of evidence_quotes before a finding is stored.

    Does NOT consult the audit log. Schema-only check.

    Rules:
      - CONFIRMED findings must have at least one evidence_quote.
      - Every quote must have: "tool" (non-empty str), "claim" (non-empty str).
      - "invocation_id", if present, must be a non-empty string.

    finding dict accepts either "finding_id" (return value key) or "id"
    (stored record key). Uses "confidence" field (not "label").
    Both verified against live findings.py on 2026-05-13.

    Raises GroundingError if any rule is violated.
    """
    finding_id = finding.get("finding_id") or finding.get("id", "<unknown>")
    confidence = finding.get("confidence", "")
    quotes = finding.get("evidence_quotes", [])

    if "CONFIRMED" in confidence and not quotes:
        raise GroundingError(
            f"Finding {finding_id!r} has confidence={confidence!r} but "
            "evidence_quotes is empty. CONFIRMED findings must cite at least "
            "one tool output. Add evidence_quotes or downgrade to INFERRED."
        )

    for i, quote in enumerate(quotes):
        missing = REQUIRED_QUOTE_FIELDS - set(quote.keys())
        if missing:
            raise GroundingSchemaError(
                f"Finding {finding_id!r} evidence_quotes[{i}] missing "
                f"required fields: {sorted(missing)}. "
                f"Required: {sorted(REQUIRED_QUOTE_FIELDS)}."
            )
        if not isinstance(quote["tool"], str) or not quote["tool"].strip():
            raise GroundingSchemaError(
                f"Finding {finding_id!r} evidence_quotes[{i}]['tool'] "
                "must be a non-empty string."
            )
        if not isinstance(quote["claim"], str) or not quote["claim"].strip():
            raise GroundingSchemaError(
                f"Finding {finding_id!r} evidence_quotes[{i}]['claim'] "
                "must be a non-empty string."
            )
        inv_id = quote.get("invocation_id")
        if inv_id is not None and (
            not isinstance(inv_id, str) or not inv_id.strip()
        ):
            raise GroundingSchemaError(
                f"Finding {finding_id!r} evidence_quotes[{i}]['invocation_id'] "
                "must be a non-empty string when supplied."
            )


# ---------------------------------------------------------------------------
# verify_finding_claims — Tier 1: invocation attestation
# ---------------------------------------------------------------------------

def verify_finding_claims(
    finding: dict,
    audit_log_path: str,
) -> VerificationResult:
    """Verify evidence_quotes against audit/mcp.jsonl (Tier 1 attestation).

    For each evidence_quote:
      1. Tool attestation: is this tool in the audit log?
         - If invocation_id supplied → verify that specific entry exists
           and that entry.tool matches quote["tool"]
         - If no invocation_id → verify at least one entry for the tool name
      2. Metadata check: if audit_field + audit_expected supplied,
         verify the field value in the entry satisfies the expectation.

    GROUNDED     = tool attested AND all audit_field checks pass
    UNGROUNDED   = tool not in audit log OR audit_field missing in entry
    CONTRADICTED = tool found BUT audit_field check fails (hallucination)
    INFERRED_LABELED = INFERRED finding with no quotes (acceptable)

    Phase 2 will add CSV value verification (exact_value against csv_files).
    """
    finding_id = finding.get("finding_id") or finding.get("id", "<unknown>")
    confidence = finding.get("confidence", "")
    quotes = finding.get("evidence_quotes", [])

    audit_index = _load_audit_log(audit_log_path)
    by_tool = _build_tool_index(audit_index)

    claim_results: list[ClaimVerification] = []

    # --- INFERRED with no quotes: acceptable ---
    if not quotes and "INFERRED" in confidence:
        claim_results.append(ClaimVerification(
            claim_text="(no evidence_quotes — INFERRED finding)",
            status="INFERRED_LABELED",
            supporting_invocation_id=None,
            note=(
                "Finding labeled INFERRED with no evidence_quotes. "
                "Acceptable — inference is documented. Consider adding "
                "audit_field checks for stronger grounding."
            ),
        ))
        return VerificationResult(
            finding_id=finding_id,
            total_claims=1,
            grounded=0,
            ungrounded=0,
            contradicted=0,
            inferred_labeled=1,
            claims=claim_results,
            passed=True,
        )

    # --- CONFIRMED with no quotes: defensive catch ---
    if not quotes and "CONFIRMED" in confidence:
        claim_results.append(ClaimVerification(
            claim_text="(no evidence_quotes — CONFIRMED finding)",
            status="UNGROUNDED",
            supporting_invocation_id=None,
            note=(
                "CONFIRMED finding has no evidence_quotes. Cannot verify. "
                "Call validate_evidence_quotes() before record_finding()."
            ),
        ))
        return VerificationResult(
            finding_id=finding_id,
            total_claims=1,
            grounded=0,
            ungrounded=1,
            contradicted=0,
            inferred_labeled=0,
            claims=claim_results,
            passed=False,
        )

    # --- Main path: verify each quote ---
    for quote in quotes:
        tool = quote["tool"]
        claim_text = quote["claim"]
        inv_id = quote.get("invocation_id")
        audit_field = quote.get("audit_field")
        audit_expected = quote.get("audit_expected")

        display = (
            f"tool={tool!r} claim={claim_text!r}"
            + (f" inv_id={inv_id!r}" if inv_id else "")
            + (f" audit_field={audit_field!r}" if audit_field else "")
        )

        # Step 1: resolve audit entry
        if inv_id:
            entry = audit_index.get(inv_id)
            if entry is None:
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="UNGROUNDED",
                    supporting_invocation_id=inv_id,
                    note=(
                        f"invocation_id {inv_id!r} not found in audit log. "
                        "Tool call may not have run in this session, "
                        "or invocation_id is incorrect."
                    ),
                ))
                continue
            if entry.get("tool") != tool:
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="CONTRADICTED",
                    supporting_invocation_id=inv_id,
                    note=(
                        f"invocation_id {inv_id!r} exists but tool is "
                        f"{entry.get('tool')!r}, not {tool!r}."
                    ),
                ))
                continue
        else:
            entries_for_tool = by_tool.get(tool, [])
            if not entries_for_tool:
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="UNGROUNDED",
                    supporting_invocation_id=None,
                    note=(
                        f"Tool {tool!r} has no audit log entries in this session. "
                        f"Tools with entries: {sorted(by_tool.keys())}. "
                        "Either the tool was never called or the name is wrong."
                    ),
                ))
                continue
            entry = entries_for_tool[0]

        used_inv_id = entry.get("invocation_id")

        # Step 2: optional audit_field check
        if audit_field is not None and audit_expected is not None:
            satisfied, field_note = _check_audit_field(
                entry, audit_field, audit_expected
            )
            if satisfied:
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="GROUNDED",
                    supporting_invocation_id=used_inv_id,
                    note=f"Tool attested and field check passed: {field_note}",
                ))
            else:
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="CONTRADICTED",
                    supporting_invocation_id=used_inv_id,
                    note=(
                        f"HALLUCINATION DETECTED: {field_note}. "
                        "The finding narrative must be corrected to match "
                        "the actual tool output."
                    ),
                ))
        else:
            # Attestation-only — tool ran, no field check
            claim_results.append(ClaimVerification(
                claim_text=display,
                status="GROUNDED",
                supporting_invocation_id=used_inv_id,
                note=(
                    f"Tool {tool!r} attested in audit log "
                    f"(invocation_id={used_inv_id!r}, "
                    f"parsed_record_count={entry.get('parsed_record_count')})."
                ),
            ))

    grounded = sum(1 for c in claim_results if c.status == "GROUNDED")
    ungrounded = sum(1 for c in claim_results if c.status == "UNGROUNDED")
    contradicted = sum(1 for c in claim_results if c.status == "CONTRADICTED")
    inferred_labeled = sum(1 for c in claim_results if c.status == "INFERRED_LABELED")

    return VerificationResult(
        finding_id=finding_id,
        total_claims=len(claim_results),
        grounded=grounded,
        ungrounded=ungrounded,
        contradicted=contradicted,
        inferred_labeled=inferred_labeled,
        claims=claim_results,
        passed=(contradicted == 0),
    )


# ---------------------------------------------------------------------------
# Source Attestation Registry
# ---------------------------------------------------------------------------

def get_attested_sources(audit_log_path: str) -> set[str]:
    """Return the set of tool names with audit entries in this session.

    Raises GroundingError if audit log is missing or malformed.
    """
    audit_index = _load_audit_log(audit_log_path)
    return {entry.get("tool", "") for entry in audit_index.values() if entry.get("tool")}


def assert_sources_attested(
    finding: dict,
    attested_sources: set[str],
) -> list[str]:
    """Check that all tools cited in evidence_quotes were actually called.

    Returns list of warning strings. Empty = all attested.
    Does not raise — caller decides enforcement policy.
    """
    warnings: list[str] = []
    finding_id = finding.get("finding_id") or finding.get("id", "<unknown>")
    for i, quote in enumerate(finding.get("evidence_quotes", [])):
        tool = quote.get("tool", "")
        if tool and tool not in attested_sources:
            warnings.append(
                f"Finding {finding_id!r} evidence_quotes[{i}] cites "
                f"tool {tool!r} which has no audit log entry. "
                f"Attested tools: {sorted(attested_sources)}."
            )
    return warnings


# ---------------------------------------------------------------------------
# Training Data Contamination Guard
# ---------------------------------------------------------------------------

BASELINE_ASSUMPTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"normally runs from", re.IGNORECASE),
    re.compile(r"legitimate \w+ runs", re.IGNORECASE),
    re.compile(r"typically spawned by", re.IGNORECASE),
    re.compile(r"standard location", re.IGNORECASE),
    re.compile(r"expected behavior", re.IGNORECASE),
    re.compile(r"usually found in", re.IGNORECASE),
    re.compile(r"in a normal environment", re.IGNORECASE),
    re.compile(r"by default", re.IGNORECASE),
]


def detect_baseline_assumptions(narrative: str) -> list[str]:
    """Scan a finding narrative for training-data baseline assumption phrases.

    Returns list of warning strings. Empty = no patterns detected.
    Warnings only — analyst may have legitimate reason to reference baseline
    behavior. Warning prompts explicit INFERRED labeling.
    """
    warnings: list[str] = []
    for pattern in BASELINE_ASSUMPTION_PATTERNS:
        match = pattern.search(narrative)
        if match:
            warnings.append(
                f"Possible training-data baseline assumption: "
                f"phrase {match.group(0)!r} at position {match.start()}. "
                "Verify this is supported by a tool output from this case, "
                "or label it explicitly as INFERRED general forensic context."
            )
    return warnings


# ---------------------------------------------------------------------------
# Aggregate accuracy report
# ---------------------------------------------------------------------------

def build_claim_accuracy_report(results: list[VerificationResult]) -> dict:
    """Aggregate VerificationResults into the claim-accuracy section of the
    accuracy report (Architecture doc Improvement 10).
    """
    total = sum(r.total_claims for r in results)
    grounded = sum(r.grounded for r in results)
    ungrounded = sum(r.ungrounded for r in results)
    contradicted = sum(r.contradicted for r in results)
    inferred_labeled = sum(r.inferred_labeled for r in results)
    all_passed = all(r.passed for r in results)

    return {
        "total_claims": total,
        "grounded": grounded,
        "ungrounded": ungrounded,
        "contradicted": contradicted,
        "inferred_labeled": inferred_labeled,
        "grounding_rate": round(grounded / total, 4) if total else 1.0,
        "hallucination_rate": round(contradicted / total, 4) if total else 0.0,
        "all_passed": all_passed,
        "findings": [r.to_dict() for r in results],
    }
