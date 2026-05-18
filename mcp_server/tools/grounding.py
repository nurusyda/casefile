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

import csv
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

# ---------------------------------------------------------------------------
# Tool name alias map
# ---------------------------------------------------------------------------
# Claude Code uses logical/wrapper names in evidence_quotes (e.g. "parse_prefetch")
# while the audit log records the actual MCP tool class names (e.g. "pyscca").
# This map resolves logical names → canonical audit log names so the verifier
# does not falsely CONTRADICT valid grounded findings.
_TOOL_NAME_ALIASES: dict[str, str] = {
    "parse_prefetch":   "pyscca",
    "parse_memory":     "Volatility3",
    "parse_event_logs": "EvtxECmd",
    "parse_registry":   "RECmd",
    "parse_amcache":    "AmcacheParser",
    "parse_mft":        "MFTECmd",
}


def _resolve_tool_name(name: str) -> str:
    """Resolve a logical tool name to its canonical audit log name.

    If the name is already canonical (or unknown), it is returned unchanged.
    This allows evidence_quotes to use either form without triggering false
    CONTRADICTED verdicts.

    Examples:
        _resolve_tool_name("parse_prefetch")  -> "pyscca"
        _resolve_tool_name("pyscca")          -> "pyscca"   (passthrough)
        _resolve_tool_name("unknown_tool")    -> "unknown_tool"  (passthrough)
    """
    return _TOOL_NAME_ALIASES.get(name, name)



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
) -> tuple[str, str]:
    """Check whether entry[audit_field] satisfies audit_expected.

    Supports dot-notation for nested fields (e.g. "params.process_name").

    Returns (status: str, note: str) where status is one of:
      "OK"      — field found and satisfies audit_expected
      "MISMATCH" — field found but does not satisfy audit_expected (hallucination)
      "MISSING"  — field not found in audit entry (cannot verify)
    """
    current: object = entry
    for part in audit_field.split("."):
        if isinstance(current, dict):
            if part not in current:
                return "MISSING", (
                    f"Field {audit_field!r} not found in audit entry. "
                    f"Top-level keys: {sorted(entry.keys())}"
                )
            current = current[part]
        else:
            return "MISSING", (
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
                return ("OK" if ok else "MISMATCH"), (
                    f"{audit_field} = {value!r} "
                    f"{'satisfies' if ok else 'does NOT satisfy'} {expected!r}"
                )
            except (TypeError, ValueError):
                return "MISSING", (
                    f"Cannot compare {audit_field} = {value!r} "
                    f"numerically with {expected!r}"
                )
        if op in {"==", "!="}:
            match = str(value) == rhs
            if op == "!=":
                match = not match
            return ("OK" if match else "MISMATCH"), (
                f"{audit_field} = {value!r} "
                f"{op} expected {rhs!r} -> {'PASS' if match else 'FAIL'}"
            )

    # Boolean — CR-5: normalise string representations; use bool() for numerics
    if expected.lower() == "true":
        if isinstance(value, (int, float)):
            actual_bool = bool(value)
        else:
            actual_bool = str(value).lower() not in ("false", "0", "0.0", "", "none", "null")
        return ("OK" if actual_bool else "MISMATCH"), f"{audit_field} = {value!r} (expected truthy)"
    if expected.lower() == "false":
        if isinstance(value, (int, float)):
            actual_bool = bool(value)
        else:
            actual_bool = str(value).lower() not in ("false", "0", "0.0", "", "none", "null")
        return ("OK" if not actual_bool else "MISMATCH"), f"{audit_field} = {value!r} (expected falsy)"

    # Substring / string containment
    match = expected.lower() in str(value).lower()
    return ("OK" if match else "MISMATCH"), (
        f"{audit_field} = {value!r} "
        f"{'contains' if match else 'does not contain'} {expected!r}"
    )


# ---------------------------------------------------------------------------
# _verify_exact_value_in_csv — Tier 2: value verification against CSV output
# ---------------------------------------------------------------------------

def _verify_exact_value_in_csv(
    csv_files: list[str],
    exact_value: str,
) -> tuple[bool, str, bool]:
    """Search csv_files for exact_value (case-insensitive exact field match).

    Reads each CSV with csv.reader and checks whether any cell's stripped
    value equals exact_value — prevents false grounding from partial or
    path matches (e.g. "subject_srv.exe" must not match "subject_srv.exe.bak"
    or "C:\\Temp\\subject_srv.exe").

    Returns (found: bool, note: str, any_read: bool).
    any_read is False when all files were skipped (too large, unreadable,
    outside case root) — callers must not CONTRADICT when any_read is False.
    Empty csv_files list -> (False, 'no CSV files available', False).
    """
    if not csv_files:
        return False, "no CSV files available in audit entry", False

    needle = exact_value.lower()
    read_count = 0  # files actually opened and parsed (excludes skipped)

    for csv_path in csv_files:
        try:
            p = Path(csv_path)  # malformed path string (null bytes etc.) → skip
        except (ValueError, OSError):
            continue
        # Path confinement — same pattern as _enforce_case_root() in correlation.py.
        # CR3: dev/test passthrough when CASEFILE_CASE_ROOT unset (project-wide policy).
        _case_root_env = os.environ.get("CASEFILE_CASE_ROOT")
        if _case_root_env:
            try:
                p.resolve().relative_to(Path(_case_root_env).resolve())
            except ValueError:
                continue  # outside case root — skip, not counted as read
        try:
            file_size = p.stat().st_size
        except OSError:
            continue  # unreadable stat — skip
        _MAX_CSV_BYTES = 50 * 1024 * 1024  # 50 MB guard — avoid OOM on large dumps
        if file_size > _MAX_CSV_BYTES:
            continue  # too large — skip
        # Exact field-level equality via csv.reader — prevents false grounding
        # from substring matches (e.g. "subject_srv.exe" in "subject_srv.exe.bak").
        # Streams line-by-line — avoids loading full file twice.
        # Delimiter assumption: all CaseFile parsers produce comma-delimited CSV.
        # TSV/PSV output would cause whole-line single-field reads (false negatives).
        # csv.Error caught: malformed CSV treated as unreadable, not a crash.
        try:
            with p.open(newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.reader(fh)
                field_match = any(
                    cell.strip().lower() == needle
                    for row in reader
                    for cell in row
                )
        except (OSError, csv.Error):
            continue  # malformed or unreadable — skip, not counted as read
        read_count += 1
        if field_match:
            return True, (
                f"exact_value {exact_value!r} found in CSV output "
                f"({read_count} of {len(csv_files)} file(s) read)"
            ), True

    any_read = read_count > 0
    return False, (
        f"exact_value {exact_value!r} NOT found in any CSV "
        f"({read_count} file(s) read, {len(csv_files)} total considered)"
    ), any_read


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
# _should_run_tier2 — type-safe csv_files extractor
# ---------------------------------------------------------------------------

def _should_run_tier2(entry: dict) -> "list[str] | None":
    """Return csv_files from audit entry extra if valid, else None.

    Guards against malformed audit entries where csv_files is not a list
    (e.g. a string or None). Returning None causes callers to fall through
    to Tier 1 attestation only, preventing false CONTRADICTED verdicts.
    """
    raw = entry.get("csv_files") or (entry.get("extra") or {}).get("csv_files")
    if not isinstance(raw, list) or not raw:
        return None
    # Filter to non-empty strings only — Path(non-string) raises TypeError
    filtered = [x for x in raw if isinstance(x, str) and x]
    return filtered if filtered else None


# _apply_tier2_csv_check — shared Tier 2 dispatch used by both branches
# ---------------------------------------------------------------------------

def _apply_tier2_csv_check(
    entry: dict,  # kept for future extensibility (e.g. tool name in notes)
    csv_files: list[str],
    exact_value: str,
    display: str,
    used_inv_id: str | None,
    tool: str,
    base_note: str,
) -> ClaimVerification:
    """Run Tier 2 CSV check and return a ClaimVerification.

    Called from both the audit_field-satisfied branch and the attestation-only
    branch of verify_finding_claims. Returns GROUNDED if exact_value found in
    any csv_files entry, CONTRADICTED otherwise.

    base_note is prepended to the CSV result note so each branch can supply
    its own context (e.g. field-check result for the satisfied branch).
    """
    # csv_files already validated by _should_run_tier2() in caller — use directly
    csv_found, csv_note, any_read = _verify_exact_value_in_csv(
        csv_files, exact_value
    )
    if csv_found:
        return ClaimVerification(
            claim_text=display,
            status="GROUNDED",
            supporting_invocation_id=used_inv_id,
            note=(
                (base_note + " and " if base_note else "")
                + f"Tier 2 CSV check passed: {csv_note}"
            ),
        )
    if not any_read:
        # All CSV files were skipped (too large, outside case root, unreadable).
        # Cannot verify — do not CONTRADICT; fall back to Tier 1 attestation.
        return ClaimVerification(
            claim_text=display,
            status="GROUNDED",
            supporting_invocation_id=used_inv_id,
            note=(
                (base_note + " — " if base_note else "")
                + f"Tier 2 CSV check skipped (no file readable): {csv_note}. "
                "Tier 1 attestation only."
            ),
        )
    return ClaimVerification(
        claim_text=display,
        status="CONTRADICTED",
        supporting_invocation_id=used_inv_id,
        note=(
            f"HALLUCINATION DETECTED (Tier 2): "
            + (f"{base_note} but " if base_note else "")
            + f"exact_value not in CSV: {csv_note}. "
            "Correct the finding to use only values present in tool output."
        ),
    )


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
        tool = _resolve_tool_name(quote.get("tool") or "")
        claim_text = quote.get("claim", "")
        if not tool or not claim_text:
            claim_results.append(ClaimVerification(
                claim_text=str(quote),
                status="UNGROUNDED",
                supporting_invocation_id=None,
                note="Malformed evidence_quote: missing 'tool' or 'claim' key.",
            ))
            continue
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
            if _resolve_tool_name(entry.get("tool") or "") != tool:
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
            entries_for_tool = by_tool.get(tool) or by_tool.get(quote.get("tool") or "", [])
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
            # If audit_field supplied, find first entry that satisfies;
            # attestation-only → first entry is fine.
            if audit_field is not None and audit_expected is not None:
                entry = next(
                    (e for e in entries_for_tool
                     if _check_audit_field(e, audit_field, audit_expected)[0] == "OK"),
                    entries_for_tool[0],
                )
            else:
                entry = entries_for_tool[0]

        used_inv_id = entry.get("invocation_id")

        # Step 2: optional audit_field check
        if audit_field is not None and audit_expected is not None:
            field_status, field_note = _check_audit_field(
                entry, audit_field, audit_expected
            )
            if field_status == "OK":
                # Field check passed — additionally run Tier 2 CSV check
                # if exact_value is supplied.
                exact_value = quote.get("exact_value")
                tier2_csv = _should_run_tier2(entry)
                if exact_value and tier2_csv:
                    claim_results.append(_apply_tier2_csv_check(
                        entry, tier2_csv, exact_value, display, used_inv_id, tool,
                        base_note=f"field check passed ({field_note})",
                    ))
                else:
                    # CR9: consistent note — flag when exact_value supplied but unverifiable
                    _f_note = f"Tool attested and field check passed: {field_note}"
                    if exact_value and not tier2_csv:
                        _f_note += (
                            " exact_value supplied but no valid csv_files in audit"
                            " entry — Tier 2 skipped, Tier 1 attestation only."
                        )
                    claim_results.append(ClaimVerification(
                        claim_text=display,
                        status="GROUNDED",
                        supporting_invocation_id=used_inv_id,
                        note=_f_note,
                    ))
            elif field_status == "MISSING":
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="UNGROUNDED",
                    supporting_invocation_id=used_inv_id,
                    note=f"Cannot verify — {field_note}",
                ))
            else:  # MISMATCH
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
            # Attestation-only — tool ran, no audit_field check.
            # Tier 2: if exact_value + csv_files present, verify value in CSV.
            exact_value = quote.get("exact_value")
            tier2_csv = _should_run_tier2(entry)

            if exact_value and tier2_csv:
                claim_results.append(_apply_tier2_csv_check(
                    entry, tier2_csv, exact_value, display, used_inv_id, tool,
                    base_note=f"Tool {tool!r} attested",
                ))
            else:
                # No exact_value, no csv_files, or csv_files not a list — Tier 1 only
                _t1_note = (
                    f"Tool {tool!r} attested in audit log "
                    f"(invocation_id={used_inv_id!r}, "
                    f"parsed_record_count={entry.get('parsed_record_count')})."
                )
                if exact_value and not tier2_csv:
                    _t1_note += (
                        " exact_value supplied but no valid csv_files in audit entry"
                        " — Tier 2 skipped, Tier 1 attestation only."
                    )
                elif not exact_value:
                    _t1_note += " No exact_value supplied — Tier 1 attestation only."
                claim_results.append(ClaimVerification(
                    claim_text=display,
                    status="GROUNDED",
                    supporting_invocation_id=used_inv_id,
                    note=_t1_note,
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
        raw_tool = quote.get("tool", "")
        tool = _resolve_tool_name(raw_tool)
        # Accept either the canonical name OR the original logical name
        if tool and tool not in attested_sources and raw_tool not in attested_sources:
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
    re.compile(r"\bby default\s+\w+\s+(runs|lives|writes|loads|executes|spawns)\b", re.IGNORECASE),
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
