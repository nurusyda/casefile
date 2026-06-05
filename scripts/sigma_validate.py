#!/usr/bin/env python3
"""
sigma_validate.py — Validates CaseFile Sigma detection rules.

Checks each .yml file in detections/sigma/ for:
  - Required fields (title, id, status, description, author, date, tags, logsource, detection, level)
  - Valid UUID format in id field
  - Valid status value
  - Valid level value
  - ATT&CK tag format (attack.tNNNN or attack.tNNNN.NNN)
  - detection block contains at least one selection and a condition
  - No unknown top-level keys

Usage:
    python3 scripts/sigma_validate.py              # validate all rules
    python3 scripts/sigma_validate.py --strict     # fail on warnings too
    python3 scripts/sigma_validate.py path/to/rule.yml  # validate one rule

Exit codes:
    0 — all rules valid
    1 — one or more rules have errors
"""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Spec constants
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {
    "title", "id", "status", "description", "author",
    "date", "tags", "logsource", "detection", "level",
}

VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

KNOWN_TOP_LEVEL = {
    "title", "id", "name", "status", "description", "references",
    "author", "date", "modified", "tags", "logsource", "detection",
    "falsepositives", "level", "fields", "related", "definition",
}

ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

def validate_rule(path: Path) -> tuple[list[str], list[str]]:
    """
    Returns (errors, warnings) for a single rule file.
    errors = hard failures; warnings = style issues.
    """
    errors: list[str] = []
    warnings: list[str] = []

    try:
        content = path.read_text(encoding="utf-8")
        rule = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []
    except OSError as e:
        return [f"Cannot read file: {e}"], []

    if not isinstance(rule, dict):
        return ["Rule must be a YAML mapping at the top level"], []

    # Required fields
    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

    # Unknown top-level keys
    unknown = set(rule.keys()) - KNOWN_TOP_LEVEL
    if unknown:
        warnings.append(f"Unknown top-level keys: {', '.join(sorted(unknown))}")

    # id must be a valid UUID
    rule_id = rule.get("id", "")
    if rule_id and not UUID_RE.match(str(rule_id)):
        errors.append(f"id '{rule_id}' is not a valid UUID4")

    # status
    status = rule.get("status", "")
    if status and status not in VALID_STATUSES:
        errors.append(f"status '{status}' must be one of: {', '.join(sorted(VALID_STATUSES))}")

    # level
    level = rule.get("level", "")
    if level and level not in VALID_LEVELS:
        errors.append(f"level '{level}' must be one of: {', '.join(sorted(VALID_LEVELS))}")

    # tags — at least one attack.* tag
    tags = rule.get("tags", [])
    if not isinstance(tags, list):
        errors.append("tags must be a list")
    else:
        attack_tags = [t for t in tags if str(t).startswith("attack.")]
        if not attack_tags:
            warnings.append("No attack.* tags found — add ATT&CK technique mapping")
        for tag in tags:
            if not ATTACK_TAG_RE.match(str(tag)):
                warnings.append(f"Tag '{tag}' does not match expected format attack.tNNNN or attack.tactic")

    # logsource
    logsource = rule.get("logsource", {})
    if not isinstance(logsource, dict):
        errors.append("logsource must be a mapping")
    elif not logsource:
        errors.append("logsource must not be empty")

    # detection
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        errors.append("detection must be a mapping")
    else:
        if "condition" not in detection:
            errors.append("detection must contain a 'condition' key")
        selections = [k for k in detection if k != "condition" and not k.startswith("filter")]
        if not selections:
            errors.append("detection must contain at least one selection key")

    # description length
    desc = rule.get("description", "")
    if isinstance(desc, str) and len(desc.strip()) < 30:
        warnings.append("description is very short — add more context for analysts")

    return errors, warnings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CaseFile Sigma rules")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Rule files or directories to validate (default: detections/sigma/)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )
    args = parser.parse_args()

    # Resolve paths
    PROJECT_ROOT = Path(__file__).parent.parent.resolve()

    if args.paths:
        rule_files: list[Path] = []
        for p in args.paths:
            path = Path(p).resolve()
            if not path.is_relative_to(PROJECT_ROOT):
                print(f"ERROR: {p} is outside the project directory", file=sys.stderr)
                continue
            if path.is_dir():
                rule_files.extend(sorted(path.glob("**/*.yml")))
            elif path.is_file():
                rule_files.append(path)
            else:
                print(f"WARNING: Path not found: {p}", file=sys.stderr)
    else:
        sigma_dir = Path(__file__).parent.parent / "detections" / "sigma"
        if not sigma_dir.exists():
            print(f"ERROR: {sigma_dir} does not exist. Create it with Sigma rules.", file=sys.stderr)
            return 1
        rule_files = sorted(sigma_dir.glob("**/*.yml"))

    if not rule_files:
        print("No Sigma rule files found.", file=sys.stderr)
        return 1

    total_errors = 0
    total_warnings = 0

    for path in rule_files:
        errors, warnings = validate_rule(path)

        if not errors and not warnings:
            print(f"  ✓  {path.name}")
        elif errors:
            print(f"  ✗  {path.name}")
            for e in errors:
                print(f"       ERROR:   {e}")
            for w in warnings:
                print(f"       WARNING: {w}")
        else:
            print(f"  ⚠  {path.name}")
            for w in warnings:
                print(f"       WARNING: {w}")

        total_errors += len(errors)
        total_warnings += len(warnings)

    print()
    exit_errors = total_errors + (total_warnings if args.strict else 0)
    suffix = " (strict)" if args.strict and total_warnings else ""
    summary = f"{len(rule_files)} rule(s) — {total_errors} error(s), {total_warnings} warning(s){suffix}"
    if exit_errors == 0:
        print(f"PASS: {summary}")
        return 0
    else:
        print(f"FAIL: {summary}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
