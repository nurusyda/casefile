# CaseFile Security Architecture

## Guardrail Layers

CaseFile enforces evidence integrity through two distinct layers. Judges can verify each independently.

### Layer 1 — Architectural (code/config level)

These cannot be bypassed by prompt injection or agent confusion.

| Guardrail | Location | What it blocks |
|---|---|---|
| `approve_finding` not registered as MCP tool | `mcp_server/server.py` | AI cannot approve its own findings |
| `getpass()` in `cli_approve` | `mcp_server/tools/findings.py` | AI cannot supply a TTY password |
| `BLOCKED_COMMANDS` frozenset | `mcp_server/tools/findings.py` | AI cannot invoke rm, dd, mkfs, approve, etc. |
| `.claude/settings.json` deny rules | `.claude/settings.json` | Filesystem writes to evidence paths blocked at Claude Code level |

### Layer 2 — Prompt-based (CLAUDE.md)

These guide the agent's reasoning and are documented for transparency.

| Guardrail | Location | What it enforces |
|---|---|---|
| Heartbeat rule | `CLAUDE.md` | Agent checks provability after every tool call |
| Inference constraint levels | `CLAUDE.md` | HIGH/MEDIUM/LOW confidence tiers per artifact type |
| "Never approve your own findings" | `CLAUDE.md` | Redundant reminder of architectural gate |
| Evidence read-only reminder | `CLAUDE.md` | Reinforces `.claude/settings.json` deny rules |

## Evidence Path Protection

The following paths are blocked from all writes and edits via `.claude/settings.json`:

- `/mnt/evidence/*` — SIFT evidence mount
- `cases/*/evidence/*` — per-case evidence subdirectory
- `**/audit/mcp.jsonl` — append-only audit trail (written only via `audit_log()`)
- `**/approvals.jsonl` — written only via `casefile-approve` CLI (requires TTY)

## Chain of Custody

Every finding carries:
1. `finding_id` — `F-{examiner}-{n:03d}` format
2. `artifact_source` — path to the raw artifact
3. `supporting_tool` — which parse tool produced the evidence
5. SHA-256 hash — computed at approval time, written to `approvals.jsonl`
