# Deployment Guide

How to set up and run CaseFile for a new forensic investigation.

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **OS** | Ubuntu 22.04 (SIFT Workstation or plain Ubuntu) | SIFT Workstation |
| **Python** | 3.10+ | 3.11+ |
| **RAM** | 8 GB (no memory forensics) | 16 GB (with memory analysis) |
| **Disk** | 50 GB + evidence | SSD, 50 GB + evidence + memory image |
| **.NET** | 9.0 SDK (runtime-only insufficient) | 9.0 SDK |
| **Claude Code** | Latest | Latest (claude.ai/code) |
| **jq** | Any version | — |

### Required forensic tools

| Tool | Installer | Notes |
|---|---|---|
| EZ Tools (net9) | `setup-sift.sh` | AmcacheParser, MFTECmd, EvtxECmd, RECmd, SBECmd, LECmd, JLECmd |
| Volatility 3 | `pip install volatility3` | Memory forensics (optional) |
| Hayabusa | `setup-sift.sh` | Binary at `/usr/local/bin/hayabusa` |
| pyscca | `pip install pyscca` | Prefetch parsing (optional; graceful degradation if absent) |
| ewftools | Pre-installed on SIFT | E01 mounting (`ewfmount`) |

---

## Install Steps

### Option A: Full SIFT Setup (recommended)

```bash
git clone https://github.com/nurusyda/casefile.git
cd casefile
bash setup-sift.sh
```

`setup-sift.sh` performs:
1. Python version check (3.10+ required)
2. .NET 9 SDK installation via Microsoft apt repo
3. EZ Tools download to `/opt/zimmermantools/`
4. Hayabusa binary + rules installation
5. Python virtual environment creation and pip install
6. Path configuration in `~/.bashrc`

### Option B: Python-Only (tools already installed)

```bash
git clone https://github.com/nurusyda/casefile.git
cd casefile
python3 -m venv venv
source venv/bin/activate
pip install -e . --break-system-packages
```

Ensure the following are already on your system:
- .NET 9 SDK (`dotnet --version` shows `9.x`)
- EZ Tools at `/opt/zimmermantools/`
- Hayabusa at `/usr/local/bin/hayabusa` (optional)
- Volatility 3 (`python3 -c "import volatility3"` works)

### Verify Installation

```bash
cd casefile
pytest tests/ -q
# Expected: 626 passed
```

---

## Per-Case Setup

### 1. Evidence Layout

Place your evidence in a case directory:

```
~/cases/CASE_NAME/
├── evidence/                  # READ-ONLY
│   ├── base-rd-01-cdrive.E01  # Disk image
│   └── memory.img             # Memory image (optional)
├── iocs.md                    # IOCs (optional, can be propagated from prior host)
└── prd.json                   # Investigation tasks
```

### 2. Create prd.json

```json
{
  "version": "1.0",
  "case": "My Case Name",
  "description": "Investigation scope and context",
  "max_iterations": 25,
  "completion_signal": "TASK_COMPLETE",
  "tasks": [
    {
      "id": "T01",
      "name": "task_short_name",
      "description": "What to find",
      "required_label": "CONFIRMED",
      "pass_criteria": [
        "Specific artifact type expected",
        "Another criterion"
      ],
      "failure_action": "Which MCP tool to call if not found"
    }
  ],
  "known_iocs": [
    "malware.exe",
    "suspicious_service.exe"
  ],
  "suspicious_patterns": [
    "attacker_ip",
    "C2_domain"
  ]
}
```

Each task must have: `id`, `name`, `description`, `required_label` (CONFIRMED or INFERRED),
`pass_criteria` (list of observable evidence), and `failure_action` (which parser to retry).

### 3. Ingest Evidence

```bash
bash scripts/ingest.sh ~/cases/CASE_NAME/evidence/image.E01 CASE_NAME
```

`ingest.sh` extracts:
- Registry hives: SYSTEM, SOFTWARE, SECURITY, SAM
- Amcache.hve + LOG1/LOG2
- Prefetch files (.pf)
- Event Logs (.evtx)
- $MFT
- User hives per profile: NTUSER.DAT + UsrClass.dat → `analysis/user_hives/{username}/`
- Writes SHA-256 of source image to `source.sha256`
- Initializes `findings.json` and `audit/mcp.jsonl`

Extraction takes ~2 minutes for typical E01 images.

### 4. IOCs (Optional)

If you have IOCs from a prior host investigation, place them in `iocs.md`:

```markdown
# IOCs — Propagated from BASE-RD-01

## File IOCs
- STUN.exe — SHA1: abc123...
- subject_srv.exe — SHA1: def456...
- procdump.exe

## Network IOCs
- 172.16.6.12 (R&D subnet)
- 172.15.1.20 (external C2)
```

Claude Code reads this file at investigation start and cross-references all findings.

### 5. Propagate IOCs from Prior Host (Optional)

```bash
python3 scripts/propagate_iocs.py \
  --from ~/cases/PRIOR_HOST \
  --to ~/cases/CASE_NAME
```

---

## Running Ralph

### Environment Variables

```bash
export CASEFILE_CASE_ROOT=~/cases/CASE_NAME
export CASEFILE_CASE_DIR=~/cases/CASE_NAME
export CASEFILE_EXAMINER=your_name
```

| Variable | Required | Purpose |
|---|---|---|
| `CASEFILE_CASE_ROOT` | Yes | Base path for tool path validation and output defaults |
| `CASEFILE_CASE_DIR` | Yes | Active case directory (findings.json, audit log location) |
| `CASEFILE_EXAMINER` | Recommended | Embedded in finding IDs (e.g., `F-yourname-001`) |

### Start the Investigation

```bash
cd ~/casefile
bash ralph.sh ~/cases/CASE_NAME
```

What happens:
1. `ralph.sh` generates `.mcp.json` with the current case directory
2. Pipelines the investigation prompt to `claude -p`
3. Claude reads `CLAUDE.md`, `prd.json`, and `iocs.md` (if present)
4. Claude calls MCP tools, correlates evidence, records findings
5. Claude emits `<promise>TASK_COMPLETE</promise>`
6. `grounding_verify.py` checks every claim
7. If CONTRADICTED claims found: correction loop fires (max 3 iterations)
8. Results written to `claim_accuracy_report.json`

### After the Run

```bash
# Review findings
cat ~/cases/CASE_NAME/findings.json | jq .

# Check grounding report
cat ~/cases/CASE_NAME/analysis/claim_accuracy_report.json | jq .

# Review audit trail
cat ~/cases/CASE_NAME/audit/mcp.jsonl | jq .

# Approve findings (requires TTY + password)
casefile-approve

# Generate HTML report
python3 scripts/generate_html_report.py
```

### Approve Findings

`casefile-approve` is a standalone CLI — not an MCP tool. The AI cannot invoke it.

```bash
casefile-approve
# Prompts for password (getpass, no echo)
# Lists each DRAFT finding
# Examiner types 'y' or 'n' for each
# Writes SHA-256 hash to approvals.jsonl
```

---

## Verifying Results

### Grounding Report Interpretation

```json
{
  "total_claims": 10,
  "grounded": 10,
  "ungrounded": 0,
  "contradicted": 0,
  "inferred_labeled": 0,
  "grounding_rate": 1.0,
  "hallucination_rate": 0.0,
  "all_passed": true,
  "tier2_verified": 7
}
```

| Field | Meaning |
|---|---|
| `total_claims` | Number of evidence claims across all findings |
| `grounded` | Claims where invocation ID exists in audit log |
| `ungrounded` | Claims with missing audit fields (not the same as hallucination) |
| `contradicted` | Claims where exact_value was NOT found in CSV output (hallucination) |
| `grounding_rate` | `grounded / total_claims` |
| `hallucination_rate` | `contradicted / total_claims` |
| `tier2_verified` | Number of claims that passed CSV cell-value verification |
| `all_passed` | `true` if no CONTRADICTED and no UNGROUNDED |

### Per-Claim Status

Each claim in the report has one of three statuses:

| Status | Meaning | Action |
|---|---|---|
| `GROUNDED` | Invocation ID exists AND exact value found in CSV (or Tier 2 skipped for non-CSV tools) | None |
| `UNGROUNDED` | Invocation ID exists but audit field missing — traceability gap | Verify manually |
| `CONTRADICTED` | Invocation ID exists but exact value NOT in CSV — hallucination | Triggers correction loop |

### Manual Verification

For claims with Tier 2 skipped (Prefetch, Memory), verify manually:

```bash
# Check that the Volatility plugin actually ran
jq 'select(.invocation_id == "mem-566f3c84")' ~/cases/CASE_NAME/audit/mcp.jsonl

# Check parsed record count
jq 'select(.invocation_id == "mem-566f3c84") | .parsed_record_count' \
  ~/cases/CASE_NAME/audit/mcp.jsonl
```

---

## Troubleshooting

### "Output too short — likely rate limit"

Claude Code quota exhausted. Wait and retry, or reduce scope.

### MFT/Amcache parser returns 0 entries

Some hive versions have schema incompatibilities. Use pre-existing CSVs from a
prior session as fallback evidence (document the gap in findings).

### "Grounding verify exit: 1"

Import error in `grounding_verify.py`. Check `PYTHONPATH` includes the casefile
directory.

### RAM exhaustion (OOM)

- Run Volatility and EZ Tools sequentially, never concurrently
- Reduce scope with `filename_filter` on `parse_mft()`
- Use `event_ids` filter on `parse_event_logs()` to reduce output size
- Check free RAM: `free -h`

### Path confinement errors

Ensure all evidence paths resolve under `CASEFILE_CASE_ROOT`. Symlinks are
rejected — use the actual path, not a symlink.

---

## Directory Structure After a Run

```
~/cases/CASE_NAME/
├── source.sha256                    # SHA-256 of source E01
├── findings.json                    # All findings (DRAFT/APPROVED/REJECTED)
├── timeline.json                    # Investigation timeline events
├── iocs.md                          # IOCs
├── prd.json                         # Task definitions
├── claim_accuracy_report.json       # Post-run grounding results
├── analysis/
│   ├── Amcache.hve                  # Extracted from image
│   ├── MFT                          # Extracted $MFT
│   ├── amcache_out/                 # AmcacheParser CSV output
│   ├── prefetch/                    # Prefetch .pf files
│   ├── evtx/                        # Event Log .evtx files
│   ├── evtx_out/                    # EvtxECmd CSV output
│   ├── registry/                    # Registry hive files
│   ├── registry_out/                # RECmd CSV output
│   ├── mft_out/                     # MFTECmd CSV output
│   ├── hayabusa/                    # Hayabusa CSV output
│   ├── user_hives/{username}/       # NTUSER.DAT + UsrClass.dat
│   ├── progress.txt                 # Accumulated Claude output
│   └── ralph.log                    # Ralph loop execution log
├── reports/
│   ├── report.md                    # Markdown IR report
│   └── report.html                  # HTML report
└── audit/
    ├── mcp.jsonl                    # Every MCP tool call
    └── ralph.jsonl                  # Ralph loop events
```
