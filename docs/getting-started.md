# Getting Started

## Prerequisites

| Requirement | Notes |
|---|---|
| SIFT Workstation or WSL2 Ubuntu 22.04 | Primary supported platform |
| Python 3.10+ | `python3 --version` |
| EZ Tools | Installed by `setup-sift.sh` to `/opt/zimmermantools/` |
| Volatility 3 | `pip install volatility3` |
| Claude Code | Required for autonomous investigation loop |
| .NET 6.0+ | Required by EZ Tools |

## Install

```bash
git clone https://github.com/nurusyda/casefile.git
cd casefile
pip install -e . --break-system-packages
```

To also install EZ Tools and dependencies on SIFT:

```bash
bash setup-sift.sh
```

## Verify Installation

```bash
pytest tests/ -q
# Expected: 485 passed
```

## Your First Investigation

### Step 1: Extract Artifacts

```bash
bash scripts/ingest.sh /path/to/evidence.E01 MY_CASE_NAME
```

This command:
- Mounts the E01 image via ewfmount
- Extracts Registry hives, Amcache, Prefetch, Event Logs, MFT to `~/cases/MY_CASE_NAME/analysis/`
- Writes SHA-256 of source image to `source.sha256`
- Takes approximately 2 minutes for a 17GB image

### Step 2: Set Environment

```bash
export CASEFILE_CASE_ROOT=~/cases/MY_CASE_NAME
export CASEFILE_CASE_DIR=~/cases/MY_CASE_NAME
export CASEFILE_EXAMINER=your_name
```

### Step 3: Run Investigation

```bash
bash ralph.sh ~/cases/MY_CASE_NAME
```

Ralph runs autonomously:

1. Claude Code reads investigation tasks from `prd.json`
2. Calls MCP tools to parse each artifact type
3. Records findings with exact evidence quotes
4. Verifies every claim against tool output
5. Self-corrects if contradictions detected (max 3 iterations)
6. Writes `analysis/claim_accuracy_report.json`

### Step 4: Review Findings

```bash
casefile-approve
```

This launches an interactive review session requiring:
- Real TTY (will fail in scripts or CI)
- Password confirmation

For each finding you can: approve, edit, reject, add a note, or skip.

### Step 5: Generate Report

```bash
# Markdown report
python3 scripts/generate_report.py

# HTML report (dark theme with tabs)
python3 scripts/generate_html_report.py

# Update dataset documentation
python3 scripts/generate_dataset_doc.py
```

## Key Files

```
~/cases/MY_CASE_NAME/
├── findings.json              # All findings (DRAFT/APPROVED/REJECTED)
├── timeline.json              # Investigation timeline events
├── source.sha256              # SHA-256 of source evidence image
├── iocs.md                    # IOCs (auto-populated by propagate_iocs.py)
├── prd.json                   # Investigation tasks
├── analysis/
│   ├── *.csv                  # Parser output files
│   └── claim_accuracy_report.json  # Grounding verification results
└── audit/
    ├── mcp.jsonl              # Every tool invocation (append-only)
    └── approvals.jsonl        # Approval records with content hashes
```

## Multi-Host Investigation

After investigating the first host, propagate IOCs to the next:

```bash
python3 scripts/propagate_iocs.py \
  --source ~/cases/FIRST_HOST \
  --target ~/cases/SECOND_HOST

# Then run ralph on the second host
bash ralph.sh ~/cases/SECOND_HOST
```

## Troubleshooting

**EZ Tools not found:** Run `bash setup-sift.sh` or check `ls /opt/zimmermantools/`

**ewfmount fails:** Check `which ewfmount` and install libewf-dev if missing

**Volatility3 import error:** `pip install volatility3 --break-system-packages`

**casefile-approve requires TTY:** Must run in an interactive terminal, not a script

**Ralph hits rate limit:** Claude Code has a 5-hour session limit. Wait for reset, then re-run with existing `findings.json` intact (ralph resumes from current state).
