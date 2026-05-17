#!/usr/bin/env python3
"""Extract failed tasks from PRD for ralph.sh iteration prompt.

Called by ralph.sh when a previous iteration did not complete all tasks.
Reads PRD_FILE (default: prd.json) and prints a bullet list of failed tasks.

Environment variables:
    PRD_FILE      Path to the PRD JSON file (default: prd.json)

Exit codes:
        0  Normal exit — tasks printed (or "All tasks passed.")
        1  Error — bad path, file not found, or parse failure (message on stderr)
"""
import json
import os
import sys

_project_root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
prd_path = os.environ.get("PRD_FILE") or os.path.join(_project_root, "prd.json")
_resolved_prd = os.path.realpath(prd_path)
if not (_resolved_prd.startswith(_project_root + os.sep) or _resolved_prd == _project_root):
    print(f"PRD_FILE outside project root: {prd_path!r}", file=sys.stderr)
    sys.exit(1)

try:
    with open(prd_path) as fh:
        prd = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"Error reading PRD file {prd_path!r}: {exc}", file=sys.stderr)
    sys.exit(1)

failed = []
for task in prd.get("tasks", []):
    if not task.get("passed", False):
        failed.append(
            f"- {task.get('id', '?')} ({task.get('name', '?')}): "
            f"{task.get('failure_action', '?')}"
        )

print("\n".join(failed) if failed else "All tasks passed.")
