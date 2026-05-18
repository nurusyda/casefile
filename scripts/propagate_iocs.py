#!/usr/bin/env python3
"""
propagate_iocs.py - Extract IOCs from confirmed findings and write to target case.

Usage:
    python3 scripts/propagate_iocs.py <source_case_dir> <target_case_dir>

Reads CONFIRMED findings from source_case_dir/findings.json.
Writes extracted IOCs to target_case_dir/iocs.md.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
HOSTNAME_RE = re.compile(
    r"\b([a-zA-Z0-9][a-zA-Z0-9\-]{2,}\.(?:lan|local|internal|corp|test|lab|intra))\b", re.I
)
EXE_RE = re.compile(r"([A-Za-z0-9_\-]{1,255}\.exe)", re.I)
SHA1_RE = re.compile(r"\b([0-9a-fA-F]{40})\b")
SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")

# Windows built-in binaries only — NOT third-party tools
SYSTEM_BINARIES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "smss.exe", "wininit.exe", "explorer.exe",
    "taskhostw.exe", "spoolsv.exe", "msiexec.exe", "conhost.exe",
    "dllhost.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe",
    "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "wevtutil.exe", "net.exe", "netsh.exe", "sc.exe", "reg.exe",
    "whoami.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe",
    "wmiprvse.exe", "wsmprovhost.exe", "wmic.exe",
}


def _enforce_case_root(path: Path, label: str) -> None:
    """Enforce CASEFILE_CASE_ROOT confinement when env var is set."""
    case_root_env = os.environ.get("CASEFILE_CASE_ROOT")
    if not case_root_env:
        return
    try:
        path.resolve().relative_to(Path(case_root_env).resolve())
    except ValueError:
        print(
            f"ERROR: {label} path escapes CASEFILE_CASE_ROOT: {path}",
            file=sys.stderr,
        )
        sys.exit(1)


def extract_iocs(text: str) -> dict:
    ips = {
        ip for ip in IPV4_RE.findall(text)
        if not ip.startswith("127.") and ip != "0.0.0.0"
    }
    hostnames = set(HOSTNAME_RE.findall(text))
    exes = {
        match.group(1)
        for match in EXE_RE.finditer(text)
        if match.group(1).lower() not in SYSTEM_BINARIES
    }
    hashes = set(SHA1_RE.findall(text)).union(SHA256_RE.findall(text))
    return {"ips": ips, "hostnames": hostnames, "executables": exes, "hashes": hashes}


def load_findings(case_dir: Path) -> list:
    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        print(f"ERROR: No findings.json at {findings_path}", file=sys.stderr)
        sys.exit(1)
    data = json.loads(findings_path.read_text())
    return list(data.values()) if isinstance(data, dict) else data


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/propagate_iocs.py <source_case_dir> <target_case_dir>")
        sys.exit(1)

    source_dir = Path(sys.argv[1]).resolve()
    target_dir = Path(sys.argv[2]).resolve()

    for d, label in [(source_dir, "Source"), (target_dir, "Target")]:
        if not d.exists():
            print(f"ERROR: {label} dir not found: {d}", file=sys.stderr)
            sys.exit(1)

    _enforce_case_root(source_dir, "source")
    _enforce_case_root(target_dir, "target")

    findings = load_findings(source_dir)
    confirmed = [f for f in findings if f.get("confidence") == "CONFIRMED"]
    approved = [f for f in confirmed if f.get("status") == "APPROVED"]

    print(f"Source: {source_dir.name}")
    print(f"  Total findings : {len(findings)}")
    print(f"  CONFIRMED      : {len(confirmed)}")
    print(f"  APPROVED       : {len(approved)}")
    if len(approved) < len(confirmed):
        unapproved = len(confirmed) - len(approved)
        print(f"  NOTE: Including {unapproved} unapproved CONFIRMED findings")

    all_ips: dict[str, list[str]] = {}
    all_hostnames: dict[str, list[str]] = {}
    all_exes: dict[str, list[str]] = {}
    all_hashes: dict[str, list[str]] = {}

    for f in confirmed:
        fid = f.get("id", "?")
        text = " ".join([
            f.get("observation", ""),
            f.get("interpretation", ""),
            " ".join(q.get("claim", "") for q in f.get("evidence_quotes", [])),
        ])
        iocs = extract_iocs(text)
        for ip in iocs["ips"]:
            all_ips.setdefault(ip, []).append(fid)
        for h in iocs["hostnames"]:
            all_hostnames.setdefault(h, []).append(fid)
        for exe in iocs["executables"]:
            all_exes.setdefault(exe.lower(), []).append(fid)
        for sha in iocs["hashes"]:
            all_hashes.setdefault(sha, []).append(fid)

    for d in [all_ips, all_hostnames, all_exes, all_hashes]:
        for k in d:
            d[k] = sorted(set(d[k]))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output_path = target_dir / "iocs.md"
    if output_path.is_symlink():
        print(f"ERROR: {output_path} is a symlink -- aborting", file=sys.stderr)
        sys.exit(1)

    lines = [
        f"# IOCs Propagated from {source_dir.name}",
        f"Generated: {now}  ",
        f"Source: `{source_dir}`  ",
        f"Extracted from **{len(confirmed)} CONFIRMED** findings ({len(approved)} approved).",
        "",
        "> Cross-reference all findings against these IOCs.",
        "> These were found by CaseFile on the source host — treat as high-confidence leads.",
        "",
    ]

    if all_ips:
        lines += [
            "## Network IOCs",
            "| IP Address | Source Findings |",
            "|------------|-----------------|"
        ]
        for ip, fids in sorted(all_ips.items()):
            lines.append(f"| `{ip}` | {', '.join(fids)} |")
        lines.append("")

    if all_hostnames:
        lines += [
            "## Hostnames",
            "| Hostname | Source Findings |",
            "|----------|-----------------|"
        ]
        for h, fids in sorted(all_hostnames.items()):
            lines.append(f"| `{h}` | {', '.join(fids)} |")
        lines.append("")

    if all_exes:
        lines += [
            "## Suspicious Executables",
            "| Executable | Source Findings |",
            "|------------|-----------------|"
        ]
        for exe, fids in sorted(all_exes.items()):
            lines.append(f"| `{exe}` | {', '.join(fids)} |")
        lines.append("")

    if all_hashes:
        lines += [
            "## SHA1/SHA256 Hashes",
            "| Hash | Source Findings |",
            "|------|-----------------|"
        ]
        for sha, fids in sorted(all_hashes.items()):
            lines.append(f"| `{sha}` | {', '.join(fids)} |")
        lines.append("")

    output_path.write_text("\n".join(lines))

    total = len(all_ips) + len(all_hostnames) + len(all_exes) + len(all_hashes)
    print(f"\nExtracted {total} unique IOCs:")
    print(f"  IPs         : {len(all_ips)}")
    print(f"  Hostnames   : {len(all_hostnames)}")
    print(f"  Executables : {len(all_exes)}")
    print(f"  Hashes      : {len(all_hashes)}")
    print(f"\nWritten to: {output_path}")


if __name__ == "__main__":
    main()
