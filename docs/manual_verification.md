# Manual Verification — Walking One Finding by Hand

`verify.sh` runs the grounding verifier against all 41 claims across the four committed fixture cases and
reports the aggregate accuracy mechanically. This document shows the same check
performed by hand on a single finding, so anyone — including readers who don't
trust the verifier yet — can walk the chain themselves in three commands.

## The chain

Every claim CaseFile makes can be traced through three artifacts:

```
claim  →  evidence_quotes[].exact_value  →  parser CSV cell
   ↓
evidence_quotes[].invocation_id  →  audit/mcp.jsonl entry
```

- **Tier 1** of the verifier checks the `invocation_id` exists in the audit log with
  the named tool.
- **Tier 2** opens the CSV and confirms the cited `exact_value` appears as a literal
  cell value.

If either fails, the claim is flagged `CONTRADICTED` and `ralph.sh`'s correction
loop re-prompts the agent.

## Example: Workstation finding F-001

### Step 1 — Pick a finding and read its cited value

```bash
jq '.[0] | {title, exact_value: .evidence_quotes[0].exact_value, inv: .evidence_quotes[0].invocation_id}' \
    fixtures/reproducibility/SRL-2018/findings.json
```

Output:

```json
{
  "title": "CSRSS.EXE Malicious Impersonator in Windows\\Temp\\Perfmon\\ — Timestomped SHA1 IOC",
  "exact_value": "0300c7833bfba831b67f9291097655cb162263fd",
  "inv": "f9a16390-6bc1-4173-bb15-dd469d1161b7"
}
```

The agent claims the SHA1 `0300c7833bfba831b67f9291097655cb162263fd` appears in the
Amcache parser output. Let's check.

### Step 2 — Grep the parser CSV for the cited value (Tier 2)

```bash
grep -F "0300c7833bfba831b67f9291097655cb162263fd" fixtures/reproducibility/SRL-2018/csv/*.csv
```

Output:

```
fixtures/reproducibility/SRL-2018/csv/Amcache_UnassociatedFileEntries.csv:
Unassociated,00066bda6a42f3fafe2f32735541b4bd8f9200000904,2046-01-12 06:37:24,
0300c7833bfba831b67f9291097655cb162263fd,False,c:\windows\system32\csrss.exe,
csrss.exe,.exe,2046-01-12 06:37:24,,,,,,pe64_amd64,True,,,,,
```

The hash appears as a literal cell value, on a row for `csrss.exe`. **Tier 2 verified
by hand.** ✓

> **Note on the timestamp:** The row reads `2046-01-12 06:37:24` — that's not a bug.
> Amcache stores `FileKeyLastWriteTimestamp` as a FILETIME, and timestomped or
> malformed entries yield nonsense dates. The weird date is itself consistent with
> the finding's "Timestomped SHA1 IOC" claim.

### Step 3 — Trace the invocation_id to the audit log (Tier 1)

```bash
jq 'select(.invocation_id == "f9a16390-6bc1-4173-bb15-dd469d1161b7")' \
    fixtures/reproducibility/SRL-2018/audit/mcp.jsonl
```

Output (abridged):

```json
{
  "ts": "2026-06-06T09:31:00.000000+00:00",
  "invocation_id": "f9a16390-6bc1-4173-bb15-dd469d1161b7",
  "tool": "AmcacheParser",
  "returncode": 0,
  "parsed_record_count": 223,
  "csv_files": [
    "{{CASE_DIR}}/csv/Amcache_UnassociatedFileEntries.csv"
  ]
}
```

The entry confirms:
- The tool invoked was `AmcacheParser` — matches the `tool` field in the finding's
  evidence quote.
- `parsed_record_count` is 223 — a non-empty parse, so the CSV isn't a trivially
  empty file.
- `returncode` is 0 — the parser completed without error.
- The CSV file path matches the one grepped in Step 2.

**Tier 1 verified by hand.** ✓

## What this proves

For one finding picked from a committed fixture, the entire chain — claim text, cited
verbatim value, parser CSV output, audit log invocation — is consistent and
self-evident. No trust in the agent, the verifier, or the authors is required.

The same check, performed mechanically by `scripts/grounding_verify.py` against all
41 claims across all four fixture cases, produces zero `CONTRADICTED`. The verifier isn't
a black box — it's this three-step check, automated.

## Verify a different finding

To walk a different finding by hand, change the array index in Step 1:

```bash
# Finding 2 (index 1)
jq '.[1] | {title, exact_value: .evidence_quotes[0].exact_value, inv: .evidence_quotes[0].invocation_id}' \
    fixtures/reproducibility/SRL-2018/findings.json

# Finding from the domain controller case
jq '.[0] | {title, exact_value: .evidence_quotes[0].exact_value, inv: .evidence_quotes[0].invocation_id}' \
    fixtures/reproducibility/SRL-2018-DC/findings.json

# Finding from the file server case
jq '.[0] | {title, exact_value: .evidence_quotes[0].exact_value, inv: .evidence_quotes[0].invocation_id}' \
    fixtures/reproducibility/SRL-2018-FILE/findings.json
```

Then repeat Step 2 (grep the CSV) and Step 3 (jq the audit log) with the values
extracted. The structure is the same for every finding across every case.
