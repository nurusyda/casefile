# Clean Fixtures — Negative Control Corpus

**These are SYNTHETIC benign artifacts.** They are not extracted from any real disk
image. They exist solely as a negative control to verify that CaseFile's parsers,
suspicious-flag logic, and correlation engine do NOT fabricate malicious findings
on clean data.

## Construction

Each CSV was hand-written to match the exact column schema the corresponding parser
emits, as defined by the test fixtures in:

| Fixture | Schema source | Benign rows |
|---|---|---|
| `amcache_clean.csv` | `tests/test_amcache.py` → `CLEAN_CSV` | 5 |
| `prefetch_clean.csv` | `tests/test_prefetch.py` → `CLEAN_CSV` | 5 |
| `registry_clean.csv` | `tests/test_registry.py` → `CLEAN_CSV` | 5 |
| `eventlogs_clean.csv` | `tests/test_event_logs.py` → `CLEAN_CSV` | 5 |
| `mft_clean.csv` | `tests/test_mft.py` → `CLEAN_CSV` | 5 |

**Total: 25 benign rows across 5 artifact types.**

## Content Rules

- **Paths:** All executables under `C:\Windows\System32\` or `C:\Windows\` (legitimate
  Windows directories). No `Temp\`, `Users\Public\`, `ProgramData\staging\`, or other
  suspicious paths.
- **Publishers:** All signed by `Microsoft Corporation`.
- **Timestamps:** Internally consistent — no SI/FN mismatch (no timestomping), plausible
  UTC values within June 2024.
- **Run keys:** Only default Windows entries (`SecurityHealth`, `OneDrive`). No encoded
  PowerShell, no fake services, no deleted records.
- **Event logs:** Routine logons (Type 2 interactive, Type 5 service), benign process
  creation (notepad.exe, explorer.exe). No EID 1102 (log clear), no EID 1116
  (Defender detection), no EID 7045 (service installs — flagged by design), no
  attacker IPs.
- **Prefetch:** High run counts on system binaries (svchost.exe: 850, csrss.exe: 900) —
  normal on a long-running Windows host. No Temp\ paths in FilesLoaded.
- **MFT:** All entries `InUse=True`, no ADS, no Zone.Identifier data, SI and FN
  timestamps match.

## csrss.exe Control

`csrss.exe` at `C:\Windows\System32\csrss.exe` is the legitimate Client Server Runtime
Subsystem. The negative-control test verifies this row is NOT flagged as suspicious.

In the compromised SRL-2018 case, the attacker dropped `csrss.exe` at
`C:\Windows\Temp\Perfmon\csrss.exe` — that instance IS correctly flagged by the
path-sensitive suspicious-flag logic. The cross-check in `test_false_positive.py`
proves the system differentiates by path, not by filename alone.

## False-Positive Rate

The test suite computes `flagged_rows / total_rows` across all five clean fixtures.
Expected: 0 flagged rows → **0.0% false-positive rate**.
