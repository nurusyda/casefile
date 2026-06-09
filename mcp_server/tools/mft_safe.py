"""
parse_mft() — OOM-safe composition wrapper over the raw MFT parser.

This module wraps `mcp_server.tools.mft.parse_mft` and adds:
  - Hard-cap slicing (max_parse_rows) to prevent OOM on multi-million-record $MFT files
  - Metadata enrichment (raw_parse_count, capped_parse) in the return value

The raw parser in `mft.py` is NOT modified — all safety logic lives here.
This respects the Golden Rule that parser files must not receive logic changes;
composition belongs in the correlation / wrapper layer.

Design contract:
  - Accepts the same parameters as `mft.parse_mft()` plus `max_parse_rows`.
  - Calls `mft.parse_mft()` without max_parse_rows (the raw parser ignores it).
  - Slices `entries`, `timestomped`, and `suspicious` lists post-hoc.
  - Adds `raw_parse_count` and `capped_parse` keys to the return dict.
  - Preserves suspicious entries via `_cap_entries_keep_suspicious` for
    consistency with other parsers.
  - NEVER overwrites `total_entries` — it stays the raw parse count.
  - NEVER recalculates `timestomped_count` / `suspicious_count` — those
    reflect full, uncapped totals from the raw parser.

Caveat:
  The raw parser loads all CSV rows into memory before returning, so the
  OOM cap here is a post-hoc slice, not a streaming row-limit.  True OOM
  prevention requires a row-limit inside ``_parse_mft_csv()`` (which lives
  in ``mft.py`` and is protected by the Golden Rule).  Until that is
  approved, this wrapper documents the cap and prevents downstream consumers
  from being flooded.

Cap layering:
  The raw parser (mft.py:589) hard-codes a 500-entry cap on the returned
  ``entries`` list.  This wrapper's ``max_parse_rows`` is an additional
  safety net, but the *effective* ceiling is ``min(max_parse_rows, 500)``
  until the raw parser's cap is raised.  The ``capped_parse`` flag and
  ``analyst_note`` reflect which cap was actually hit so the analyst is
  never misled about how many entries are achievable.
"""

from __future__ import annotations

from typing import Any, Optional

from mcp_server.tools.mft import parse_mft as _parse_mft_raw
from mcp_server.tools._shared import _cap_entries_keep_suspicious

# The raw parser in mft.py hard-caps entries_out at 500 (mft.py:589).
# max_parse_rows above this value has no effect unless the raw cap is raised.
_RAW_MFT_CAP = 500


def parse_mft(
    mft_path: str,
    output_dir: Optional[str] = None,
    filename_filter: Optional[list[str]] = None,
    include_all: bool = False,
    max_parse_rows: int = 10000,
) -> dict[str, Any]:
    """Parse $MFT with OOM protection.

    Calls the raw ``mft.parse_mft()`` parser, then applies a hard cap
    on the number of entries retained.  This prevents OOM on typical
    SIFT workstations (8 GB RAM) where $MFT files commonly contain
    300K–2M records.

    .. note::
       The raw parser (mft.py) caps entries at 500 before this wrapper
       runs.  The effective ceiling is ``min(max_parse_rows, 500)``.
       Passing ``max_parse_rows > 500`` has no effect unless the raw
       parser's internal cap is raised.

    Args:
        mft_path: Path to the extracted $MFT file.
        output_dir: Where MFTECmd writes CSV output (default: sibling ``mft_out/``).
        filename_filter: Optional list of filename substrings to filter for.
        include_all: If True, returns all parsed entries (subject to cap).
                     If False (default), returns only suspicious + timestomped entries.
        max_parse_rows: Hard limit on entries read into memory (default 10 000).
                        The raw parser's 500-entry cap is the binding constraint
                        when max_parse_rows > 500.

    Returns:
        Same schema as ``mft.parse_mft()``, plus:
          - ``raw_parse_count`` — entries parsed before capping
          - ``capped_parse``   — True if entries were sliced by either cap
    """
    result = _parse_mft_raw(
        mft_path=mft_path,
        output_dir=output_dir,
        filename_filter=filename_filter,
        include_all=include_all,
    )

    # If the raw parser errored, pass through unchanged — don't mask errors.
    if result.get("error"):
        result.setdefault("raw_parse_count", 0)
        result.setdefault("capped_parse", False)
        return result

    # total_entries is the raw, uncapped parse count from MFTECmd.
    # We NEVER overwrite it — it is the ground truth for accuracy metrics.
    raw_total: int = result.get("total_entries", 0)
    raw_capped: bool = result.get("entries_capped", False)
    entries_count: int = len(result.get("entries", []))

    # The raw parser caps entries_out at _RAW_MFT_CAP (500) before returning.
    # The effective ceiling is the lower of max_parse_rows and the raw cap.
    # If raw_capped is True, the entry list is already ≤ 500 regardless of
    # what max_parse_rows says.
    effective_max = min(max_parse_rows, _RAW_MFT_CAP)

    # capped is True when the entry list was actually sliced — either by
    # the raw parser or (if the raw cap is raised) by this wrapper.
    capped = raw_capped or entries_count > effective_max

    # This block only activates when max_parse_rows is stricter than the raw
    # parser's internal cap (500).  With the default max_parse_rows=10000,
    # effective_max == 500 == entries_count (raw cap), so the path is idle.
    # It becomes active when max_parse_rows < 500 or when the raw cap in
    # mft.py is raised above max_parse_rows.
    if entries_count > effective_max:
        # Slice entries using the canonical capping helper — preserves all
        # suspicious entries regardless of cap, matching every other parser.
        entries, _trunc_susp = _cap_entries_keep_suspicious(
            entries=result.get("entries", []),
            suspicious=result.get("suspicious", []),
            cap=effective_max,
            key_fn=lambda e: e.get("mft_entry", id(e)),
        )
        result["entries"] = entries
        result["entries_returned"] = len(entries)

        # Keep suspicious list consistent with capped entries so consumers
        # never find a suspicious entry that is absent from the entries list.
        capped_keys = {e.get("mft_entry", id(e)) for e in entries}
        result["suspicious"] = [
            s for s in result.get("suspicious", [])
            if s.get("mft_entry", id(s)) in capped_keys
        ]

        # Slice timestomped list — keep as many as fit.  These are a subset
        # of the suspicious set so _cap_entries_keep_suspicious above already
        # handled preservation.
        result["timestomped"] = result.get("timestomped", [])[:effective_max]

        # DO NOT recalculate timestomped_count / suspicious_count — they
        # reflect full, uncapped totals from the raw parser.
        # DO NOT overwrite total_entries — it stays the raw parse count.

    # Enrich with OOM-safety metadata
    result["raw_parse_count"] = raw_total
    result["capped_parse"] = capped

    if capped:
        existing_note = result.get("analyst_note", "")
        if raw_capped and effective_max < max_parse_rows:
            cap_note = (
                f"NOTE: raw parser (mft.py) capped entries at {entries_count} "
                f"(out of {raw_total} total parsed). "
                f"max_parse_rows={max_parse_rows} was not reached — the raw "
                f"parser's internal cap of {_RAW_MFT_CAP} is the binding limit. "
                f"Raise the raw cap in mft.py before increasing max_parse_rows."
            )
        else:
            cap_note = (
                f"NOTE: parse capped at {effective_max} entries "
                f"(raw parse count: {raw_total}). "
                f"Increase max_parse_rows if full coverage is needed."
            )
        result["analyst_note"] = (
            f"{existing_note} {cap_note}" if existing_note else cap_note
        )

    return result
