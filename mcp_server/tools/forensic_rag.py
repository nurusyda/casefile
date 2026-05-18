"""Forensic Knowledge RAG — keyword-based search over curated DFIR references.

Provides ``forensic_knowledge_search()`` MCP tool that searches a bundled
knowledge base of MITRE ATT&CK techniques, artifact guides, Sigma rule
patterns, and forensic methodology references.

Zero external dependencies.  No embeddings, no vector DB, no PyTorch.
Uses TF-IDF-inspired keyword scoring against a JSON knowledge base.

The knowledge base ships as ``data/forensic_knowledge.json`` relative to
this file.  Records are loaded once at import time.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Optional

from mcp_server.tools._shared import audit_log


# ---------------------------------------------------------------------------
# Knowledge base loading
# ---------------------------------------------------------------------------

_KB_PATH = Path(__file__).resolve().parent.parent / "data" / "forensic_knowledge.json"

_RECORDS: list[dict] = []
_IDF: dict[str, float] = {}


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanumeric (preserving dots for IDs like T1543.003)."""
    raw = re.split(r"[^a-z0-9.]+", text.lower())
    tokens: list[str] = []
    for t in raw:
        t = t.strip(".")
        if len(t) >= 2:
            tokens.append(t)
            # Also add dot-split parts for partial matching
            if "." in t:
                for part in t.split("."):
                    if len(part) >= 2:
                        tokens.append(part)
    return tokens


def _build_index(records: list[dict]) -> dict[str, float]:
    """Build IDF scores from the loaded records."""
    doc_count = len(records)
    if doc_count == 0:
        return {}
    df: dict[str, int] = {}
    for rec in records:
        blob = _record_to_text(rec)
        unique_tokens = set(_tokenize(blob))
        for tok in unique_tokens:
            df[tok] = df.get(tok, 0) + 1
    return {tok: math.log(doc_count / count) for tok, count in df.items()}


def _record_to_text(rec: dict) -> str:
    """Flatten a record into a single searchable string."""
    parts: list[str] = []
    for key in ("name", "description", "category", "tactic", "detection_logic",
                "forensic_value", "content", "title"):
        val = rec.get(key)
        if val:
            parts.append(str(val))
    # keywords and tags get extra weight by repeating
    keywords = rec.get("keywords", [])
    if isinstance(keywords, list):
        parts.append(" ".join(str(k) for k in keywords) * 2)
    tags = rec.get("tags", [])
    if isinstance(tags, list):
        parts.append(" ".join(str(t) for t in tags) * 2)
    # artifacts, tools, key_fields, caveats
    for listkey in ("artifacts", "tools", "key_fields", "caveats",
                     "best_practices"):
        lst = rec.get(listkey)
        if isinstance(lst, list):
            parts.append(" ".join(str(v) for v in lst))
    # key_event_ids, key_locations, key_plugins — dict values
    for dictkey in ("key_event_ids", "key_locations", "key_plugins"):
        d = rec.get(dictkey)
        if isinstance(d, dict):
            parts.append(" ".join(f"{k} {v}" for k, v in d.items()))
    return " ".join(parts)


def _load_kb() -> None:
    """Load the knowledge base and build the search index."""
    global _RECORDS, _IDF  # noqa: PLW0603
    if _RECORDS:
        return
    if not _KB_PATH.exists():
        return
    try:
        with open(_KB_PATH, encoding="utf-8") as f:
            data = json.load(f)
        _RECORDS = data if isinstance(data, list) else data.get("records", [])
        _IDF = _build_index(_RECORDS)
    except (json.JSONDecodeError, OSError, KeyError):
        _RECORDS = []
        _IDF = {}


# Load at import time
_load_kb()


# ---------------------------------------------------------------------------
# Search function
# ---------------------------------------------------------------------------

def _score_record(rec: dict, query_tokens: list[str]) -> float:
    """Score a record against query tokens using TF-IDF-inspired weighting."""
    text = _record_to_text(rec)
    doc_tokens = _tokenize(text)
    if not doc_tokens:
        return 0.0
    # Term frequency in this document
    tf: dict[str, int] = {}
    for tok in doc_tokens:
        tf[tok] = tf.get(tok, 0) + 1
    score = 0.0
    for qt in query_tokens:
        # Exact match
        if qt in tf:
            idf = _IDF.get(qt, 1.0)
            score += (1 + math.log(tf[qt])) * idf
        else:
            # Partial match (query token is substring of doc token)
            for dt, count in tf.items():
                if qt in dt or dt in qt:
                    idf = _IDF.get(dt, 0.5)
                    score += 0.5 * (1 + math.log(count)) * idf
                    break
    # Bonus for title and id keyword match
    title_text = (rec.get("title", "") + " " + rec.get("id", "")).lower()
    for qt in query_tokens:
        if qt in title_text:
            score += 5.0
    # Bonus for technique_id match (exact or prefix)
    if query_tokens:
        tid = rec.get("technique_id", "").lower()
        if tid:
            for qt in query_tokens:
                if qt == tid or tid.startswith(qt) or qt == tid.replace(".", ""):
                    score += 10.0
                    break
    # Bonus for category match
    cat = rec.get("category") or rec.get("source", "")
    for qt in query_tokens:
        if qt in cat.lower():
            score *= 1.3
            break
    tid = rec.get("technique_id", "").lower()
    for qt in query_tokens:
        if qt == tid or qt == tid.replace(".", ""):
            score += 10.0  # Strong boost for exact technique ID match
            break
    return score


def search_knowledge(
    query: str,
    *,
    max_results: int = 5,
    category: Optional[str] = None,
) -> list[dict]:
    """Search the forensic knowledge base.

    Parameters
    ----------
    query : str
        Free-text search query (e.g. "lateral movement smb", "T1543.003",
        "prefetch analysis", "event log clearing").
    max_results : int
        Maximum number of results to return (default 5, max 10).
    category : str, optional
        Filter by category: "mitre_attack", "artifact_guide", "sigma_rule",
        "methodology".  If None, searches all categories.

    Returns
    -------
    list[dict]
        Matching records sorted by relevance score, each with an added
        ``relevance_score`` field.
    """
    import time, uuid
    _t0 = time.monotonic()
    _inv_id = str(uuid.uuid4())
    _load_kb()
    if not _RECORDS:
        audit_log(
            tool="search_knowledge",
            invocation_id=_inv_id,
            cmd=f"search_knowledge(query={query!r}, max_results={max_results}, category={category!r})",
            returncode=0,
            stdout_lines=0,
            stderr_excerpt="Knowledge base empty",
            parsed_record_count=0,
            duration_ms=round((time.monotonic() - _t0) * 1000),
            extra={"query": query, "category_filter": category or "all", "result": "kb_empty"},
        )
        return []

    max_results = min(max(1, max_results), 10)
    query_tokens = _tokenize(query)
    if not query_tokens:
        audit_log(
            tool="search_knowledge",
            invocation_id=_inv_id,
            cmd=f"search_knowledge(query={query!r}, max_results={max_results}, category={category!r})",
            returncode=0,
            stdout_lines=0,
            stderr_excerpt="No query tokens",
            parsed_record_count=0,
            duration_ms=round((time.monotonic() - _t0) * 1000),
            extra={"query": query, "category_filter": category or "all", "result": "no_tokens"},
        )
        return []

    candidates = _RECORDS
    if category:
        cat_lower = category.lower().strip()
        def _norm_cat(r: dict) -> str:
            _c = r.get("category") or r.get("source", "")
            return "sigma_rule" if _c == "sigma" else _c
        candidates = [r for r in _RECORDS if _norm_cat(r).lower() == cat_lower]

    scored: list[tuple[float, dict]] = []
    for rec in candidates:
        s = _score_record(rec, query_tokens)
        if s > 0:
            result = dict(rec)
            result["relevance_score"] = round(s, 3)
            if "category" not in result:
                _src = result.get("source", "unknown")
                result["category"] = "sigma_rule" if _src == "sigma" else _src
            scored.append((s, result))

    scored.sort(key=lambda x: x[0], reverse=True)
    _results = [item[1] for item in scored[:max_results]]
    _elapsed = round((time.monotonic() - _t0) * 1000)
    audit_log(
        tool="search_knowledge",
        invocation_id=_inv_id,
        cmd=f"search_knowledge(query={query!r}, max_results={max_results}, category={category!r})",
        returncode=0,
        stdout_lines=len(_results),
        stderr_excerpt="",
        parsed_record_count=len(_results),
        duration_ms=_elapsed,
        extra={"query": query, "category_filter": category or "all"},
    )
    return _results


def get_knowledge_stats() -> dict:
    """Return statistics about the loaded knowledge base."""
    import uuid
    _load_kb()
    categories: dict[str, int] = {}
    for rec in _RECORDS:
        _src = rec.get("category") or rec.get("source", "unknown")
        cat = "sigma_rule" if _src == "sigma" else _src
        categories[cat] = categories.get(cat, 0) + 1
    _stats = {
        "total_records": len(_RECORDS),
        "categories": categories,
        "index_terms": len(_IDF),
        "kb_path": str(_KB_PATH),
        "kb_loaded": len(_RECORDS) > 0,
    }
    audit_log(
        tool="get_knowledge_stats",
        invocation_id=str(uuid.uuid4()),
        cmd="get_knowledge_stats()",
        returncode=0,
        stdout_lines=1,
        stderr_excerpt="",
        parsed_record_count=len(_RECORDS),
        duration_ms=0,
    )
    return _stats
