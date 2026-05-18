"""Tests for mcp_server.tools.forensic_rag — forensic knowledge search."""

from __future__ import annotations

import pytest

from mcp_server.tools.forensic_rag import (
    get_knowledge_stats,
    search_knowledge,
)


# ---------------------------------------------------------------------------
# Knowledge base loading
# ---------------------------------------------------------------------------


class TestKnowledgeStats:
    def test_kb_loaded(self):
        stats = get_knowledge_stats()
        assert stats["kb_loaded"] is True
        assert stats["total_records"] >= 20

    def test_categories_present(self):
        stats = get_knowledge_stats()
        cats = stats["categories"]
        assert "mitre_attack" in cats
        assert "artifact_guide" in cats
        assert "sigma_rule" in cats
        assert "methodology" in cats

    def test_index_built(self):
        stats = get_knowledge_stats()
        assert stats["index_terms"] > 50


# ---------------------------------------------------------------------------
# Search — MITRE ATT&CK techniques
# ---------------------------------------------------------------------------


class TestSearchMitreAttack:
    def test_search_powershell(self):
        results = search_knowledge("powershell execution")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "ATT-T1059.001" in top_ids or "SIGMA-SUSPICIOUS-POWERSHELL" in top_ids

    def test_search_by_technique_id(self):
        results = search_knowledge("T1543.003")
        assert len(results) > 0
        assert results[0]["technique_id"] == "T1543.003"

    def test_search_lateral_movement(self):
        results = search_knowledge("lateral movement smb admin share")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "ATT-T1021.002" in top_ids

    def test_search_credential_dumping(self):
        results = search_knowledge("lsass mimikatz credential dump")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "ATT-T1003.001" in top_ids or "SIGMA-PROCDUMP" in top_ids

    def test_search_masquerading(self):
        results = search_knowledge("fake csrss masquerade wrong path")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "ATT-T1036.005" in top_ids or "SIGMA-MASQUERADING" in top_ids

    def test_search_log_clearing(self):
        results = search_knowledge("wevtutil event log clearing 1102")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "ATT-T1070.001" in top_ids or "SIGMA-LOG-CLEARING" in top_ids

    def test_search_service_persistence(self):
        results = search_knowledge("service 7045 persistence auto-start")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "ATT-T1543.003" in top_ids or "SIGMA-SERVICE-INSTALL" in top_ids


# ---------------------------------------------------------------------------
# Search — artifact guides
# ---------------------------------------------------------------------------


class TestSearchArtifactGuides:
    def test_search_prefetch(self):
        results = search_knowledge("prefetch execution evidence")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "GUIDE-PREFETCH" in top_ids or "ARTIFACT-PREFETCH-TIMING" in top_ids

    def test_search_amcache(self):
        results = search_knowledge("amcache sha1 hash application")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "GUIDE-AMCACHE" in top_ids

    def test_search_mft_timestomping(self):
        results = search_knowledge("mft timestomping standard_information file_name")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "GUIDE-MFT" in top_ids

    def test_search_memory_volatility(self):
        results = search_knowledge("memory volatility pslist process")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "GUIDE-MEMORY" in top_ids

    def test_search_event_log_4624(self):
        results = search_knowledge("4624 logon event")
        assert len(results) > 0
        top_ids = [r["id"] for r in results[:3]]
        assert "GUIDE-EVENTLOGS" in top_ids or "ATT-T1078" in top_ids or "WIN-EVENTID-4624" in top_ids


# ---------------------------------------------------------------------------
# Search — category filtering
# ---------------------------------------------------------------------------


class TestSearchCategoryFilter:
    def test_filter_mitre_only(self):
        results = search_knowledge("service persistence", category="mitre_attack")
        for r in results:
            assert r["category"] == "mitre_attack"

    def test_filter_artifact_guide_only(self):
        results = search_knowledge("execution", category="artifact_guide")
        for r in results:
            assert r["category"] == "artifact_guide"

    def test_filter_sigma_only(self):
        results = search_knowledge("service lateral", category="sigma_rule")
        for r in results:
            assert r["category"] == "sigma_rule"

    def test_filter_methodology_only(self):
        results = search_knowledge("timeline correlation", category="methodology")
        assert len(results) > 0
        for r in results:
            assert r["category"] == "methodology"


# ---------------------------------------------------------------------------
# Search — edge cases
# ---------------------------------------------------------------------------


class TestSearchEdgeCases:
    def test_empty_query_returns_empty(self):
        results = search_knowledge("")
        assert results == []

    def test_nonsense_query_returns_empty_or_low(self):
        results = search_knowledge("xyzzyfoobarbaz")
        # May return 0 or low-score partial matches
        assert len(results) <= 3

    def test_max_results_respected(self):
        results = search_knowledge("windows", max_results=3)
        assert len(results) <= 3

    def test_max_results_capped_at_10(self):
        results = search_knowledge("windows", max_results=99)
        assert len(results) <= 10

    def test_relevance_score_present(self):
        results = search_knowledge("powershell")
        assert len(results) > 0
        assert "relevance_score" in results[0]
        assert results[0]["relevance_score"] > 0

    def test_results_sorted_by_score(self):
        results = search_knowledge("service persistence execution")
        scores = [r["relevance_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_case_insensitive(self):
        r1 = search_knowledge("POWERSHELL")
        r2 = search_knowledge("powershell")
        assert len(r1) > 0
        assert r1[0]["id"] == r2[0]["id"]

    def test_event_id_search(self):
        """Searching for a specific Event ID finds relevant records."""
        results = search_knowledge("7045")
        assert len(results) > 0
        # Should find service installation references
        all_keywords = []
        for r in results[:3]:
            kw = r.get("keywords") or r.get("tags", [])
            all_keywords.extend(kw if isinstance(kw, list) else [kw])
        assert any("7045" in str(k) for k in all_keywords)
