"""Tests for scripts.parse_token_usage — token extraction from Claude output."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# Import from scripts directory
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from parse_token_usage import parse_token_counts, write_token_log


class TestParseTokenCounts:
    def test_no_token_info(self):
        result = parse_token_counts("Just some random output with no token data")
        assert result["tokens_found"] is False

    def test_empty_string(self):
        result = parse_token_counts("")
        assert result["tokens_found"] is False

    def test_total_tokens_pattern(self):
        result = parse_token_counts("Analysis complete. Total tokens: 15,234")
        assert result["tokens_found"] is True
        assert result["total_tokens"] == 15234

    def test_input_output_pattern(self):
        text = "Input: 10,000 tokens\nOutput: 2,500 tokens"
        result = parse_token_counts(text)
        assert result["tokens_found"] is True
        assert result["input_tokens"] == 10000
        assert result["output_tokens"] == 2500
        assert result["total_tokens"] == 12500

    def test_cost_pattern(self):
        result = parse_token_counts("Done. Cost: $0.0342")
        assert result["tokens_found"] is True
        assert result["estimated_cost_usd"] == pytest.approx(0.0342)

    def test_cache_patterns(self):
        text = "cache_read: 5000\ncache_creation: 1200"
        result = parse_token_counts(text)
        assert result["tokens_found"] is True
        assert result["cache_read_tokens"] == 5000
        assert result["cache_write_tokens"] == 1200

    def test_json_usage_pattern(self):
        text = 'Some output... "usage": {"input_tokens": 8000, "output_tokens": 1500} ...more'
        result = parse_token_counts(text)
        assert result["tokens_found"] is True
        assert result["input_tokens"] == 8000
        assert result["output_tokens"] == 1500

    def test_combined_patterns(self):
        text = (
            "Input: 10,000 tokens\n"
            "Output: 2,000 tokens\n"
            "Cost: $0.05\n"
            "cache_read: 3000\n"
        )
        result = parse_token_counts(text)
        assert result["tokens_found"] is True
        assert result["input_tokens"] == 10000
        assert result["output_tokens"] == 2000
        assert result["total_tokens"] == 12000
        assert result["estimated_cost_usd"] == pytest.approx(0.05)
        assert result["cache_read_tokens"] == 3000

    def test_no_commas_in_numbers(self):
        result = parse_token_counts("Total tokens: 5000")
        assert result["total_tokens"] == 5000

    def test_rate_limit_message_no_tokens(self):
        """52-char rate limit response should have no token info."""
        result = parse_token_counts("Rate limit exceeded. Please try again in 5 minutes.")
        assert result["tokens_found"] is False


class TestWriteTokenLog:
    def test_writes_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASEFILE_EXAMINER", "testuser")
        token_info = {"tokens_found": True, "total_tokens": 1000}
        log_file = write_token_log(
            case_dir=str(tmp_path),
            iteration=1,
            phase="main",
            token_info=token_info,
            output_chars=500,
        )
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["iteration"] == 1
        assert entry["phase"] == "main"
        assert entry["total_tokens"] == 1000
        assert entry["output_chars"] == 500
        assert entry["examiner"] == "testuser"
        assert entry["source"] == "ralph_token_tracker"

    def test_appends_multiple(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASEFILE_EXAMINER", "tester")
        for i in range(3):
            write_token_log(
                case_dir=str(tmp_path),
                iteration=i + 1,
                phase="main",
                token_info={"tokens_found": True, "total_tokens": i * 1000},
                output_chars=100,
            )
        log_file = tmp_path / "audit" / "ralph_token_usage.jsonl"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_creates_audit_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CASEFILE_EXAMINER", "tester")
        case_dir = tmp_path / "newcase"
        write_token_log(
            case_dir=str(case_dir),
            iteration=1,
            phase="main",
            token_info={"tokens_found": False},
            output_chars=52,
        )
        assert (case_dir / "audit" / "ralph_token_usage.jsonl").exists()
