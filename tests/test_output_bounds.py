"""Tests for grep's content-mode output bounds (per-line clipping + total-bytes cap).

Without these bounds, a single match line from a minified/generated file (large
JSON snapshot, generated HTML, etc.) can blow up a content-mode result to
hundreds of KB or more, since head_limit only bounds the number of matches,
not the size of each match's content. These tests exercise the real ripgrep
binary (the fast path) and, where noted, force the Python fallback path via
`tool.use_ripgrep = False` to prove both paths clip identically.
"""

import json
import shutil
from pathlib import Path

import pytest

from amplifier_module_tool_search.grep import GrepTool

requires_ripgrep = pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep (rg) not installed")


@pytest.fixture
def long_line_corpus(tmp_path: Path) -> Path:
    """One line far longer than the default max_line_chars, plus one short line."""
    long_line = "findme" + ("x" * 3000)
    short_line = "findme short"
    (tmp_path / "sample.txt").write_text(f"{long_line}\n{short_line}\n")
    return tmp_path


@pytest.fixture
def many_matches_corpus(tmp_path: Path) -> Path:
    """Many files, each with one match whose content is a few hundred bytes."""
    line = "findme " + ("z" * 500)
    for i in range(50):
        (tmp_path / f"file{i:02d}.txt").write_text(line + "\n")
    return tmp_path


class TestPerLineClipping:
    """Item 1 & 2: long lines are clipped with the marker; short lines are untouched."""

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_long_line_is_clipped_with_marker(self, long_line_corpus: Path) -> None:
        tool = GrepTool({"working_dir": str(long_line_corpus)})
        result = await tool.execute({"pattern": "findme", "output_mode": "content"})

        assert result.success
        assert isinstance(result.output, dict)
        contents = [m["content"] for m in result.output["results"]]

        clipped = [c for c in contents if c.endswith("... [truncated]")]
        assert len(clipped) == 1
        assert len(clipped[0]) == GrepTool.DEFAULT_MAX_LINE_CHARS + len("... [truncated]")

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_short_line_is_untouched(self, long_line_corpus: Path) -> None:
        tool = GrepTool({"working_dir": str(long_line_corpus)})
        result = await tool.execute({"pattern": "findme", "output_mode": "content"})

        assert result.success
        assert isinstance(result.output, dict)
        contents = [m["content"] for m in result.output["results"]]

        assert "findme short" in contents
        untouched = next(c for c in contents if c == "findme short")
        assert not untouched.endswith("... [truncated]")


class TestTotalBytesCap:
    """Item 3: many matches under the per-line limit still hit the total-bytes cap."""

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_total_bytes_cap_engages(self, many_matches_corpus: Path) -> None:
        tool = GrepTool({"working_dir": str(many_matches_corpus), "max_result_bytes": 2000})
        result = await tool.execute({"pattern": "findme", "output_mode": "content", "head_limit": 0})

        assert result.success
        assert isinstance(result.output, dict)

        assert result.output["total_matches"] == 50
        assert result.output["matches_count"] < 50
        assert result.output.get("results_truncated_bytes") is True

        serialized_size = len(json.dumps(result.output["results"]).encode("utf-8"))
        # The cap bounds the accumulated per-item size to <= max_result_bytes;
        # the surrounding JSON array punctuation (commas/brackets) is the only
        # slack allowed on top of that.
        assert serialized_size <= 2000 + 100


class TestConfigOverrides:
    """Item 4: both knobs are configurable independently."""

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_max_line_chars_override_is_honored(self, long_line_corpus: Path) -> None:
        tool = GrepTool({"working_dir": str(long_line_corpus), "max_line_chars": 50})
        result = await tool.execute({"pattern": "findme", "output_mode": "content"})

        assert result.success
        assert isinstance(result.output, dict)
        contents = [m["content"] for m in result.output["results"]]

        clipped = [c for c in contents if c.endswith("... [truncated]")]
        assert len(clipped) == 1
        assert len(clipped[0]) == 50 + len("... [truncated]")

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_max_result_bytes_override_is_honored(self, many_matches_corpus: Path) -> None:
        small_cap_tool = GrepTool({"working_dir": str(many_matches_corpus), "max_result_bytes": 1000})
        large_cap_tool = GrepTool({"working_dir": str(many_matches_corpus), "max_result_bytes": 20_000})

        small_result = await small_cap_tool.execute({"pattern": "findme", "output_mode": "content", "head_limit": 0})
        large_result = await large_cap_tool.execute({"pattern": "findme", "output_mode": "content", "head_limit": 0})

        assert small_result.success and large_result.success
        assert isinstance(small_result.output, dict)
        assert isinstance(large_result.output, dict)

        # A smaller byte budget must keep strictly fewer (or equal) matches.
        assert small_result.output["matches_count"] < large_result.output["matches_count"]


class TestBoundsCanBeDisabled:
    """Item 5: setting either bound to 0 disables it."""

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_zero_max_line_chars_disables_clipping(self, long_line_corpus: Path) -> None:
        tool = GrepTool({"working_dir": str(long_line_corpus), "max_line_chars": 0})
        result = await tool.execute({"pattern": "findme", "output_mode": "content"})

        assert result.success
        assert isinstance(result.output, dict)
        contents = [m["content"] for m in result.output["results"]]

        assert not any(c.endswith("... [truncated]") for c in contents)
        long_line = next(c for c in contents if len(c) > GrepTool.DEFAULT_MAX_LINE_CHARS)
        assert long_line == "findme" + ("x" * 3000)

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_zero_max_result_bytes_disables_cap(self, many_matches_corpus: Path) -> None:
        tool = GrepTool({"working_dir": str(many_matches_corpus), "max_result_bytes": 0})
        result = await tool.execute({"pattern": "findme", "output_mode": "content", "head_limit": 0})

        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["matches_count"] == 50
        assert "results_truncated_bytes" not in result.output


class TestRipgrepAndFallbackAgree:
    """Item 6: ripgrep and the Python fallback path clip identically."""

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_line_clipping_matches_across_both_paths(self, long_line_corpus: Path) -> None:
        rg_tool = GrepTool({"working_dir": str(long_line_corpus)})
        assert rg_tool.use_ripgrep, "this test requires ripgrep to be available for the comparison"
        rg_result = await rg_tool.execute({"pattern": "findme", "output_mode": "content"})

        fallback_tool = GrepTool({"working_dir": str(long_line_corpus)})
        fallback_tool.use_ripgrep = False  # force the Python re fallback path
        fallback_result = await fallback_tool.execute({"pattern": "findme", "output_mode": "content"})

        assert rg_result.success and fallback_result.success
        assert isinstance(rg_result.output, dict)
        assert isinstance(fallback_result.output, dict)

        rg_contents = sorted(m["content"] for m in rg_result.output["results"])
        fallback_contents = sorted(m["content"] for m in fallback_result.output["results"])
        assert rg_contents == fallback_contents

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_total_bytes_cap_matches_across_both_paths(self, many_matches_corpus: Path) -> None:
        config = {"working_dir": str(many_matches_corpus), "max_result_bytes": 2000}

        rg_tool = GrepTool(config)
        assert rg_tool.use_ripgrep, "this test requires ripgrep to be available for the comparison"
        rg_result = await rg_tool.execute({"pattern": "findme", "output_mode": "content", "head_limit": 0})

        fallback_tool = GrepTool(config)
        fallback_tool.use_ripgrep = False
        fallback_result = await fallback_tool.execute({"pattern": "findme", "output_mode": "content", "head_limit": 0})

        assert rg_result.success and fallback_result.success
        assert isinstance(rg_result.output, dict)
        assert isinstance(fallback_result.output, dict)

        assert rg_result.output["matches_count"] == fallback_result.output["matches_count"]
        assert rg_result.output.get("results_truncated_bytes") is True
        assert fallback_result.output.get("results_truncated_bytes") is True
