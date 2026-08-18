"""Tests for count output mode.

These tests exercise the real ripgrep binary rather than canned subprocess
output. The behaviour under test is what rg actually prints -- specifically
that rg omits the "path:" prefix when handed a single explicit file -- so a
mocked subprocess would only assert our assumption about rg, not rg itself.
"""

import shutil
from pathlib import Path

import pytest

from amplifier_module_tool_search.grep import GrepTool

requires_ripgrep = pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep (rg) not installed")


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Two files with a known, unequal number of matches."""
    (tmp_path / "sample.py").write_text("findme\nfindme\nnope\nfindme\n")
    (tmp_path / "other.py").write_text("nope\nfindme\n")
    return tmp_path


@pytest.fixture
def grep_tool(corpus: Path) -> GrepTool:
    return GrepTool({"working_dir": str(corpus)})


class TestCountModeSingleFile:
    """count mode must report counts when path is a single file, not a directory."""

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_single_file_path_reports_counts(self, grep_tool: GrepTool, corpus: Path) -> None:
        """Regression: rg drops the 'path:' prefix for a single explicit file.

        The count parser splits on the last colon, so an unprefixed "3" was
        discarded and the tool reported zero matches for a file with three.
        """
        assert grep_tool.use_ripgrep, "this test is only meaningful on the ripgrep path"
        target = corpus / "sample.py"

        result = await grep_tool.execute({"pattern": "findme", "path": str(target), "output_mode": "count"})

        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["total_matches"] == 3
        assert result.output["counts"] == {str(target): 3}

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_directory_path_still_reports_counts(self, grep_tool: GrepTool, corpus: Path) -> None:
        """Control: the multi-file case that already worked must keep working."""
        result = await grep_tool.execute({"pattern": "findme", "path": str(corpus), "output_mode": "count"})

        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["counts"] == {
            str(corpus / "sample.py"): 3,
            str(corpus / "other.py"): 1,
        }
        assert result.output["total_matches"] == 4

    @requires_ripgrep
    @pytest.mark.asyncio
    async def test_single_file_count_matches_content_mode(self, grep_tool: GrepTool, corpus: Path) -> None:
        """count and content modes must agree on how many matches a file has."""
        target = str(corpus / "sample.py")

        counted = await grep_tool.execute({"pattern": "findme", "path": target, "output_mode": "count"})
        contented = await grep_tool.execute({"pattern": "findme", "path": target, "output_mode": "content"})

        assert counted.success and contented.success
        assert isinstance(counted.output, dict)
        assert isinstance(contented.output, dict)
        assert counted.output["total_matches"] == contented.output["matches_count"]
