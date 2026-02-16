"""Tests for ~ (home directory) expansion in search tools."""

import shutil
import uuid
from collections.abc import Generator
from pathlib import Path

import pytest

from amplifier_module_tool_search.glob import GlobTool
from amplifier_module_tool_search.grep import GrepTool


class TestGlobExpandUser:
    """GlobTool expands ~ in path parameters."""

    @pytest.fixture
    def glob_tool(self, tmp_path: Path) -> GlobTool:
        tool = GlobTool({"working_dir": str(tmp_path)})
        return tool

    @pytest.mark.asyncio
    async def test_tilde_path_resolves_to_home(self, glob_tool: GlobTool, tmp_path: Path) -> None:
        """Passing ~ as path resolves to home directory, not literal '~' dir."""
        home = Path.home()
        result = await glob_tool.execute({"pattern": "*", "path": "~"})
        # Should NOT fail with "Path not found: ~"
        if not result.success:
            error_msg = result.error.get("message", "") if result.error else ""
            assert "not found" not in error_msg.lower(), f"~ was not expanded to {home}: {error_msg}"


class TestGrepExpandUser:
    """GrepTool expands ~ in path parameters."""

    @pytest.fixture
    def grep_tool(self) -> GrepTool:
        tool = GrepTool({"working_dir": "."})
        return tool

    @pytest.fixture
    def home_test_dir(self) -> Generator[Path, None, None]:
        """Create a temporary test directory under $HOME so ~/... paths work."""
        unique = f".test_expanduser_{uuid.uuid4().hex[:8]}"
        test_dir = Path.home() / unique
        test_dir.mkdir()
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_tilde_path_resolves_to_home_ripgrep(self, grep_tool: GrepTool, home_test_dir: Path) -> None:
        """Passing ~ as path resolves to home dir in ripgrep code path."""
        (home_test_dir / "hello.txt").write_text("findme_token_abc123", encoding="utf-8")

        tilde_path = "~/" + home_test_dir.name
        result = await grep_tool.execute(
            {
                "pattern": "findme_token_abc123",
                "path": tilde_path,
            }
        )
        assert result.success, f"Grep with ~ path failed: {result.error}"

    @pytest.mark.asyncio
    async def test_tilde_path_resolves_to_home_python_fallback(self, grep_tool: GrepTool, home_test_dir: Path) -> None:
        """Passing ~ as path resolves to home dir in Python fallback code path."""
        grep_tool.use_ripgrep = False

        (home_test_dir / "hello.txt").write_text("findme_token_def456", encoding="utf-8")

        tilde_path = "~/" + home_test_dir.name
        result = await grep_tool.execute(
            {
                "pattern": "findme_token_def456",
                "path": tilde_path,
            }
        )
        assert result.success, f"Grep (Python fallback) with ~ path failed: {result.error}"
