"""Tests for authorized ~ (home directory) expansion in search tools."""

from pathlib import Path

import pytest

from amplifier_module_tool_search.glob import GlobTool
from amplifier_module_tool_search.grep import GrepTool
from amplifier_module_tool_search.paths import ACCESS_DENIED_MESSAGE


@pytest.mark.asyncio
async def test_glob_rejects_home_when_not_allowed(tmp_path: Path) -> None:
    result = await GlobTool({"working_dir": str(tmp_path)}).execute({"pattern": "*", "path": "~"})

    assert not result.success
    assert result.output == ACCESS_DENIED_MESSAGE
    assert str(Path.home()) not in str(result.output)


@pytest.mark.asyncio
async def test_glob_allows_home_when_explicitly_configured(tmp_path: Path) -> None:
    result = await GlobTool({"working_dir": str(tmp_path), "allowed_paths": [str(Path.home())]}).execute(
        {"pattern": "__definitely_missing_search_test_*", "path": "~"}
    )

    assert result.success
    assert isinstance(result.output, dict)
    assert result.output["base_path"] == str(Path.home().resolve())


@pytest.mark.parametrize("use_ripgrep", [True, False], ids=["ripgrep", "python"])
@pytest.mark.asyncio
async def test_grep_rejects_home_when_not_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, use_ripgrep: bool
) -> None:
    tool = GrepTool({"working_dir": str(tmp_path)})
    tool.use_ripgrep = use_ripgrep
    subprocess_called = False

    def unexpected_subprocess(*args: object, **kwargs: object) -> None:
        nonlocal subprocess_called
        subprocess_called = True

    monkeypatch.setattr("amplifier_module_tool_search.grep.subprocess.run", unexpected_subprocess)

    result = await tool.execute({"pattern": "secret", "path": "~", "output_mode": "content"})

    assert not result.success
    assert result.output == ACCESS_DENIED_MESSAGE
    assert str(Path.home()) not in str(result.output)
    assert not subprocess_called
