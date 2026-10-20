"""Backend reporting and actionable, once-per-instance ripgrep notices."""

import asyncio
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from amplifier_core import ToolResult

from amplifier_module_tool_search.grep import GrepTool
from amplifier_module_tool_search.paths import ACCESS_DENIED_MESSAGE

MODES = ["files_with_matches", "content", "count"]
REAL_RG = shutil.which("rg")


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    (tmp_path / "sample.txt").write_text("needle\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def missing_rg(monkeypatch: pytest.MonkeyPatch) -> Mock:
    which = Mock(return_value=None)
    monkeypatch.setattr("amplifier_module_tool_search.grep.shutil.which", which)
    return which


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.asyncio
async def test_missing_rg_warns_once_without_changing_results(corpus: Path, missing_rg: Mock, mode: str) -> None:
    tool = GrepTool({"working_dir": str(corpus)})
    first = await tool.execute({"pattern": "needle", "output_mode": mode})

    assert first.success
    assert first.output["backend"] == "python"
    assert first.output["backend_reason"] == "ripgrep_unavailable"
    assert first.output["matches_count"] == 1
    warning = first.output["warning"]
    assert "slower" in warning
    assert "faster searches on large codebases" in warning
    assert "authorized" in warning and "ask the user" in warning
    assert "does not authorize installation" in warning
    assert "ignore-file handling, multiline matching, and counts" in warning

    # One notice across all output modes, not one notice per mode.
    for next_mode in MODES:
        after = await tool.execute({"pattern": "needle", "output_mode": next_mode})
        assert after.success
        assert after.output["backend_reason"] == "ripgrep_unavailable"
        assert "warning" not in after.output
    if mode == "content":
        assert first.output["results"][0]["content"] == "needle"
    elif mode == "count":
        assert first.output["counts"] == {str(corpus / "sample.txt"): 1}
    else:
        assert first.output["files"] == [str(corpus / "sample.txt")]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.asyncio
async def test_zero_matches_still_get_first_notice(corpus: Path, missing_rg: Mock, mode: str) -> None:
    result = await GrepTool({"working_dir": str(corpus)}).execute(
        {"pattern": "absent", "output_mode": mode}
    )
    assert result.success
    assert result.output["matches_count"] == 0
    assert result.output["backend"] == "python"
    assert "warning" in result.output


@pytest.mark.asyncio
async def test_failures_do_not_consume_notice(corpus: Path, missing_rg: Mock) -> None:
    tool = GrepTool({"working_dir": str(corpus)})
    for arguments in ({}, {"pattern": "["}, {"pattern": "needle", "path": "missing.txt"}):
        result = await tool.execute(arguments)
        assert not result.success
        assert not isinstance(result.output, dict)
        assert result.error

    for arguments in (
        {"pattern": "needle", "path": str(corpus.parent)},
        {"pattern": "needle", "glob": "../*"},
    ):
        denied = await tool.execute(arguments)
        assert not denied.success
        assert denied.output == ACCESS_DENIED_MESSAGE
        assert denied.error == {"message": ACCESS_DENIED_MESSAGE}

    success = await tool.execute({"pattern": "needle"})
    assert success.success
    assert "warning" in success.output


@pytest.mark.parametrize("executable", [None, "/tools/rg"])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.asyncio
async def test_policy_python_never_suggests_installation(
    corpus: Path, monkeypatch: pytest.MonkeyPatch, executable: str | None, mode: str
) -> None:
    which = Mock(return_value=executable)
    monkeypatch.setattr("amplifier_module_tool_search.grep.shutil.which", which)
    secret = corpus / "denied.txt"
    secret.write_text("needle private-marker\n", encoding="utf-8")
    tool = GrepTool({"working_dir": str(corpus), "denied_paths": ["denied.txt"]})
    which.reset_mock()
    run = Mock(side_effect=AssertionError("Policy must not invoke ripgrep"))
    monkeypatch.setattr("amplifier_module_tool_search.grep.subprocess.run", run)

    before = await tool.execute({"pattern": "needle", "output_mode": mode})
    after = await tool.execute({"pattern": "needle", "output_mode": mode})
    assert before.success and after.success
    assert before.output == after.output
    assert before.output["backend"] == "python"
    assert before.output["backend_reason"] == "path_policy"
    assert before.output["matches_count"] == 1
    assert "warning" not in before.output
    assert "enforce configured read denials" in before.output["note"]
    assert "denied.txt" not in str(before.output)
    assert "private-marker" not in str(before.output)
    which.assert_not_called()
    run.assert_not_called()


@pytest.mark.asyncio
async def test_explicitly_disabled_instance_stays_python(corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    which = Mock(return_value="/tools/rg")
    monkeypatch.setattr("amplifier_module_tool_search.grep.shutil.which", which)
    tool = GrepTool({"working_dir": str(corpus)})
    tool.use_ripgrep = False
    which.reset_mock()
    result = await tool.execute({"pattern": "needle"})
    assert result.success
    assert result.output["backend"] == "python"
    assert result.output["backend_reason"] == "disabled"
    assert "warning" not in result.output
    which.assert_not_called()


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.asyncio
async def test_newly_available_rg_is_used_without_restart(corpus: Path, missing_rg: Mock, mode: str) -> None:
    # Use the actual binary and argv, not a mocked successful search.
    actual_rg = REAL_RG
    if not actual_rg:
        pytest.skip("real ripgrep not available")
    tool = GrepTool({"working_dir": str(corpus)})
    arguments = {"pattern": "needle", "output_mode": mode}
    first = await tool.execute(arguments)
    assert first.output["backend"] == "python"
    assert "warning" in first.output

    missing_rg.return_value = actual_rg
    after = await tool.execute(arguments)
    assert after.success
    assert after.output["backend"] == "ripgrep"
    assert after.output["backend_reason"] == "available"
    assert after.output["matches_count"] == first.output["matches_count"] == 1
    result_key = {"files_with_matches": "files", "content": "results", "count": "counts"}[mode]
    assert after.output[result_key] == first.output[result_key]
    assert "warning" not in after.output
    assert tool.rg_path == actual_rg

    missing_rg.reset_mock()
    again = await tool.execute(arguments)
    assert again.success
    assert again.output == after.output
    missing_rg.assert_not_called()


@pytest.mark.asyncio
async def test_rg_appearing_before_first_call_needs_no_warning(corpus: Path, missing_rg: Mock) -> None:
    tool = GrepTool({"working_dir": str(corpus)})
    missing_rg.return_value = "/tools/rg"
    engine = AsyncMock(return_value=ToolResult(success=True, output={"files": []}))
    tool._execute_ripgrep = engine
    result = await tool.execute({"pattern": "needle"})
    engine.assert_awaited_once()
    assert result.output["backend"] == "ripgrep"
    assert "warning" not in result.output


@pytest.mark.asyncio
async def test_rg_execution_failure_is_not_retried(corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("amplifier_module_tool_search.grep.shutil.which", lambda _: "/tools/rg")
    tool = GrepTool({"working_dir": str(corpus)})
    monkeypatch.setattr(
        "amplifier_module_tool_search.grep.subprocess.run",
        Mock(side_effect=FileNotFoundError("rg removed")),
    )
    python = AsyncMock()
    monkeypatch.setattr(tool, "_execute_python", python)
    result = await tool.execute({"pattern": "needle"})
    assert not result.success
    assert "rg removed" in result.error["message"]
    assert isinstance(result.output, str)
    python.assert_not_awaited()


@pytest.mark.asyncio
async def test_notice_is_once_across_concurrent_successes(corpus: Path, missing_rg: Mock) -> None:
    tool = GrepTool({"working_dir": str(corpus)})

    async def yielding_engine(_):
        await asyncio.sleep(0)
        return ToolResult(success=True, output={"files": []})

    tool._execute_python = yielding_engine
    results = await asyncio.gather(*(tool.execute({"pattern": "needle"}) for _ in range(5)))
    assert all(result.success for result in results)
    assert sum("warning" in result.output for result in results) == 1


@pytest.mark.asyncio
async def test_notice_is_per_instance(corpus: Path, missing_rg: Mock) -> None:
    tools = [GrepTool({"working_dir": str(corpus)}) for _ in range(2)]
    for tool in tools:
        result = await tool.execute({"pattern": "needle"})
        assert result.success
        assert "warning" in result.output