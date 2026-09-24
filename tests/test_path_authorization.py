"""Authorization tests for grep and glob search roots."""

from pathlib import Path
from typing import Any

import pytest

from amplifier_module_tool_search import mount
from amplifier_module_tool_search.glob import GlobTool
from amplifier_module_tool_search.grep import GrepTool
from amplifier_module_tool_search.paths import ACCESS_DENIED_MESSAGE


class _NoMatchProcess:
    returncode = 1
    stdout = ""
    stderr = ""


def _make_layout(tmp_path: Path) -> tuple[Path, Path]:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "inside.txt").write_text("inside-token", encoding="utf-8")
    (outside / "secret.txt").write_text("outside-secret-token", encoding="utf-8")
    return allowed, outside


def _assert_denied_without_disclosure(result: Any, outside: Path) -> None:
    assert not result.success
    assert result.output == ACCESS_DENIED_MESSAGE
    rendered = str(result.output) + str(result.error)
    assert str(outside) not in rendered
    assert "outside-secret-token" not in rendered
    assert "secret.txt" not in rendered


@pytest.mark.parametrize("tool_class", [GlobTool, GrepTool])
@pytest.mark.parametrize("request_kind", ["absolute", "traversal"])
@pytest.mark.asyncio
async def test_outside_paths_are_rejected(
    tmp_path: Path, tool_class: type[GlobTool] | type[GrepTool], request_kind: str
) -> None:
    allowed, outside = _make_layout(tmp_path)
    tool = tool_class({"working_dir": str(allowed)})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = False
    requested = str(outside) if request_kind == "absolute" else "../outside"
    request = (
        {"path": requested, "pattern": "*"}
        if isinstance(tool, GlobTool)
        else {
            "path": requested,
            "pattern": "outside-secret-token",
            "output_mode": "content",
        }
    )

    result = await tool.execute(request)

    _assert_denied_without_disclosure(result, outside)


@pytest.mark.parametrize("use_ripgrep", [True, False], ids=["ripgrep", "python"])
@pytest.mark.parametrize("request_kind", ["absolute", "traversal"])
@pytest.mark.asyncio
async def test_grep_engines_reject_outside_paths_before_search(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    use_ripgrep: bool,
    request_kind: str,
) -> None:
    allowed, outside = _make_layout(tmp_path)
    tool = GrepTool({"working_dir": str(allowed)})
    tool.use_ripgrep = use_ripgrep
    subprocess_called = False

    def unexpected_subprocess(*args: object, **kwargs: object) -> _NoMatchProcess:
        nonlocal subprocess_called
        subprocess_called = True
        return _NoMatchProcess()

    monkeypatch.setattr("amplifier_module_tool_search.grep.subprocess.run", unexpected_subprocess)
    requested = str(outside) if request_kind == "absolute" else "../outside"

    result = await tool.execute(
        {
            "path": requested,
            "pattern": "outside-secret-token",
            "output_mode": "content",
        }
    )

    _assert_denied_without_disclosure(result, outside)
    assert not subprocess_called


@pytest.mark.parametrize("tool_class", [GlobTool, GrepTool])
@pytest.mark.asyncio
async def test_symlink_escape_is_rejected(tmp_path: Path, tool_class: type[GlobTool] | type[GrepTool]) -> None:
    allowed, outside = _make_layout(tmp_path)
    link = allowed / "outside-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    tool = tool_class({"working_dir": str(allowed)})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = False
    request = (
        {"path": "outside-link", "pattern": "*"}
        if isinstance(tool, GlobTool)
        else {
            "path": "outside-link",
            "pattern": "outside-secret-token",
            "output_mode": "content",
        }
    )

    result = await tool.execute(request)

    _assert_denied_without_disclosure(result, outside)


@pytest.mark.parametrize("use_ripgrep", [True, False], ids=["ripgrep", "python"])
@pytest.mark.asyncio
async def test_grep_engines_accept_explicit_additional_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    use_ripgrep: bool,
) -> None:
    allowed, outside = _make_layout(tmp_path)
    tool = GrepTool({"working_dir": str(allowed), "allowed_paths": [".", str(outside)]})
    tool.use_ripgrep = use_ripgrep
    invoked_path: str | None = None

    def no_match_subprocess(command: list[str], **kwargs: object) -> _NoMatchProcess:
        nonlocal invoked_path
        invoked_path = command[-1]
        return _NoMatchProcess()

    monkeypatch.setattr("amplifier_module_tool_search.grep.subprocess.run", no_match_subprocess)

    result = await tool.execute({"path": str(outside), "pattern": "outside-secret-token"})

    assert result.success
    if use_ripgrep:
        assert invoked_path == str(outside.resolve())
    else:
        assert isinstance(result.output, dict)
        assert result.output["matches_count"] == 1


@pytest.mark.parametrize("tool_class", [GlobTool, GrepTool])
@pytest.mark.asyncio
async def test_explicit_additional_root_is_allowed(tmp_path: Path, tool_class: type[GlobTool] | type[GrepTool]) -> None:
    allowed, outside = _make_layout(tmp_path)
    tool = tool_class({"working_dir": str(allowed), "allowed_paths": [".", str(outside)]})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = False
        result = await tool.execute({"path": str(outside), "pattern": "outside-secret-token"})
        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["matches_count"] == 1
    else:
        result = await tool.execute({"path": str(outside), "pattern": "*.txt"})
        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["count"] == 1


@pytest.mark.parametrize("tool_class", [GlobTool, GrepTool])
@pytest.mark.asyncio
async def test_relative_in_root_search_still_works(tmp_path: Path, tool_class: type[GlobTool] | type[GrepTool]) -> None:
    allowed, _ = _make_layout(tmp_path)
    tool = tool_class({"working_dir": str(allowed)})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = False
        result = await tool.execute({"path": ".", "pattern": "inside-token"})
        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["matches_count"] == 1
    else:
        result = await tool.execute({"path": ".", "pattern": "*.txt"})
        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["count"] == 1


@pytest.mark.parametrize("tool_class", [GlobTool, GrepTool])
@pytest.mark.asyncio
async def test_glob_pattern_traversal_is_rejected(tmp_path: Path, tool_class: type[GlobTool] | type[GrepTool]) -> None:
    allowed, outside = _make_layout(tmp_path)
    tool = tool_class({"working_dir": str(allowed)})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = False
        result = await tool.execute({"path": ".", "pattern": "outside-secret-token", "glob": "../outside/*.txt"})
    else:
        result = await tool.execute({"path": ".", "pattern": "../outside/*.txt"})

    _assert_denied_without_disclosure(result, outside)


class RecordingCoordinator:
    def __init__(self, working_dir: Path) -> None:
        self.working_dir = working_dir
        self.tools: dict[str, Any] = {}

    def get_capability(self, name: str) -> str | None:
        return str(self.working_dir) if name == "session.working_dir" else None

    async def mount(self, category: str, tool: Any, name: str) -> None:
        assert category == "tools"
        self.tools[name] = tool


@pytest.mark.asyncio
async def test_mount_honors_module_allowed_paths_and_tool_override(tmp_path: Path) -> None:
    module_root = tmp_path / "module-root"
    grep_root = tmp_path / "grep-root"
    module_root.mkdir()
    grep_root.mkdir()
    coordinator = RecordingCoordinator(tmp_path)

    await mount(
        coordinator,  # type: ignore[arg-type]
        {
            "allowed_paths": [str(module_root)],
            "grep": {"allowed_paths": [str(grep_root)]},
        },
    )

    assert coordinator.tools["glob"].path_policy.allowed_roots == (module_root.resolve(),)
    assert coordinator.tools["grep"].path_policy.allowed_roots == (grep_root.resolve(),)
