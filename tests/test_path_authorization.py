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


@pytest.mark.parametrize("pattern", ["--files", "--follow", "--pre=unexpected", "-n"])
@pytest.mark.parametrize("output_mode", ["files_with_matches", "content", "count"])
@pytest.mark.asyncio
async def test_real_ripgrep_treats_leading_dash_patterns_as_data(
    tmp_path: Path, pattern: str, output_mode: str
) -> None:
    tool = GrepTool({"working_dir": str(tmp_path)})
    if not tool.use_ripgrep:
        pytest.skip("ripgrep unavailable")
    (tmp_path / "match.txt").write_text(pattern + "\n", encoding="utf-8")
    (tmp_path / "other.txt").write_text("not a match\n", encoding="utf-8")

    result = await tool.execute({"pattern": pattern, "output_mode": output_mode, "path": "."})

    assert result.success
    assert result.output["matches_count"] == 1
    assert "other.txt" not in str(result.output)


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


@pytest.mark.parametrize('tool_class', [GlobTool, GrepTool])
@pytest.mark.parametrize('allowed', [None, []])
@pytest.mark.asyncio
async def test_explicit_null_unrestricted_and_empty_deny_all(tmp_path, tool_class, allowed):
    workspace, outside = _make_layout(tmp_path)
    tool = tool_class({'working_dir': str(workspace), 'allowed_paths': allowed})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = False
    result = await tool.execute({'path': str(outside), 'pattern': '*.txt' if tool_class is GlobTool else 'outside-secret-token'})
    assert result.success is (allowed is None)


@pytest.mark.parametrize('use_ripgrep', [True, False], ids=['ripgrep', 'python'])
@pytest.mark.parametrize('mode', ['content', 'files_with_matches', 'count'])
@pytest.mark.asyncio
async def test_denied_descendants_never_enter_engine_results(tmp_path, monkeypatch, use_ripgrep, mode):
    # Glob metacharacters in directory names must be literal policy paths.
    private = tmp_path / 'private[1] space'
    private.mkdir()
    (private / 'secret.txt').write_text('needle private-token\n')
    (tmp_path / 'public.txt').write_text('needle public-token\n')
    (tmp_path / 'alias.txt').symlink_to(private / 'secret.txt')
    tool = GrepTool({'working_dir': str(tmp_path), 'allowed_paths': None,
                     'denied_paths': [str(private)]})
    if use_ripgrep and not tool.use_ripgrep:
        pytest.skip('ripgrep unavailable')
    tool.use_ripgrep = use_ripgrep
    def no_subprocess(*args, **kwargs):
        pytest.fail('denied-path policy must select enforcement before invoking rg')
    monkeypatch.setattr('amplifier_module_tool_search.grep.subprocess.run', no_subprocess)
    import builtins
    original = builtins.open
    def checked_open(file, *args, **kwargs):
        assert not Path(file).resolve().is_relative_to(private)
        return original(file, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', checked_open)
    result = await tool.execute({'path': '.', 'pattern': 'needle', 'output_mode': mode, 'include_ignored': True,
                                 'glob': '**/*'})
    assert result.success, result.error
    assert result.output['matches_count'] == 1
    assert 'private-token' not in str(result)
    assert 'secret.txt' not in str(result)


@pytest.mark.parametrize('tool_class', [GlobTool, GrepTool])
@pytest.mark.parametrize('use_ripgrep', [True, False])
@pytest.mark.asyncio
async def test_denied_exact_path_and_symlink_cannot_be_requested(tmp_path, tool_class, use_ripgrep):
    _, private = _make_layout(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(private, target_is_directory=True)
    tool = tool_class({'working_dir': str(tmp_path), 'allowed_paths': None, 'denied_paths': ['outside']})
    if isinstance(tool, GrepTool):
        tool.use_ripgrep = use_ripgrep
    for path in (private, alias, tmp_path / 'allowed/../outside'):
        result = await tool.execute({'path': str(path), 'pattern': '*' if tool_class is GlobTool else 'outside'})
        _assert_denied_without_disclosure(result, private)
    if isinstance(tool, GlobTool):
        result = await tool.execute({'path': str(tmp_path), 'pattern': '**/*', 'include_ignored': True})
        assert result.success
        assert 'secret.txt' not in str(result)
        assert 'outside' not in str(result)
        assert 'alias' not in str(result)


@pytest.mark.parametrize('use_ripgrep', [True, False])
@pytest.mark.asyncio
async def test_case_alias_uses_actual_filesystem_identity(tmp_path, use_ripgrep):
    secret = tmp_path / 'Secret.txt'
    secret.write_text('needle-private\n')
    alias = tmp_path / 'SECRET.TXT'
    if not alias.exists():
        # On a case-sensitive volume this is a separate permitted file.
        alias.write_text('needle-public\n')
    same = alias.samefile(secret)
    tool = GrepTool({'working_dir': str(tmp_path), 'allowed_paths': None, 'denied_paths': [str(secret)]})
    if use_ripgrep and not tool.use_ripgrep:
        pytest.skip('ripgrep unavailable')
    tool.use_ripgrep = use_ripgrep
    result = await tool.execute({'path': str(alias), 'pattern': 'needle', 'output_mode': 'content'})
    assert result.success is not same
    listing = await GlobTool(tool.config).execute({'path': '.', 'pattern': '*.TXT'})
    assert listing.success
    assert listing.output['count'] == (0 if same else 1)
    result = await tool.execute({'path': '.', 'pattern': 'needle', 'output_mode': 'content', 'include_ignored': True})
    assert result.success
    assert result.output['matches_count'] == (0 if same else 1)
    assert 'needle-private' not in str(result)


@pytest.mark.asyncio
@pytest.mark.parametrize('ignore_file', ['.ignore', '.gitignore'])
async def test_denial_policy_does_not_consume_denied_ignore_configuration(tmp_path, monkeypatch, ignore_file):
    private = tmp_path / ignore_file
    private.write_text('public.txt\n')
    (tmp_path / 'public.txt').write_text('needle\n')
    tool = GrepTool({'working_dir': str(tmp_path), 'allowed_paths': None, 'denied_paths': [str(private)]})
    if not tool.use_ripgrep:
        pytest.skip('ripgrep unavailable')
    result = await tool.execute({'path': '.', 'pattern': 'needle', 'output_mode': 'content'})
    assert result.success
    assert result.output['matches_count'] == 1
    assert 'public.txt' in str(result.output)
    private.write_text('# different private configuration\n')
    after = await tool.execute({'path': '.', 'pattern': 'needle', 'output_mode': 'content'})
    assert after.output == result.output


def test_null_empty_and_invalid_denial_shapes(tmp_path):
    from amplifier_module_tool_search.paths import PathAccessPolicy
    assert PathAccessPolicy(tmp_path, None, None).is_allowed(tmp_path)
    for value in ('', [''], Path('')):
        assert not PathAccessPolicy(tmp_path, None, value).is_allowed(tmp_path)
    for value in (False, 0, [None]):
        with pytest.raises(ValueError, match='Search paths'):
            PathAccessPolicy(tmp_path, None, value)


@pytest.mark.asyncio
@pytest.mark.parametrize('alias_kind', ['unicode', 'hardlink'])
async def test_filesystem_alias_denial_happens_before_open(tmp_path, monkeypatch, alias_kind):
    secret = tmp_path / ('cafe\u0301.txt' if alias_kind == 'unicode' else 'secret.txt')
    secret.write_text('private-token\n')
    alias = tmp_path / ('caf\u00e9.txt' if alias_kind == 'unicode' else 'hardlink.txt')
    if alias_kind == 'hardlink':
        alias.hardlink_to(secret)
    elif not alias.exists():
        pytest.skip('This filesystem keeps Unicode spellings distinct')
    assert alias.samefile(secret)
    config = {'working_dir': str(tmp_path), 'allowed_paths': None, 'denied_paths': [str(alias)]}
    grep = GrepTool(config)
    import builtins
    original = builtins.open
    def check_open(file, *args, **kwargs):
        assert not Path(file).samefile(secret), 'denied alias opened'
        return original(file, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', check_open)
    def no_subprocess(*args, **kwargs):
        pytest.fail('denied policy must not invoke rg')
    monkeypatch.setattr('amplifier_module_tool_search.grep.subprocess.run', no_subprocess)
    assert not (await grep.execute({'path': str(secret), 'pattern': 'private'})).success
    result = await grep.execute({'path': '.', 'pattern': 'private', 'output_mode': 'content'})
    assert result.success and result.output['matches_count'] == 0
    listing = await GlobTool(config).execute({'path': '.', 'pattern': '*.txt'})
    assert listing.success and listing.output['count'] == 0


def test_allowlist_does_not_grant_unrelated_hardlink(tmp_path):
    from amplifier_module_tool_search.paths import PathAccessPolicy
    allowed = tmp_path / 'allowed.txt'
    allowed.write_text('content')
    other = tmp_path / 'outside.txt'
    other.hardlink_to(allowed)
    policy = PathAccessPolicy(tmp_path, [allowed])
    assert policy.is_allowed(allowed)
    assert not policy.is_allowed(other)
