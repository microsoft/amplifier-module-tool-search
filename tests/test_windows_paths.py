"""Windows-compatibility tests for grep/glob.

Four bugs were fixed:
  1. grep ripgrep subprocess used text=True with no encoding=  -> cp1252 crash on
     Windows for non-ASCII matched content. (Reachable only on Windows; covered
     by the explicit encoding= argument at the call site, not testable here.)
  2. grep count-mode parsed rg output with split(":", 1)  -> a Windows absolute
     path "C:\\...\\f.py:3" split on the FIRST colon, dropping the entry.
  3. grep default-exclusion check used a "/"-delimited substring -> never matched
     a "\\"-separated Windows path, so node_modules/.git/etc. were never excluded.
  4. glob default-exclusion check: identical bug, pure-Python, every call.

Every test below drives real product code (GrepTool.execute / _is_excluded,
GlobTool._is_excluded) so that reverting a fix turns the test red.
"""

import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from amplifier_module_tool_search.glob import GlobTool
from amplifier_module_tool_search.grep import GrepTool


class _FakeCompletedProcess:
    """Stand-in for subprocess.CompletedProcess with canned ripgrep output."""

    def __init__(self, stdout: str) -> None:
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


class TestCountModeColonSplit:
    """Bug 2: rg count output must rsplit on the LAST colon, not the first."""

    @pytest.mark.asyncio
    async def test_count_mode_parses_windows_absolute_paths(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A Windows drive-letter path survives count parsing intact.

        Teeth: with the old split(":", 1) the filepath becomes "C" and the count
        string becomes "\\Users\\...\\file.py:3", which raises ValueError on
        int() and silently drops the entry -- counts would be {} and
        total_matches 0.
        """
        tool = GrepTool({"working_dir": str(tmp_path)})
        tool.use_ripgrep = True

        rg_stdout = "C:\\Users\\me\\project\\file.py:3\nC:\\Users\\me\\project\\other.py:5\n"
        monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _FakeCompletedProcess(rg_stdout))

        result = await tool.execute({"pattern": "findme", "path": ".", "output_mode": "count"})

        assert result.success, f"count mode failed: {result.error}"
        assert isinstance(result.output, dict)
        assert result.output["counts"] == {
            r"C:\Users\me\project\file.py": 3,
            r"C:\Users\me\project\other.py": 5,
        }
        assert result.output["total_matches"] == 8
        assert result.output["matches_count"] == 8

    @pytest.mark.asyncio
    async def test_count_mode_still_parses_posix_paths(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """No regression: POSIX paths (no drive-letter colon) still parse."""
        tool = GrepTool({"working_dir": str(tmp_path)})
        tool.use_ripgrep = True

        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: _FakeCompletedProcess("/proj/src/app.py:7\n"),
        )

        result = await tool.execute({"pattern": "findme", "path": ".", "output_mode": "count"})

        assert result.success
        assert isinstance(result.output, dict)
        assert result.output["counts"] == {"/proj/src/app.py": 7}
        assert result.output["total_matches"] == 7


class TestGrepExclusionByComponent:
    """Bug 3: grep default exclusions must match a path COMPONENT, cross-OS."""

    def test_windows_path_excludes_node_modules(self) -> None:
        tool = GrepTool({"working_dir": "."})
        assert "node_modules" in tool.exclusions
        assert tool._is_excluded(PureWindowsPath(r"C:\proj\node_modules\pkg\index.js"))
        assert tool._is_excluded(PureWindowsPath(r"C:\proj\.git\config"))

    def test_windows_path_does_not_exclude_plain_file(self) -> None:
        tool = GrepTool({"working_dir": "."})
        assert not tool._is_excluded(PureWindowsPath(r"C:\proj\src\app.py"))

    def test_posix_behaviour_preserved(self) -> None:
        """The fix must keep excluding on POSIX too (no regression)."""
        tool = GrepTool({"working_dir": "."})
        assert tool._is_excluded(PurePosixPath("/proj/.venv/lib/x.py"))
        assert not tool._is_excluded(PurePosixPath("/proj/src/app.py"))

    def test_substring_lookalike_is_not_excluded(self) -> None:
        """Component matching, not substring matching.

        A directory merely CONTAINING an exclusion name as a substring
        ("my_node_modules_backup") is a legitimate user directory and must be
        searched.
        """
        tool = GrepTool({"working_dir": "."})
        assert not tool._is_excluded(PurePosixPath("/proj/my_node_modules_backup/x.py"))
        assert not tool._is_excluded(PureWindowsPath(r"C:\proj\my_node_modules_backup\x.py"))


class TestGlobExclusionByComponent:
    """Bug 4: glob._is_excluded must match a path COMPONENT, cross-OS."""

    def test_windows_path_excluded(self) -> None:
        tool = GlobTool({"working_dir": "."})
        assert tool._is_excluded(PureWindowsPath(r"C:\proj\.git\config"))
        assert tool._is_excluded(PureWindowsPath(r"C:\proj\node_modules\a\b.js"))

    def test_windows_plain_path_not_excluded(self) -> None:
        tool = GlobTool({"working_dir": "."})
        assert not tool._is_excluded(PureWindowsPath(r"C:\proj\src\app.py"))

    def test_posix_behaviour_preserved(self) -> None:
        """The fix must keep excluding on POSIX too (no regression)."""
        tool = GlobTool({"working_dir": "."})
        assert tool._is_excluded(PurePosixPath("/proj/.venv/lib/x.py"))
        assert not tool._is_excluded(PurePosixPath("/proj/src/app.py"))

    def test_substring_lookalike_is_not_excluded(self) -> None:
        tool = GlobTool({"working_dir": "."})
        assert not tool._is_excluded(PurePosixPath("/proj/my_node_modules_backup/x.py"))
        assert not tool._is_excluded(PureWindowsPath(r"C:\proj\my_node_modules_backup\x.py"))


class TestGrepExclusionEndToEnd:
    """Bug 3, at the execute() boundary: excluded dirs are really skipped."""

    @pytest.mark.asyncio
    async def test_python_fallback_skips_excluded_directory(self, tmp_path: Path) -> None:
        tool = GrepTool({"working_dir": str(tmp_path)})
        tool.use_ripgrep = False  # exercise _find_files, which calls _is_excluded

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("needle_xyz", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "vendor.py").write_text("needle_xyz", encoding="utf-8")

        result = await tool.execute({"pattern": "needle_xyz", "path": "."})

        assert result.success, f"grep failed: {result.error}"
        assert isinstance(result.output, dict)
        found = " ".join(result.output["files"])
        assert "app.py" in found
        assert "node_modules" not in found

    @pytest.mark.asyncio
    async def test_include_ignored_reaches_excluded_directory(self, tmp_path: Path) -> None:
        """The exclusion is an opt-out, not a hard block."""
        tool = GrepTool({"working_dir": str(tmp_path)})
        tool.use_ripgrep = False

        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "vendor.py").write_text("needle_xyz", encoding="utf-8")

        result = await tool.execute({"pattern": "needle_xyz", "path": ".", "include_ignored": True})

        assert result.success
        assert isinstance(result.output, dict)
        assert "node_modules" in " ".join(result.output["files"])
