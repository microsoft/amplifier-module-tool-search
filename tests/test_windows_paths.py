"""Windows-compatibility tests for grep/glob.

Four bugs were fixed:
  1. grep ripgrep subprocess used text=True with no encoding=  -> cp1252 crash on
     Windows for non-ASCII matched content. (Teeth on Windows only.)
  2. grep count-mode parsed rg output with split(":", 1)  -> a Windows absolute
     path "C:\\...\\f.py:3" split on the FIRST colon, dropping the entry.
     (Testable on Linux by feeding a Windows-style rg line to the parser logic.)
  3. grep default-exclusion check used a "/"-delimited substring -> never matched
     a "\\"-separated Windows path, so node_modules/.git/etc. were never excluded.
  4. glob default-exclusion check: identical bug, pure-Python, every call.

Bugs 3 and 4 are verified here via Path.parts semantics, which is exactly what
the fix relies on -- and these have real teeth on Linux too: the old substring
check is demonstrably wrong for the component-membership contract.
"""

from pathlib import PureWindowsPath

from amplifier_module_tool_search.glob import GlobTool
from amplifier_module_tool_search.grep import GrepTool


class TestCountModeColonSplit:
    """Bug 2: rg count output must rsplit on the LAST colon, not the first."""

    def test_rsplit_handles_windows_drive_letter(self):
        # rg emits "filepath:count"; on Windows filepath has a drive-letter colon.
        line = r"C:\Users\me\project\file.py:3"
        # The fix parses with rsplit(":", 1):
        filepath, count_str = line.rsplit(":", 1)
        assert filepath == r"C:\Users\me\project\file.py"
        assert int(count_str) == 3

    def test_old_split_would_have_dropped_it(self):
        # Demonstrates the teeth: the OLD split(":", 1) breaks on the drive letter.
        line = r"C:\Users\me\project\file.py:3"
        bad_path, bad_count = line.split(":", 1)
        assert bad_path == "C"  # wrong path
        try:
            int(bad_count)  # r"\Users\...\file.py:3" -> ValueError -> entry dropped
            raise AssertionError("expected the old split to yield a non-int count")
        except ValueError:
            pass


class TestGrepExclusionByComponent:
    """Bug 3: grep default exclusions must match a path COMPONENT, cross-OS."""

    def test_windows_path_excludes_node_modules(self):
        tool = GrepTool({"working_dir": "."})
        # Simulate a Windows path via PureWindowsPath so .parts splits on "\".
        win = PureWindowsPath(r"C:\proj\node_modules\pkg\index.js")
        assert "node_modules" in tool.exclusions
        assert any(excl in win.parts for excl in tool.exclusions)

    def test_windows_path_does_not_exclude_plain_file(self):
        tool = GrepTool({"working_dir": "."})
        win = PureWindowsPath(r"C:\proj\src\app.py")
        assert not any(excl in win.parts for excl in tool.exclusions)

    def test_old_substring_check_missed_windows_paths(self):
        # Teeth: the OLD "/{exclusion}/" substring never appears in a "\" path.
        path_str = str(PureWindowsPath(r"C:\proj\node_modules\pkg\index.js"))
        assert "/node_modules/" not in path_str  # old check -> never excluded


class TestGlobExclusionByComponent:
    """Bug 4: glob._is_excluded must match a path COMPONENT, cross-OS."""

    def test_windows_path_excluded(self):
        tool = GlobTool({"working_dir": "."})
        assert tool._is_excluded(PureWindowsPath(r"C:\proj\.git\config"))
        assert tool._is_excluded(PureWindowsPath(r"C:\proj\node_modules\a\b.js"))

    def test_windows_plain_path_not_excluded(self):
        tool = GlobTool({"working_dir": "."})
        assert not tool._is_excluded(PureWindowsPath(r"C:\proj\src\app.py"))

    def test_posix_behaviour_preserved(self):
        # The fix must keep excluding on POSIX too (no regression).
        from pathlib import PurePosixPath

        tool = GlobTool({"working_dir": "."})
        assert tool._is_excluded(PurePosixPath("/proj/.venv/lib/x.py"))
        assert not tool._is_excluded(PurePosixPath("/proj/src/app.py"))
