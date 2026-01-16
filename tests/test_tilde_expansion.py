"""Tests for tilde (~) path expansion in glob and grep tools."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from amplifier_module_tool_search.glob import GlobTool
from amplifier_module_tool_search.grep import GrepTool


class TestTildeExpansion:
    """Test that ~ paths are properly expanded to home directory."""

    @pytest.fixture
    def glob_tool(self, tmp_path):
        """Create a GlobTool instance."""
        return GlobTool({"working_dir": str(tmp_path)})

    @pytest.fixture
    def grep_tool(self, tmp_path):
        """Create a GrepTool instance."""
        return GrepTool({"working_dir": str(tmp_path)})

    @pytest.mark.asyncio
    async def test_glob_expands_tilde(self, glob_tool, tmp_path):
        """Glob tool should expand ~ to home directory."""
        # Create a test file in home directory subdirectory
        home = Path.home()
        
        # Mock expanduser to verify it's being called
        original_expanduser = Path.expanduser
        expanduser_called = False
        
        def mock_expanduser(self):
            nonlocal expanduser_called
            expanduser_called = True
            return original_expanduser(self)
        
        with patch.object(Path, 'expanduser', mock_expanduser):
            # This should call expanduser internally
            result = await glob_tool.execute({"pattern": "*.py", "path": "~/nonexistent_path_12345"})
        
        # expanduser should have been called
        assert expanduser_called, "expanduser() was not called on the path"

    @pytest.mark.asyncio
    async def test_grep_expands_tilde_ripgrep(self, grep_tool, tmp_path):
        """Grep tool (ripgrep path) should expand ~ to home directory."""
        original_expanduser = Path.expanduser
        expanduser_called = False
        
        def mock_expanduser(self):
            nonlocal expanduser_called
            expanduser_called = True
            return original_expanduser(self)
        
        with patch.object(Path, 'expanduser', mock_expanduser):
            # Force ripgrep path
            grep_tool.use_ripgrep = True
            grep_tool.rg_path = "/usr/bin/rg"  # May not exist, that's ok
            
            try:
                await grep_tool.execute({"pattern": "test", "path": "~/nonexistent_path_12345"})
            except Exception:
                pass  # We only care that expanduser was called
        
        assert expanduser_called, "expanduser() was not called on the path (ripgrep path)"

    @pytest.mark.asyncio
    async def test_grep_expands_tilde_python(self, grep_tool, tmp_path):
        """Grep tool (Python fallback) should expand ~ to home directory."""
        original_expanduser = Path.expanduser
        expanduser_called = False
        
        def mock_expanduser(self):
            nonlocal expanduser_called
            expanduser_called = True
            return original_expanduser(self)
        
        with patch.object(Path, 'expanduser', mock_expanduser):
            # Force Python fallback path
            grep_tool.use_ripgrep = False
            
            result = await grep_tool.execute({"pattern": "test", "path": "~/nonexistent_path_12345"})
        
        assert expanduser_called, "expanduser() was not called on the path (Python fallback)"

    def test_expanduser_cross_platform(self):
        """Verify expanduser behavior is consistent across platforms.
        
        This documents the expected behavior:
        - ~/path -> /home/user/path (Linux) or /Users/user/path (macOS) or C:\\Users\\user\\path (Windows)
        - Paths without ~ are returned unchanged
        - After expanduser, is_absolute() returns True for ~ paths
        """
        # ~ path becomes absolute after expansion
        tilde_path = Path("~/some/path")
        expanded = tilde_path.expanduser()
        assert expanded.is_absolute(), "Expanded ~ path should be absolute"
        assert "~" not in str(expanded), "Expanded path should not contain ~"
        
        # Non-tilde paths are unchanged
        relative_path = Path("relative/path")
        assert relative_path.expanduser() == relative_path
        assert not relative_path.expanduser().is_absolute()
        
        # Absolute paths are unchanged
        if os.name == 'nt':  # Windows
            abs_path = Path("C:/absolute/path")
        else:
            abs_path = Path("/absolute/path")
        assert abs_path.expanduser() == abs_path
