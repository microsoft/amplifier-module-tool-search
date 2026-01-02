"""GlobTool - Find files matching glob patterns."""

from pathlib import Path
from typing import Any

from amplifier_core import ToolResult


class GlobTool:
    """Find files matching glob patterns."""

    name = "glob"
    description = """
- Fast file pattern matching tool that works with any codebase size
- Supports glob patterns like "**/*.js" or "src/**/*.ts"
- Returns matching file paths sorted by modification time
- Use this tool when you need to find files by name patterns
- When you are doing an open ended search that may require multiple rounds of globbing and grepping, use the task tool instead
- You can call multiple tools in a single response. It is always better to speculatively perform multiple searches in parallel if they are potentially useful.

SCOPE AND LIMITS:
- By default, excludes common non-source directories: node_modules, .venv, .git, __pycache__, build dirs
- Results are limited to 500 files by default to prevent context overflow
- Set `include_ignored: true` to search excluded directories
- Response includes `total_files` to know if results were capped
                   """

    # Default exclusions - common non-source directories (same as grep)
    DEFAULT_EXCLUSIONS = [
        "node_modules", ".venv", "venv", ".git", "__pycache__",
        ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
        ".next", ".nuxt", "target", "vendor", ".gradle",
        ".idea", ".vscode", "coverage", ".nyc_output",
    ]

    def __init__(self, config: dict[str, Any]):
        """Initialize GlobTool with configuration."""
        self.config = config
        self.max_results = config.get("max_results", 500)
        self.allowed_paths = config.get("allowed_paths", ["."])
        self.working_dir = config.get("working_dir", ".")
        
        # Configurable exclusions (can override defaults)
        self.exclusions = config.get("exclusions", self.DEFAULT_EXCLUSIONS)

    @property
    def input_schema(self) -> dict:
        """Return JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern to match files (e.g., '**/*.py')"},
                "path": {"type": "string", "description": "Base path to search from (default: current directory)"},
                "type": {
                    "type": "string",
                    "enum": ["file", "dir", "any"],
                    "description": "Filter by type: file, dir, or any (default: file)",
                },
                "exclude": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Patterns to exclude from results",
                },
                "include_ignored": {
                    "type": "boolean",
                    "description": "Search in normally-excluded directories (node_modules, .venv, .git, etc.). Default: false.",
                },
            },
            "required": ["pattern"],
        }

    def _is_excluded(self, path_str: str) -> bool:
        """Check if a path should be excluded based on exclusion patterns."""
        for exclusion in self.exclusions:
            # Check for exclusion as a directory component
            if f"/{exclusion}/" in path_str or f"/{exclusion}" in path_str or path_str.startswith(f"{exclusion}/"):
                return True
        return False

    async def execute(self, input: dict[str, Any]) -> ToolResult:
        """
        Find files matching pattern.

        Args:
            input: {
                "pattern": str - Glob pattern (e.g., "**/*.py")
                "path": Optional[str] - Base path to search from
                "type": Optional[str] - Filter by type: "file", "dir", "any"
                "exclude": Optional[List[str]] - Patterns to exclude
                "include_ignored": Optional[bool] - Include normally-excluded directories
            }
        """
        pattern = input.get("pattern")
        base_path = input.get("path", ".")
        filter_type = input.get("type", "any")
        exclude_patterns = input.get("exclude", [])
        include_ignored = input.get("include_ignored", False)

        if not pattern:
            return ToolResult(success=False, error={"message": "Pattern is required"})

        try:
            # Resolve relative paths against working_dir
            path_obj = Path(base_path)
            if not path_obj.is_absolute():
                path = Path(self.working_dir) / base_path
            else:
                path = path_obj
            if not path.exists():
                return ToolResult(success=False, error={"message": f"Path not found: {base_path}"})

            # Find matching paths - collect all first to get total count
            all_matches: list[dict[str, Any]] = []
            for match_path in path.glob(pattern):
                # Convert to string for exclusion check (BEFORE stat() for performance)
                match_path_str = str(match_path)

                # Apply default exclusions (unless include_ignored is True)
                if not include_ignored and self._is_excluded(match_path_str):
                    continue

                # Apply type filter
                if (
                    filter_type == "file"
                    and not match_path.is_file()
                    or filter_type == "dir"
                    and not match_path.is_dir()
                ):
                    continue

                # Apply user-specified exclusions
                excluded = False
                for exclude_pattern in exclude_patterns:
                    if match_path.match(exclude_pattern):
                        excluded = True
                        break

                if not excluded:
                    try:
                        stat = match_path.stat()
                        match_info: dict[str, Any] = {
                            "path": match_path_str,
                            "type": "file" if match_path.is_file() else "dir",
                            "mtime": stat.st_mtime,  # For sorting
                        }
                        # Add size for files
                        if match_path.is_file():
                            match_info["size"] = stat.st_size
                        else:
                            match_info["size"] = None

                        all_matches.append(match_info)
                    except OSError:
                        # Skip files we can't stat
                        continue

            # Capture total before limiting
            total_files = len(all_matches)

            # Sort by modification time (newest first) as advertised
            all_matches.sort(key=lambda m: m["mtime"], reverse=True)

            # Apply limit
            matches = all_matches[:self.max_results]

            # Remove mtime from output (internal sorting key only)
            for match in matches:
                del match["mtime"]

            # Build output
            output: dict[str, Any] = {
                "pattern": pattern,
                "base_path": str(path),
                "total_files": total_files,
                "count": len(matches),
                "matches": matches,
            }

            # Add results_capped flag only if results were limited
            if total_files > len(matches):
                output["results_capped"] = True

            return ToolResult(success=True, output=output)

        except Exception as e:
            return ToolResult(success=False, error={"message": f"Glob search failed: {e}"})
