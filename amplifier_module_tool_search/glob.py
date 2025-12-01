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
                   """

    def __init__(self, config: dict[str, Any]):
        """Initialize GlobTool with configuration."""
        self.config = config
        self.max_results = config.get("max_results", 1000)
        self.allowed_paths = config.get("allowed_paths", ["."])
        self.working_dir = config.get("working_dir", ".")

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
            },
            "required": ["pattern"],
        }

    async def execute(self, input: dict[str, Any]) -> ToolResult:
        """
        Find files matching pattern.

        Args:
            input: {
                "pattern": str - Glob pattern (e.g., "**/*.py")
                "path": Optional[str] - Base path to search from
                "type": Optional[str] - Filter by type: "file", "dir", "any"
                "exclude": Optional[List[str]] - Patterns to exclude
            }
        """
        pattern = input.get("pattern")
        base_path = input.get("path", ".")
        filter_type = input.get("type", "any")
        exclude_patterns = input.get("exclude", [])

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

            # Find matching paths
            matches: list[dict[str, Any]] = []
            for match_path in path.glob(pattern):
                # Apply type filter
                if (
                    filter_type == "file"
                    and not match_path.is_file()
                    or filter_type == "dir"
                    and not match_path.is_dir()
                ):
                    continue

                # Apply exclusions
                excluded = False
                for exclude_pattern in exclude_patterns:
                    if match_path.match(exclude_pattern):
                        excluded = True
                        break

                if not excluded:
                    try:
                        stat = match_path.stat()
                        match_info: dict[str, Any] = {
                            "path": str(match_path),
                            "type": "file" if match_path.is_file() else "dir",
                            "mtime": stat.st_mtime,  # For sorting
                        }
                        # Add size for files
                        if match_path.is_file():
                            match_info["size"] = stat.st_size
                        else:
                            match_info["size"] = None

                        matches.append(match_info)
                    except OSError:
                        # Skip files we can't stat
                        continue

                if len(matches) >= self.max_results:
                    break

            # Sort by modification time (newest first) as advertised
            matches.sort(key=lambda m: m["mtime"], reverse=True)

            # Remove mtime from output (internal sorting key only)
            for match in matches:
                del match["mtime"]

            return ToolResult(
                success=True,
                output={"pattern": pattern, "base_path": str(path), "count": len(matches), "matches": matches},
            )

        except Exception as e:
            return ToolResult(success=False, error={"message": f"Glob search failed: {e}"})
