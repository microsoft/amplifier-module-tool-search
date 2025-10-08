"""GrepTool - Search file contents with regex patterns."""

import re
from pathlib import Path
from typing import Any, List, Optional

from amplifier_core import ToolResult


class GrepTool:
    """Search file contents with regex patterns."""

    name = "grep"
    description = "Search for patterns in files"

    def __init__(self, config: dict[str, Any]):
        """Initialize GrepTool with configuration."""
        self.config = config
        self.max_results = config.get("max_results", 100)
        self.max_file_size = config.get("max_file_size", 10 * 1024 * 1024)  # 10MB
        self.allowed_paths = config.get("allowed_paths", ["."])

    @property
    def input_schema(self) -> dict:
        """Return JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "path": {"type": "string", "description": "File or directory to search (default: current directory)"},
                "recursive": {"type": "boolean", "description": "Search recursively in directories (default: true)"},
                "ignore_case": {"type": "boolean", "description": "Case-insensitive search (default: false)"},
                "include": {"type": "string", "description": "File pattern to include (e.g., '*.py')"},
                "exclude": {"type": "string", "description": "File pattern to exclude"},
                "context_lines": {"type": "integer", "description": "Number of context lines to show around matches"},
            },
            "required": ["pattern"],
        }

    async def execute(self, input: dict[str, Any]) -> ToolResult:
        """
        Search for pattern in files.

        Args:
            input: {
                "pattern": str - Regex pattern to search
                "path": str - File or directory to search
                "recursive": bool - Search recursively in directories
                "ignore_case": bool - Case-insensitive search
                "include": Optional[str] - File pattern to include (e.g., "*.py")
                "exclude": Optional[str] - File pattern to exclude
                "context_lines": int - Number of context lines to show
            }
        """
        pattern = input.get("pattern")
        search_path = input.get("path", ".")
        recursive = input.get("recursive", True)
        ignore_case = input.get("ignore_case", False)
        include_pattern = input.get("include", "*")
        exclude_pattern = input.get("exclude", "")
        context_lines = input.get("context_lines", 0)

        if not pattern:
            return ToolResult(success=False, error={"message": "Pattern is required"})

        try:
            # Compile regex
            flags = re.IGNORECASE if ignore_case else 0
            regex = re.compile(pattern, flags)

            # Find files to search
            path = Path(search_path)
            if not path.exists():
                return ToolResult(success=False, error={"message": f"Path not found: {search_path}"})

            files_to_search = self._find_files(path, recursive, include_pattern, exclude_pattern)

            # Search files
            results = []
            for file_path in files_to_search:
                file_results = await self._search_file(file_path, regex, context_lines)
                if file_results:
                    results.extend(file_results)

                if len(results) >= self.max_results:
                    break

            # Format results
            output = {"pattern": pattern, "matches": len(results), "results": results[: self.max_results]}

            if len(results) > self.max_results:
                output["truncated"] = True
                output["total_matches"] = len(results)

            return ToolResult(success=True, output=output)

        except re.error as e:
            return ToolResult(success=False, error={"message": f"Invalid regex pattern: {e}"})
        except Exception as e:
            return ToolResult(success=False, error={"message": f"Search failed: {e}"})

    def _find_files(self, path: Path, recursive: bool, include_pattern: str, exclude_pattern: str) -> List[Path]:
        """Find files to search."""
        files = []

        if path.is_file():
            return [path]

        pattern = "**/*" if recursive else "*"
        for file_path in path.glob(pattern):
            if not file_path.is_file():
                continue

            # Check file size
            if file_path.stat().st_size > self.max_file_size:
                continue

            # Check include pattern
            if include_pattern != "*":
                if not file_path.match(include_pattern):
                    continue

            # Check exclude pattern
            if exclude_pattern:
                if file_path.match(exclude_pattern):
                    continue

            # Skip binary files (simple heuristic)
            try:
                with open(file_path, "rb") as f:
                    chunk = f.read(8192)
                    if b"\x00" in chunk:
                        continue  # Skip binary files
            except (OSError, IOError):
                continue

            files.append(file_path)

        return files

    async def _search_file(self, file_path: Path, regex: re.Pattern[str], context_lines: int) -> List[dict[str, Any]]:
        """Search a single file."""
        results = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    # Get context
                    start = max(0, i - context_lines - 1)
                    end = min(len(lines), i + context_lines)

                    context: Optional[List[dict[str, Any]]] = None
                    if context_lines > 0:
                        context = []
                        for j in range(start, end):
                            context.append({"line_no": j + 1, "content": lines[j].rstrip(), "is_match": j == i - 1})

                    results.append({"file": str(file_path), "line_no": i, "content": line.rstrip(), "context": context})

        except Exception:
            # Log but don't fail entirely - file might have changed or have permission issues
            pass

        return results
