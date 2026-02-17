"""GrepTool - Search file contents with regex patterns using ripgrep or Python re."""

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from amplifier_core import ToolResult

logger = logging.getLogger(__name__)


class GrepTool:
    """Search file contents with regex patterns using ripgrep (fast) or Python re (fallback)."""

    name = "grep"
    description = r"""
Search file contents with regex patterns. Uses ripgrep when available (fast), falls back to Python re.

CAPABILITIES:
- Full regex syntax (e.g., "log.*Error", "function\s+\w+")
- Filter by glob pattern (e.g., "*.js", "**/*.tsx") or file type (e.g., "py", "js", "rust")
- Output modes: "files_with_matches" (default), "content" (with line content), "count"
- Multiline matching with `multiline: true` for patterns spanning lines

SCOPE AND LIMITS:
- By default, excludes common non-source directories: node_modules, .venv, .git, __pycache__, build dirs
- Results are limited by default (200 files/counts, 500 content matches) to prevent context overflow
- Set `include_ignored: true` to search excluded directories
- Set explicit `head_limit: 0` for unlimited results (use with caution on large codebases)

PATTERN SYNTAX:
- Uses ripgrep regex (not grep) - literal braces need escaping: `interface\{\}` to find `interface{}`
- Case insensitive: use `-i: true`
- Context lines: use `-A`, `-B`, or `-C` parameters with content mode

PAGINATION:
- Use `head_limit` and `offset` for pagination
- Response includes `total_matches` to know how many exist beyond the limit
"""

    # Default exclusions - common non-source directories
    DEFAULT_EXCLUSIONS = [
        "node_modules",
        ".venv",
        "venv",
        ".git",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".gradle",
        ".idea",
        ".vscode",
        "coverage",
        ".nyc_output",
    ]

    # Default result limits by output mode
    DEFAULT_LIMITS = {
        "files_with_matches": 200,
        "content": 500,
        "count": 200,
    }

    # Common file type mappings for fallback
    TYPE_TO_GLOB = {
        "py": "*.py",
        "js": "*.js",
        "ts": "*.ts",
        "tsx": "*.tsx",
        "jsx": "*.jsx",
        "go": "*.go",
        "rust": "*.rs",
        "java": "*.java",
        "c": "*.c",
        "cpp": "*.cpp",
        "h": "*.h",
        "hpp": "*.hpp",
        "rb": "*.rb",
        "php": "*.php",
        "sh": "*.sh",
        "md": "*.md",
        "json": "*.json",
        "yaml": "*.yaml",
        "yml": "*.yml",
        "toml": "*.toml",
        "xml": "*.xml",
        "html": "*.html",
        "css": "*.css",
    }

    # Map common alternative type names to ripgrep-recognized types
    # This handles cases where LLMs use long-form names like "typescript" instead of "ts"
    TYPE_ALIASES = {
        "typescript": "ts",
        "javascript": "js",
        "python": "py",
        "ruby": "rb",
        "markdown": "md",
        "shell": "sh",
        "bash": "sh",
        "csharp": "cs",
        "c#": "cs",
        "c++": "cpp",
        "cplusplus": "cpp",
        "golang": "go",
        "rs": "rust",  # ripgrep uses "rust" not "rs"
        "yml": "yaml",  # ripgrep uses "yaml" not "yml"
        "tsx": "ts",  # ripgrep's ts type includes tsx
        "jsx": "js",  # ripgrep's js type includes jsx
    }

    # Known ripgrep built-in types (subset of most common ones)
    # Full list can be obtained via `rg --type-list`
    KNOWN_RG_TYPES = {
        "c",
        "cpp",
        "cs",
        "css",
        "go",
        "h",
        "hpp",
        "html",
        "java",
        "js",
        "json",
        "lua",
        "md",
        "php",
        "py",
        "rb",
        "rust",
        "sh",
        "sql",
        "swift",
        "toml",
        "ts",
        "txt",
        "xml",
        "yaml",
    }

    # Default timeout for subprocess (seconds)
    DEFAULT_TIMEOUT = 60

    def __init__(self, config: dict[str, Any]):
        """Initialize GrepTool with configuration."""
        self.config = config
        self.max_file_size = config.get("max_file_size", 10 * 1024 * 1024)  # 10MB default
        self.working_dir = config.get("working_dir", ".")
        self.timeout = config.get("timeout", self.DEFAULT_TIMEOUT)

        # Configurable exclusions (can override defaults)
        self.exclusions = config.get("exclusions", self.DEFAULT_EXCLUSIONS)

        # Configurable default limits (can override per-mode defaults)
        self.default_limits = {**self.DEFAULT_LIMITS, **config.get("default_limits", {})}

        # Check if ripgrep is available
        rg_path = shutil.which("rg")
        if rg_path:
            self.rg_path: str = rg_path
            self.use_ripgrep = True
            logger.info("GrepTool initialized with ripgrep (fast mode)")
        else:
            self.rg_path = ""
            self.use_ripgrep = False
            logger.info("GrepTool initialized with Python re (fallback mode - ripgrep not found)")

    @property
    def input_schema(self) -> dict:
        """Return JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The regular expression pattern to search for in file contents",
                },
                "path": {
                    "type": "string",
                    "description": "File or directory to search in (rg PATH). Defaults to current working directory.",
                },
                "output_mode": {
                    "type": "string",
                    "description": 'Output mode: "content" shows matching lines (supports -A/-B/-C context, -n line numbers, head_limit), "files_with_matches" shows file paths (supports head_limit), "count" shows match counts (supports head_limit). Defaults to "files_with_matches".',
                    "enum": ["content", "files_with_matches", "count"],
                },
                "-i": {
                    "type": "boolean",
                    "description": "Case insensitive search (rg -i)",
                },
                "-n": {
                    "type": "boolean",
                    "description": 'Show line numbers in output (rg -n). Requires output_mode: "content", ignored otherwise. Defaults to true.',
                },
                "-A": {
                    "type": "integer",
                    "description": 'Number of lines to show after each match (rg -A). Requires output_mode: "content", ignored otherwise.',
                },
                "-B": {
                    "type": "integer",
                    "description": 'Number of lines to show before each match (rg -B). Requires output_mode: "content", ignored otherwise.',
                },
                "-C": {
                    "type": "integer",
                    "description": 'Number of lines to show before and after each match (rg -C). Requires output_mode: "content", ignored otherwise.',
                },
                "glob": {
                    "type": "string",
                    "description": 'Glob pattern to filter files (e.g. "*.js", "*.{ts,tsx}") - maps to rg --glob',
                },
                "type": {
                    "type": "string",
                    "description": "File type to search (rg --type). Valid types: py, js, ts, go, rust, java, c, cpp, rb, sh, md, json, yaml, html, css, xml, php, sql, swift, lua, toml, txt. Also accepts aliases like 'python', 'typescript', 'javascript', 'ruby', 'markdown'.",
                },
                "multiline": {
                    "type": "boolean",
                    "description": "Enable multiline mode where . matches newlines and patterns can span lines (rg -U --multiline-dotall). Default: false.",
                },
                "head_limit": {
                    "type": "integer",
                    "description": "Limit output to first N entries. Default limits apply per mode (200 files/counts, 500 content). Set to 0 for unlimited (use with caution). Use with total_matches field for pagination.",
                },
                "offset": {
                    "type": "integer",
                    "description": "Skip first N entries before applying head_limit. Default: 0. Use with head_limit for pagination.",
                },
                "include_ignored": {
                    "type": "boolean",
                    "description": "Search in normally-excluded directories (node_modules, .venv, .git, etc.). Default: false.",
                },
            },
            "required": ["pattern"],
        }

    async def execute(self, input: dict[str, Any]) -> ToolResult:
        """
        Search for pattern in files using ripgrep (if available) or Python re (fallback).

        Args:
            input: Dictionary containing search parameters as defined in input_schema
        """
        if self.use_ripgrep:
            return await self._execute_ripgrep(input)
        return await self._execute_python(input)

    async def _execute_ripgrep(self, input: dict[str, Any]) -> ToolResult:
        """Execute search using ripgrep binary (fast path)."""
        pattern = input.get("pattern")
        if not pattern:
            error_msg = "Pattern is required"
            return ToolResult(success=False, output=error_msg, error={"message": error_msg})

        # Build ripgrep command
        cmd = [self.rg_path]

        # Output mode
        output_mode = input.get("output_mode", "files_with_matches")
        if output_mode == "files_with_matches":
            cmd.append("--files-with-matches")
        elif output_mode == "count":
            cmd.append("--count")
        # content mode is default, no flag needed

        # Case insensitive
        if input.get("-i", False):
            cmd.append("-i")

        # Line numbers (default true for content mode)
        if output_mode == "content" and input.get("-n", True):
            cmd.append("-n")

        # Context lines (only for content mode)
        if output_mode == "content":
            if "-C" in input:
                cmd.extend(["-C", str(input["-C"])])
            else:
                if "-A" in input:
                    cmd.extend(["-A", str(input["-A"])])
                if "-B" in input:
                    cmd.extend(["-B", str(input["-B"])])

        # Multiline mode
        if input.get("multiline", False):
            cmd.extend(["-U", "--multiline-dotall"])

        # File filtering
        if "glob" in input:
            cmd.extend(["--glob", input["glob"]])
        if "type" in input:
            file_type = input["type"].lower()
            # Normalize aliases (e.g., "typescript" -> "ts", "python" -> "py")
            file_type = self.TYPE_ALIASES.get(file_type, file_type)

            if file_type in self.KNOWN_RG_TYPES:
                # Use ripgrep's native type filtering
                cmd.extend(["--type", file_type])
            elif file_type in self.TYPE_TO_GLOB:
                # Fall back to glob pattern for types we know but ripgrep might not
                cmd.extend(["--glob", self.TYPE_TO_GLOB[file_type]])
            else:
                # Unknown type - return helpful error instead of letting ripgrep fail
                known_types = sorted(self.KNOWN_RG_TYPES)
                aliases = sorted(self.TYPE_ALIASES.keys())
                return ToolResult(
                    success=False,
                    error={
                        "message": f"Unrecognized file type: '{input['type']}'. "
                        f"Valid types: {', '.join(known_types)}. "
                        f"Also accepts aliases: {', '.join(aliases[:8])}..."
                    },
                )

        # Default exclusions (unless include_ignored is true)
        if not input.get("include_ignored", False):
            for exclusion in self.exclusions:
                cmd.extend(["--glob", f"!{exclusion}/**"])
                cmd.extend(["--glob", f"!**/{exclusion}/**"])

        # Max file size
        cmd.extend(["--max-filesize", str(self.max_file_size)])

        # JSON output only for content mode (other modes don't support it)
        if output_mode == "content":
            cmd.append("--json")

        # Pattern
        cmd.append(pattern)

        # Path - resolve relative paths against working_dir
        search_path = input.get("path", ".")
        path_obj = Path(search_path).expanduser()
        if not path_obj.is_absolute():
            search_path = str(Path(self.working_dir) / search_path)
        cmd.append(search_path)

        try:
            # Run ripgrep with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,  # Don't raise on non-zero exit (no matches = exit code 1)
                timeout=self.timeout,
            )

            # Check for errors
            if result.returncode not in [0, 1]:  # 0 = matches, 1 = no matches
                error_msg = result.stderr.strip() if result.stderr else "Unknown ripgrep error"
                return ToolResult(success=False, output=error_msg, error={"message": error_msg})

            # Parse output based on mode
            output: dict[str, Any] = {
                "pattern": pattern,
                "output_mode": output_mode,
            }

            if output_mode == "content":
                # Parse JSON output
                lines = result.stdout.strip().split("\n") if result.stdout.strip() else []

                matches = []
                for line in lines:
                    if not line:
                        continue
                    try:
                        match_data = json.loads(line)
                        if match_data.get("type") == "match":
                            matches.append(match_data["data"])
                    except json.JSONDecodeError:
                        # Skip malformed lines
                        continue

                # Format content with line numbers
                formatted_results = []
                for match in matches:
                    path = match.get("path", {}).get("text", "")
                    lines_data = match.get("lines", {})
                    line_number = match.get("line_number")

                    formatted_results.append(
                        {
                            "file": path,
                            "line_number": line_number,
                            "content": lines_data.get("text", "").rstrip(),
                        }
                    )

                # Capture total before pagination
                total_matches = len(formatted_results)

                # Handle head_limit and offset (apply default limit if not specified)
                offset = input.get("offset", 0)
                head_limit = input.get("head_limit")
                if head_limit is None:
                    head_limit = self.default_limits.get("content", 500)

                if offset > 0:
                    formatted_results = formatted_results[offset:]
                if head_limit > 0:
                    formatted_results = formatted_results[:head_limit]

                output["total_matches"] = total_matches
                output["matches_count"] = len(formatted_results)
                output["results"] = formatted_results
                if total_matches > len(formatted_results):
                    output["results_capped"] = True

            elif output_mode == "files_with_matches":
                # Parse plain text output (one file per line)
                files = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

                # Capture total before pagination
                total_files = len(files)

                # Handle head_limit and offset (apply default limit if not specified)
                offset = input.get("offset", 0)
                head_limit = input.get("head_limit")
                if head_limit is None:
                    head_limit = self.default_limits.get("files_with_matches", 200)

                if offset > 0:
                    files = files[offset:]
                if head_limit > 0:
                    files = files[:head_limit]

                output["total_matches"] = total_files
                output["matches_count"] = len(files)
                output["files"] = files
                if total_files > len(files):
                    output["results_capped"] = True

            elif output_mode == "count":
                # Parse count output (format: "filepath:count")
                lines = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

                # Parse all counts first
                all_counts: dict[str, int] = {}
                for line in lines:
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            filepath, count_str = parts  # Fixed: ripgrep outputs filepath:count
                            try:
                                all_counts[filepath] = int(count_str)
                            except ValueError:
                                continue

                # Capture total before pagination
                total_matches_sum = sum(all_counts.values())

                # Handle head_limit and offset on the count entries (apply default limit if not specified)
                offset = input.get("offset", 0)
                head_limit = input.get("head_limit")
                if head_limit is None:
                    head_limit = self.default_limits.get("count", 200)

                count_items = list(all_counts.items())
                if offset > 0:
                    count_items = count_items[offset:]
                if head_limit > 0:
                    count_items = count_items[:head_limit]
                counts = dict(count_items)

                output["total_matches"] = total_matches_sum
                output["matches_count"] = sum(counts.values())
                output["counts"] = counts
                if len(all_counts) > len(counts):
                    output["results_capped"] = True

            return ToolResult(success=True, output=output)

        except subprocess.TimeoutExpired:
            error_msg = "Search timed out. Try narrowing your search or using more specific patterns."
            return ToolResult(
                success=False,
                output=error_msg,
                error={"message": error_msg},
            )
        except Exception as e:
            error_msg = f"Search failed: {str(e)}"
            return ToolResult(success=False, output=error_msg, error={"message": error_msg})

    async def _execute_python(self, input: dict[str, Any]) -> ToolResult:
        """Execute search using Python re module (fallback path)."""
        pattern = input.get("pattern")
        if not pattern:
            error_msg = "Pattern is required"
            return ToolResult(success=False, output=error_msg, error={"message": error_msg})

        search_path = input.get("path", ".")
        output_mode = input.get("output_mode", "files_with_matches")
        ignore_case = input.get("-i", False)
        show_line_numbers = input.get("-n", True) and output_mode == "content"
        multiline = input.get("multiline", False)

        # Context lines (only for content mode)
        context_after = input.get("-A", 0) if output_mode == "content" else 0
        context_before = input.get("-B", 0) if output_mode == "content" else 0
        if "-C" in input and output_mode == "content":
            context_after = context_before = input["-C"]

        # Build glob pattern from type or glob parameter
        glob_pattern = input.get("glob", "**/*")
        if "type" in input:
            file_type = input["type"].lower()
            # Normalize aliases (e.g., "typescript" -> "ts", "python" -> "py")
            file_type = self.TYPE_ALIASES.get(file_type, file_type)

            # Check if we have a glob mapping for this type
            type_glob = self.TYPE_TO_GLOB.get(file_type)
            if type_glob:
                glob_pattern = f"**/{type_glob}"
            elif file_type not in self.KNOWN_RG_TYPES:
                # Unknown type - return helpful error
                known_types = sorted(self.KNOWN_RG_TYPES)
                aliases = sorted(self.TYPE_ALIASES.keys())
                return ToolResult(
                    success=False,
                    error={
                        "message": f"Unrecognized file type: '{input['type']}'. "
                        f"Valid types: {', '.join(known_types)}. "
                        f"Also accepts aliases: {', '.join(aliases[:8])}..."
                    },
                )

        try:
            # Compile regex
            flags = 0
            if ignore_case:
                flags |= re.IGNORECASE
            if multiline:
                flags |= re.MULTILINE | re.DOTALL

            regex = re.compile(pattern, flags)

            # Find files to search - resolve relative paths against working_dir
            path_obj = Path(search_path).expanduser()
            if not path_obj.is_absolute():
                path = Path(self.working_dir) / search_path
            else:
                path = path_obj
            if not path.exists():
                error_msg = f"Path not found: {search_path}"
                return ToolResult(success=False, output=error_msg, error={"message": error_msg})

            include_ignored = input.get("include_ignored", False)
            files = self._find_files(path, glob_pattern, include_ignored)

            # Search files based on mode
            output: dict[str, Any] = {
                "pattern": pattern,
                "output_mode": output_mode,
            }

            if output_mode == "content":
                # Collect all matches with content
                all_results = []
                for file_path in files:
                    matches = self._search_file_content(
                        file_path, regex, show_line_numbers, context_before, context_after
                    )
                    all_results.extend(matches)

                # Capture total before pagination
                total_matches = len(all_results)

                # Apply offset and head_limit (apply default limit if not specified)
                offset = input.get("offset", 0)
                head_limit = input.get("head_limit")
                if head_limit is None:
                    head_limit = self.default_limits.get("content", 500)
                if offset > 0:
                    all_results = all_results[offset:]
                if head_limit > 0:
                    all_results = all_results[:head_limit]

                output["total_matches"] = total_matches
                output["matches_count"] = len(all_results)
                output["results"] = all_results
                if total_matches > len(all_results):
                    output["results_capped"] = True

            elif output_mode == "files_with_matches":
                # Find files that contain matches
                matched_files = []
                for file_path in files:
                    if self._file_has_match(file_path, regex):
                        matched_files.append(str(file_path))

                # Capture total before pagination
                total_files = len(matched_files)

                # Apply offset and head_limit to matched files (apply default limit if not specified)
                offset = input.get("offset", 0)
                head_limit = input.get("head_limit")
                if head_limit is None:
                    head_limit = self.default_limits.get("files_with_matches", 200)
                if offset > 0:
                    matched_files = matched_files[offset:]
                if head_limit > 0:
                    matched_files = matched_files[:head_limit]

                output["total_matches"] = total_files
                output["matches_count"] = len(matched_files)
                output["files"] = matched_files
                if total_files > len(matched_files):
                    output["results_capped"] = True

            elif output_mode == "count":
                # Count matches per file
                all_counts: dict[str, int] = {}
                for file_path in files:
                    count = self._count_matches(file_path, regex)
                    if count > 0:
                        all_counts[str(file_path)] = count

                # Capture total before pagination
                total_matches_sum = sum(all_counts.values())

                # Apply offset and head_limit to count entries (apply default limit if not specified)
                offset = input.get("offset", 0)
                head_limit = input.get("head_limit")
                if head_limit is None:
                    head_limit = self.default_limits.get("count", 200)
                count_items = list(all_counts.items())
                if offset > 0:
                    count_items = count_items[offset:]
                if head_limit > 0:
                    count_items = count_items[:head_limit]
                counts = dict(count_items)

                output["total_matches"] = total_matches_sum
                output["matches_count"] = sum(counts.values())
                output["counts"] = counts
                if len(all_counts) > len(counts):
                    output["results_capped"] = True

            return ToolResult(success=True, output=output)

        except re.error as e:
            error_msg = f"Invalid regex pattern: {e}"
            return ToolResult(success=False, output=error_msg, error={"message": error_msg})
        except Exception as e:
            error_msg = f"Search failed: {str(e)}"
            return ToolResult(success=False, output=error_msg, error={"message": error_msg})

    def _find_files(self, path: Path, glob_pattern: str, include_ignored: bool = False) -> list[Path]:
        """Find files matching glob pattern, respecting exclusions."""
        files = []

        if path.is_file():
            return [path]

        try:
            for file_path in path.glob(glob_pattern):
                if not file_path.is_file():
                    continue

                # Check exclusions (unless include_ignored is True)
                if not include_ignored:
                    path_str = str(file_path)
                    skip = False
                    for exclusion in self.exclusions:
                        if f"/{exclusion}/" in path_str or path_str.endswith(f"/{exclusion}"):
                            skip = True
                            break
                    if skip:
                        continue

                # Check file size
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        continue
                except OSError:
                    continue

                # Skip binary files (simple heuristic)
                try:
                    with open(file_path, "rb") as f:
                        chunk = f.read(8192)
                        if b"\x00" in chunk:
                            continue  # Skip binary files
                except OSError:
                    continue

                files.append(file_path)
        except Exception:
            # Glob errors shouldn't crash the whole search
            pass

        return files

    def _file_has_match(self, file_path: Path, regex: re.Pattern[str]) -> bool:
        """Check if file contains any match."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
                return regex.search(content) is not None
        except Exception:
            return False

    def _count_matches(self, file_path: Path, regex: re.Pattern[str]) -> int:
        """Count number of matches in file."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
                return len(regex.findall(content))
        except Exception:
            return 0

    def _search_file_content(
        self, file_path: Path, regex: re.Pattern[str], show_line_numbers: bool, context_before: int, context_after: int
    ) -> list[dict[str, Any]]:
        """Search file and return matches with context."""
        results = []

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    result: dict[str, Any] = {
                        "file": str(file_path),
                        "content": line.rstrip(),
                    }

                    if show_line_numbers:
                        result["line_number"] = i

                    # Add context lines if requested
                    if context_before > 0 or context_after > 0:
                        # Calculate context window
                        start_idx = max(0, i - context_before - 1)  # -1 because i is 1-indexed
                        end_idx = min(len(lines), i + context_after)  # i-1+1 = i for the line after match

                        context_lines = []
                        for j in range(start_idx, end_idx):
                            context_lines.append(
                                {
                                    "line_number": j + 1,
                                    "content": lines[j].rstrip(),
                                    "is_match": (j + 1) == i,
                                }
                            )

                        result["context"] = context_lines

                    results.append(result)

        except Exception:
            # File read errors shouldn't crash the search
            pass

        return results
