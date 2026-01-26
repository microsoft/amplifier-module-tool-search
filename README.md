# Search Tools Module

Self-contained search tools module for Amplifier, providing grep and glob functionality for file searching and content searching.

## Purpose

This module provides essential search capabilities:
- **GrepTool**: Search file contents using regex patterns (hybrid: ripgrep when available, Python re fallback)
- **GlobTool**: Find files matching glob patterns

## Prerequisites

- **Python 3.11+**
- **[UV](https://github.com/astral-sh/uv)** - Fast Python package manager
- **[ripgrep](https://github.com/BurntSushi/ripgrep)** - Optional (recommended for better performance)

### Installing UV

```bash
# macOS/Linux/WSL
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Installing ripgrep (Optional but Recommended)

Ripgrep provides significantly faster search performance. The tool automatically detects if ripgrep is available and falls back to Python's built-in `re` module if not.

```bash
# Ubuntu/Debian
apt install ripgrep

# macOS
brew install ripgrep

# Windows
choco install ripgrep
```

**Note**: GrepTool works without ripgrep installed - it will automatically use Python's `re` module as a fallback, providing universal compatibility with graceful performance degradation.

## Installation

```bash
uv pip install -e .
```

## Configuration

Add to your Amplifier configuration:

```yaml
modules:
  search:
    module: "amplifier-module-tool-search"
    source: "git+https://github.com/microsoft/amplifier-module-tool-search@main"
    config:
      working_dir: "."   # Working directory (defaults to session.working_dir capability)
      max_results: 500   # Maximum results to return
```

> **Note**: If `working_dir` is not set in config, the module uses the `session.working_dir` coordinator capability if available, falling back to `Path.cwd()`. This enables correct behavior in server/web deployments.

Note: GrepTool automatically detects if ripgrep is available:
- **With ripgrep**: Uses ripgrep for extreme performance (recommended)
- **Without ripgrep**: Falls back to Python's `re` module (slower but works everywhere)

## Practical Examples

### Common Search Patterns

**Find all Python classes:**
```json
{
  "pattern": "^class \\w+",
  "type": "py",
  "output_mode": "content",
  "head_limit": 20
}
```

**Find TODOs in code:**
```json
{
  "pattern": "TODO|FIXME|XXX",
  "-i": true,
  "output_mode": "content",
  "glob": "**/*.py"
}
```

**Count imports per file:**
```json
{
  "pattern": "^import |^from ",
  "type": "py",
  "output_mode": "count"
}
```

**Find files containing specific text:**
```json
{
  "pattern": "AmplifierSession",
  "output_mode": "files_with_matches",
  "glob": "**/*.md"
}
```

**Search with context (show surrounding lines):**
```json
{
  "pattern": "def execute",
  "type": "py",
  "output_mode": "content",
  "-C": 3,
  "head_limit": 5
}
```

**Pagination example (iterate through results):**
```json
// First page
{
  "pattern": "function",
  "type": "js",
  "output_mode": "content",
  "head_limit": 50,
  "offset": 0
}

// Second page (use total_matches to know if more exist)
{
  "pattern": "function",
  "type": "js",
  "output_mode": "content",
  "head_limit": 50,
  "offset": 50
}
```

### Performance Tips

**Grep performance:**
- **With ripgrep installed**: Extremely fast, optimized for large codebases
- **Without ripgrep**: Slower but functional, good for smaller projects
- **Tip**: Install ripgrep for best experience on large codebases

**Glob performance:**
- Returns results sorted by modification time (newest first)
- Fast for any codebase size
- Use `type: "file"` to exclude directories from results

**Choosing between glob and type parameter:**
- **Use `type`** when searching standard file types (faster with ripgrep):
  ```json
  {"pattern": "error", "type": "py"}  // Optimized
  ```

- **Use `glob`** for custom patterns or multiple extensions:
  ```json
  {"pattern": "error", "glob": "**/*.{test.py,spec.py}"}  // Custom pattern
  ```

## Tools

### GrepTool

Search file contents with regex patterns using ripgrep (fast) or Python re (fallback).

**Input:**
```json
{
  "pattern": "TODO|FIXME",
  "path": "src",
  "output_mode": "content",
  "-i": false,
  "-n": true,
  "-C": 2,
  "glob": "*.py",
  "type": "py",
  "multiline": false,
  "head_limit": 100,
  "offset": 0
}
```

**Parameters:**
- `pattern` (required): Regular expression pattern to search for
- `path`: File or directory to search (default: current directory)
- `output_mode`: Output format - "content" (matching lines), "files_with_matches" (file paths only), or "count" (match counts)
- `-i`: Case insensitive search
- `-n`: Show line numbers (default: true for content mode)
- `-A`: Lines of context after each match
- `-B`: Lines of context before each match
- `-C`: Lines of context before and after each match
- `glob`: Glob pattern to filter files (e.g., "*.py", "*.{ts,tsx}")
- `type`: File type to search (e.g., "js", "py", "rust") - more efficient than glob
- `multiline`: Enable multiline mode for cross-line patterns
- `head_limit`: Limit output to first N results (default: 0 = unlimited). Use with `total_matches` to implement pagination.
- `offset`: Skip first N results before applying head_limit (default: 0)

**Features:**
- **Hybrid performance**: Automatically uses ripgrep (fast) or Python re (fallback)
- Full regex syntax support
- Multiple output modes (content, files, counts)
- Context lines with flexible -A/-B/-C options
- File filtering by glob pattern or file type
- Multiline pattern matching
- Result pagination with head_limit and offset
- Binary file detection and skipping
- Universal compatibility (works with or without ripgrep)

**Output (content mode):**
```json
{
  "pattern": "TODO|FIXME",
  "output_mode": "content",
  "total_matches": 47,
  "matches_count": 5,
  "results": [
    {
      "file": "src/main.py",
      "line_number": 42,
      "content": "# TODO: Implement this function",
      "context": [
        {"line_number": 40, "content": "def process():", "is_match": false},
        {"line_number": 41, "content": "    \"\"\"Process data.\"\"\"", "is_match": false},
        {"line_number": 42, "content": "    # TODO: Implement this function", "is_match": true},
        {"line_number": 43, "content": "    pass", "is_match": false},
        {"line_number": 44, "content": "", "is_match": false}
      ]
    }
  ]
}
```
Note: `context` field only appears when `-A`, `-B`, or `-C` options are used.

**Output (files_with_matches mode):**
```json
{
  "pattern": "TODO",
  "output_mode": "files_with_matches",
  "total_matches": 15,
  "matches_count": 3,
  "files": [
    "src/main.py",
    "src/utils.py",
    "tests/test_main.py"
  ]
}
```
Note: `total_matches` shows all matching files, `matches_count` shows files after pagination.

**Output (count mode):**
```json
{
  "pattern": "TODO",
  "output_mode": "count",
  "total_matches": 47,
  "matches_count": 10,
  "counts": {
    "src/main.py": 5,
    "src/utils.py": 3,
    "tests/test_main.py": 2
  }
}
```
Note: `total_matches` is sum of ALL file counts, `matches_count` is sum after pagination.

### GlobTool

Find files matching glob patterns.

**Input:**
```json
{
  "pattern": "**/*.py",
  "path": ".",
  "type": "file",
  "exclude": ["*_test.py", "*.pyc"]
}
```

**Features:**
- Standard glob pattern matching
- Type filtering (file/dir/any)
- Multiple exclusion patterns
- File size information
- Configurable result limits

**Output:**
```json
{
  "pattern": "**/*.py",
  "base_path": ".",
  "count": 10,
  "matches": [
    {
      "path": "src/main.py",
      "type": "file",
      "size": 1234
    },
    {
      "path": "src/utils.py",
      "type": "file",
      "size": 567
    }
  ]
}
```

## Design Philosophy

This module follows Amplifier's modular design principles:

- **Self-contained**: All functionality within the module directory
- **Simple interface**: Clear input/output contracts via ToolResult
- **Fail gracefully**: Meaningful error messages, partial results on file errors
- **Opportunistic performance**: Uses ripgrep when available, falls back to Python re for universal compatibility
- **Minimal dependencies**: Uses only Python standard library + amplifier-core (ripgrep optional)

## Error Handling

Both tools handle errors gracefully:

- Invalid patterns return clear error messages
- Non-existent paths are reported
- File access errors don't stop the entire search
- Results are truncated at max_results with indication

## Security

- Binary file detection (ripgrep has it built-in, Python re uses heuristic)
- No arbitrary code execution (uses trusted tools: ripgrep binary or Python re module)
- Result limits prevent memory exhaustion
- File size limits prevent memory exhaustion (configurable, default 10MB)
- Path traversal handled safely by both ripgrep and Python Path library

## Testing

```bash
# Install in development mode
uv pip install -e .

# Run basic tests (when available)
pytest tests/
```

## Module Contract

**Purpose**: Provide file and content search capabilities

**Inputs**: Search patterns and paths via tool execute() methods

**Outputs**: ToolResult with matched files or content

**Side Effects**: None (read-only operations)

**Dependencies**: amplifier-core, ripgrep (optional system binary for performance)

## Regeneration Specification

This module can be regenerated from this specification:
- Two tools: GrepTool and GlobTool
- Standard execute() interface returning ToolResult
- Configuration via __init__ parameters
- Mount function returning tool instances
- No external dependencies beyond amplifier-core

## Contributing

> [!NOTE]
> This project is not currently accepting external contributions, but we're actively working toward opening this up. We value community input and look forward to collaborating in the future. For now, feel free to fork and experiment!

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
