"""Search Tools Module for Amplifier.

Provides grep and glob tools for searching files and content.
"""

# Amplifier module metadata
__amplifier_module_type__ = "tool"

import logging
from typing import Any

from amplifier_core import ModuleCoordinator

from .glob import GlobTool
from .grep import GrepTool

__all__ = ["GrepTool", "GlobTool", "mount"]

logger = logging.getLogger(__name__)


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None) -> None:
    """Mount search tools.

    Args:
        coordinator: Module coordinator for registering tools
        config: Module configuration
            - working_dir: Base directory for searches (default: ".")
              If not set, falls back to session.working_dir capability.
            - max_results: Maximum results per search (default: 500)
            - grep: GrepTool-specific config overrides
            - glob: GlobTool-specific config overrides

    Returns:
        None
    """
    config = config or {}

    # If working_dir not explicitly set in config, use session.working_dir capability
    # This enables server deployments where Path.cwd() returns the wrong directory
    if "working_dir" not in config:
        working_dir = coordinator.get_capability("session.working_dir")
        if working_dir:
            config = {**config, "working_dir": working_dir}

    # Get tool-specific config or use defaults
    grep_config = config.get("grep", {})
    glob_config = config.get("glob", {})

    # Merge with module-level defaults
    for key in ["max_results", "allowed_paths", "working_dir"]:
        if key in config and key not in grep_config:
            grep_config[key] = config[key]
        if key in config and key not in glob_config:
            glob_config[key] = config[key]

    # Create tool instances
    tools = [
        GrepTool(grep_config),
        GlobTool(glob_config),
    ]

    # Register tools with coordinator
    for tool in tools:
        await coordinator.mount("tools", tool, name=tool.name)

    logger.info(f"Mounted {len(tools)} search tools")
