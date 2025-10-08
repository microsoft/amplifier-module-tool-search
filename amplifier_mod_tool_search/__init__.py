"""Search Tools Module for Amplifier.

Provides grep and glob tools for searching files and content.
"""

import logging
from typing import Any, List

from amplifier_core import ModuleCoordinator, Tool

from .glob import GlobTool
from .grep import GrepTool

__all__ = ["GrepTool", "GlobTool", "mount"]

logger = logging.getLogger(__name__)


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None) -> None:
    """Mount search tools.

    Args:
        coordinator: Module coordinator for registering tools
        config: Module configuration

    Returns:
        None
    """
    config = config or {}

    # Get tool-specific config or use defaults
    grep_config = config.get("grep", {})
    glob_config = config.get("glob", {})

    # Merge with module-level defaults
    for key in ["max_results", "allowed_paths"]:
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
