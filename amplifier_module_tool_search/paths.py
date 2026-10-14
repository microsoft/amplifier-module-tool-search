"""Canonical path authorization for search tools."""

from collections.abc import Iterable
from pathlib import Path

ACCESS_DENIED_MESSAGE = "Access denied: path is outside the allowed search roots"


class PathAuthorizationError(ValueError):
    """Raised when a requested search path is outside the configured roots."""


class PathAccessPolicy:
    """Resolve search paths and enforce containment within configured roots."""

    def __init__(
        self,
        working_dir: str | Path,
        allowed_paths: str | Path | Iterable[str | Path] | None,
    ) -> None:
        self.working_dir = Path(working_dir).expanduser().resolve()
        configured_paths: Iterable[str | Path]
        if allowed_paths is None:
            configured_paths = ["."]
        elif isinstance(allowed_paths, (str, Path)):
            configured_paths = [allowed_paths]
        else:
            configured_paths = allowed_paths

        self.allowed_roots = tuple(self._resolve(path) for path in configured_paths)

    def _resolve(self, path: str | Path) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.working_dir / candidate
        return candidate.resolve()

    def resolve(self, path: str | Path) -> Path:
        """Resolve a requested path and reject it unless it is authorized."""
        resolved = self._resolve(path)
        if not self.is_allowed(resolved):
            raise PathAuthorizationError(ACCESS_DENIED_MESSAGE)
        return resolved

    def is_allowed(self, path: str | Path) -> bool:
        """Return whether a path resolves within any configured root."""
        resolved = self._resolve(path)
        return any(resolved == root or resolved.is_relative_to(root) for root in self.allowed_roots)


def validate_glob_pattern(pattern: str) -> None:
    """Reject patterns that can make pathlib glob outside its authorized base."""
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or ".." in pattern_path.parts:
        raise PathAuthorizationError(ACCESS_DENIED_MESSAGE)
