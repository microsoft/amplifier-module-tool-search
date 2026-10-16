"""Canonical path authorization for search tools."""

import unicodedata
from collections.abc import Iterable
from pathlib import Path

ACCESS_DENIED_MESSAGE = "Access denied: path is outside the allowed search roots"


class PathAuthorizationError(ValueError):
    """Raised when a requested search path is outside the configured roots."""


class PathAccessPolicy:
    """Explicit null permits reads; modules default omitted policy to cwd.

    Explicit lists (including empty) and denials remain restrictions.
    """

    def __init__(
        self,
        working_dir: str | Path,
        allowed_paths: str | Path | Iterable[str | Path] | None,
        denied_paths: str | Path | Iterable[str | Path] | None = None,
    ) -> None:
        self.working_dir = Path(working_dir).expanduser().resolve()

        def roots(values):
            if isinstance(values, (str, Path)):
                values = [values]
            if not isinstance(values, Iterable):
                raise ValueError('Search paths must be paths, lists of paths, or null')
            values = list(values)
            if any(not isinstance(path, (str, Path)) for path in values):
                raise ValueError('Search paths must be paths, lists of paths, or null')
            return tuple(self._resolve(path) for path in values)

        self.allowed_roots = None if allowed_paths is None else roots(allowed_paths)
        self.denied_roots = roots([] if denied_paths is None else denied_paths)

    @staticmethod
    def contains(path: Path, root: Path, *, denial: bool = False) -> bool:
        if path == root or path.is_relative_to(root):
            return True
        # resolve() does not normalize case on case-insensitive POSIX volumes.
        # File identity handles those aliases without conflating distinct files
        # on case-sensitive volumes. Ancestors also cover denied directories.
        for candidate in (path, *path.parents):
            # A hardlink outside an allowed path is not a new grant. Denials
            # also cover physical aliases; allows only admit equivalent names.
            if not denial and (unicodedata.normalize('NFC', str(candidate)).casefold()
                               != unicodedata.normalize('NFC', str(root)).casefold()):
                continue
            try:
                if candidate.samefile(root):
                    return True
            except OSError:
                pass
        return False

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
        if any(self.contains(resolved, root, denial=True) for root in self.denied_roots):
            return False
        return self.allowed_roots is None or any(
            self.contains(resolved, root) for root in self.allowed_roots
        )


def validate_glob_pattern(pattern: str) -> None:
    """Reject patterns that can make pathlib glob outside its authorized base."""
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or ".." in pattern_path.parts:
        raise PathAuthorizationError(ACCESS_DENIED_MESSAGE)
