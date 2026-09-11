from __future__ import annotations

import os
import stat
from pathlib import Path


def _is_link_like(path: Path) -> bool:
    """Reject symlinks, junctions, and other Windows reparse points."""
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(observed.st_mode):
        return True
    attributes = getattr(observed, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def has_symlink_component(path: Path) -> bool:
    """Return whether any existing component of *path* is link-like.

    ``Path.resolve()`` deliberately follows links, so callers that use it for
    containment checks must inspect the unresolved path first.  This helper
    walks the absolute, non-resolved spelling of the path, rejects Windows
    junctions/reparse points as well as symlinks, and fails closed if a
    component cannot be inspected.
    """
    try:
        raw = Path(os.fspath(path))
        # ``os.path.abspath`` normalizes ``..`` and can therefore erase a
        # symlink component before it is inspected (for example,
        # ``link/../target``). Build the absolute spelling without resolving
        # or normalizing its individual components.
        absolute = raw if raw.is_absolute() else Path.cwd() / raw
        current = Path(absolute.anchor) if absolute.anchor else Path()
        for part in absolute.parts:
            if part in {absolute.anchor, "."}:
                continue
            current /= part
            if _is_link_like(current):
                return True
    except OSError:
        return True
    return False
