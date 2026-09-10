from __future__ import annotations

import os
from pathlib import Path


def has_symlink_component(path: Path) -> bool:
    """Return whether any existing component of *path* is a symlink.

    ``Path.resolve()`` deliberately follows links, so callers that use it for
    containment checks must inspect the unresolved path first.  This helper
    walks the absolute, non-resolved spelling of the path and fails closed if
    a component cannot be inspected.
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
            if current.is_symlink():
                return True
    except OSError:
        return True
    return False
