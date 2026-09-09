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
        absolute = Path(os.path.abspath(os.fspath(path)))
        current = Path(absolute.anchor) if absolute.anchor else Path()
        for part in absolute.parts:
            if part == absolute.anchor:
                continue
            current /= part
            if current.is_symlink():
                return True
    except OSError:
        return True
    return False
