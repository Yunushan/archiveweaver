#!/usr/bin/env python3
"""Fail closed when a controller input path contains a symlink component."""

from __future__ import annotations

import sys
from pathlib import Path

# Keep the helper runnable both from the repository root and from an
# automation controller that invokes it with an explicit PYTHONPATH.
source_root = Path(__file__).resolve().parents[1] / "src"
if str(source_root) not in sys.path:
    sys.path.insert(0, str(source_root))

from archiveweaver.path_utils import has_symlink_component  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        print("usage: verify-path-boundary.py PATH [PATH ...]", file=sys.stderr)
        return 2
    return 1 if any(has_symlink_component(Path(value)) for value in values) else 0


if __name__ == "__main__":
    raise SystemExit(main())
