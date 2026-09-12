#!/usr/bin/env python3
"""Verify the controller-approved SHA-256 binding for a readiness manifest."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from archiveweaver.path_utils import has_symlink_component  # noqa: E402
from archiveweaver.evidence import _measure_regular_file  # noqa: E402


MAX_MANIFEST_BYTES = 4 * 1024 * 1024


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: verify-readiness-manifest.py <manifest> <sha256-hex>", file=sys.stderr)
        return 2

    manifest = Path(argv[1])
    expected = argv[2]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        print("the approved readiness manifest binding must be a 64-character SHA-256 hex digest", file=sys.stderr)
        return 2
    if has_symlink_component(manifest) or not manifest.is_file():
        print("the readiness manifest must be a regular, non-symlink file", file=sys.stderr)
        return 1

    try:
        resolved = manifest.resolve()
        resolved.relative_to(REPOSITORY_ROOT.resolve())
        _, actual = _measure_regular_file(
            resolved,
            max_bytes=MAX_MANIFEST_BYTES,
            label="readiness manifest",
        )
    except (OSError, RuntimeError, ValueError):
        print("the readiness manifest must stay inside the signed repository checkout", file=sys.stderr)
        return 1
    if actual != expected:
        print("the readiness manifest does not match the controller-approved digest", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
