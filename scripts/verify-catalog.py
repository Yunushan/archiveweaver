#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from archiveweaver.catalog import Catalog  # noqa: E402
from archiveweaver.schema import validate_catalog  # noqa: E402


def main() -> int:
    catalog = Catalog()
    errors = validate_catalog(catalog)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"catalog valid: {len(catalog.solutions)} solutions, {len(catalog.runtimes)} modes, {len(catalog.operating_systems)} operating systems")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

