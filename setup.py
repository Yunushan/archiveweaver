from __future__ import annotations

from collections import defaultdict
from pathlib import Path, PurePosixPath

from setuptools import setup


ROOT = Path(__file__).resolve().parent
BUNDLE_MANIFEST = ROOT / "packaging" / "operational-bundle-files.txt"
ALLOWED_ROOTS = ("deploy/ansible/", "scripts/")


def operational_data_files() -> list[tuple[str, list[str]]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for raw_line in BUNDLE_MANIFEST.read_text(encoding="utf-8").splitlines():
        relative = raw_line.strip()
        if not relative or relative.startswith("#"):
            continue
        path = PurePosixPath(relative)
        if (
            relative in seen
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in relative
            or not relative.startswith(ALLOWED_ROOTS)
        ):
            raise RuntimeError(f"unsafe or duplicate operational bundle entry: {relative!r}")
        source = ROOT.joinpath(*path.parts)
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f"missing or unsafe operational bundle file: {relative}")
        seen.add(relative)
        destination = PurePosixPath("share", "archiveweaver", *path.parent.parts)
        grouped[destination.as_posix()].append(relative)
    if not seen:
        raise RuntimeError("operational bundle manifest is empty")
    return [
        (destination, sorted(sources))
        for destination, sources in sorted(grouped.items())
    ]


setup(data_files=operational_data_files())
