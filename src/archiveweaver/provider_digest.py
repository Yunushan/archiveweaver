from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .path_utils import has_symlink_component


def _sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_file(path: Path) -> str:
    if has_symlink_component(path) or not path.is_file():
        raise ValueError(f"provider content must be a regular file: {path}")
    return f"sha256:{_sha256_hex(path)}"


def digest_tree(directory: Path) -> str:
    if has_symlink_component(directory) or not directory.is_dir():
        raise ValueError(f"provider content must be a real directory: {directory}")
    entries: list[str] = []
    for path in sorted(directory.rglob("*")):
        if has_symlink_component(path):
            raise ValueError(f"provider content must not contain symlinked paths: {path}")
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            entries.append(f"{relative}:{_sha256_hex(path)}")
    if not entries:
        raise ValueError(f"provider directory contains no regular files: {directory}")
    return "sha256:" + hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


def digest_quadlet(directory: Path, service_name: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", service_name):
        raise ValueError("Quadlet service name must be a safe lowercase systemd name")
    if has_symlink_component(directory) or not directory.is_dir():
        raise ValueError(f"Quadlet directory must be a real directory: {directory}")
    files = (
        ("network", directory / f"archiveweaver-{service_name}.network"),
        ("volume", directory / f"archiveweaver-{service_name}.volume"),
        ("container", directory / f"{service_name}.container"),
    )
    entries = [f"{name}:{digest_file(path).removeprefix('sha256:')}" for name, path in files]
    return "sha256:" + hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()
