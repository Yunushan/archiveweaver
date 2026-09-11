from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

from .evidence import _measure_regular_file, _stat_identity
from .path_utils import has_symlink_component


MAX_PROVIDER_FILE_BYTES = 64 * 1024 * 1024
MAX_PROVIDER_TREE_BYTES = 256 * 1024 * 1024
MAX_PROVIDER_TREE_ENTRIES = 20_000
MAX_PROVIDER_TREE_FILES = 10_000
MAX_PROVIDER_RELATIVE_PATH_BYTES = 4096
ProviderEntry = tuple[str, Path, bool, tuple[int, int, int, int, int, int]]


def _sha256_hex(path: Path) -> str:
    return _measure_regular_file(
        path,
        max_bytes=MAX_PROVIDER_FILE_BYTES,
        label="provider",
    )[1]


def _tree_snapshot(directory: Path) -> tuple[
    tuple[int, int, int, int, int, int],
    list[ProviderEntry],
]:
    """Capture a bounded, non-link provider tree without materializing infinity."""

    root_identity = _stat_identity(os.lstat(directory))
    entries: list[ProviderEntry] = []
    casefolded_paths: set[str] = set()
    try:
        discovered = directory.rglob("*")
        for path in discovered:
            if len(entries) >= MAX_PROVIDER_TREE_ENTRIES:
                raise ValueError(
                    "provider tree exceeds the "
                    f"{MAX_PROVIDER_TREE_ENTRIES}-entry safety limit"
                )
            if has_symlink_component(path):
                raise ValueError(
                    f"provider content must not contain symlinked paths: {path}"
                )
            relative = path.relative_to(directory).as_posix()
            if (
                len(relative.encode("utf-8")) > MAX_PROVIDER_RELATIVE_PATH_BYTES
                or not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
            ):
                raise ValueError(
                    "provider filenames must use bounded ASCII letters, digits, "
                    "'.', '_', '-', and '/'"
                )
            folded = relative.casefold()
            if folded in casefolded_paths:
                raise ValueError(
                    "provider paths must remain unique on case-insensitive filesystems"
                )
            casefolded_paths.add(folded)
            observed = os.lstat(path)
            is_file = stat.S_ISREG(observed.st_mode)
            if not is_file and not stat.S_ISDIR(observed.st_mode):
                raise ValueError(
                    f"provider content must contain only regular files and directories: {path}"
                )
            entries.append((relative, path, is_file, _stat_identity(observed)))
    except RecursionError as exc:
        raise ValueError("provider tree nesting exceeds the safe traversal limit") from exc
    return root_identity, sorted(entries, key=lambda entry: entry[0])


def digest_file(path: Path) -> str:
    if has_symlink_component(path) or not path.is_file():
        raise ValueError(f"provider content must be a regular file: {path}")
    return f"sha256:{_sha256_hex(path)}"


def digest_tree(directory: Path) -> str:
    if has_symlink_component(directory) or not directory.is_dir():
        raise ValueError(f"provider content must be a real directory: {directory}")
    root_before, snapshot_before = _tree_snapshot(directory)
    files = [entry for entry in snapshot_before if entry[2]]
    if len(files) > MAX_PROVIDER_TREE_FILES:
        raise ValueError(
            f"provider tree exceeds the {MAX_PROVIDER_TREE_FILES}-file safety limit"
        )
    entries: list[str] = []
    total_bytes = 0
    for relative, path, _, _ in files:
        measured, digest = _measure_regular_file(
            path,
            max_bytes=MAX_PROVIDER_FILE_BYTES,
            label="provider",
        )
        total_bytes += measured
        if total_bytes > MAX_PROVIDER_TREE_BYTES:
            raise ValueError(
                f"provider tree exceeds the {MAX_PROVIDER_TREE_BYTES}-byte safety limit"
            )
        entries.append(f"{relative}:{digest}")
    if not entries:
        raise ValueError(f"provider directory contains no regular files: {directory}")
    root_after, snapshot_after = _tree_snapshot(directory)
    before_identity = [
        (relative, is_file, identity)
        for relative, _, is_file, identity in snapshot_before
    ]
    after_identity = [
        (relative, is_file, identity)
        for relative, _, is_file, identity in snapshot_after
    ]
    if root_before != root_after or before_identity != after_identity:
        raise OSError(
            f"provider tree changed while it was being measured: {directory}"
        )
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
