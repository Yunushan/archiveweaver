#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


MAX_GZIP_EPOCH = (1 << 32) - 1


def _validated_epoch(value: str) -> int:
    try:
        epoch = int(value, 10)
    except ValueError as exc:
        raise ValueError("build epoch must be an integer Unix timestamp") from exc
    if not 0 <= epoch <= MAX_GZIP_EPOCH:
        raise ValueError(f"build epoch must be between 0 and {MAX_GZIP_EPOCH}")
    return epoch


def _read_members(path: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    seen: set[str] = set()
    roots: set[str] = set()
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            name = member.name
            relative = PurePosixPath(name)
            if (
                not name
                or name in seen
                or relative.is_absolute()
                or ".." in relative.parts
                or "\\" in name
            ):
                raise ValueError(f"unsafe or duplicate sdist member: {name!r}")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"unsupported sdist member type: {name!r}")
            seen.add(name)
            roots.add(relative.parts[0])
            payload: bytes | None = None
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"could not read regular sdist member: {name!r}")
                payload = extracted.read()
                if len(payload) != member.size:
                    raise ValueError(f"short read for sdist member: {name!r}")
            entries.append((member, payload))
    if len(roots) != 1 or not entries:
        raise ValueError("sdist must contain one non-empty top-level directory")
    return entries


def normalize_sdist(path: Path, epoch: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"sdist must be a regular, non-symlink file: {path}")
    if not 0 <= epoch <= MAX_GZIP_EPOCH:
        raise ValueError(f"build epoch must be between 0 and {MAX_GZIP_EPOCH}")
    entries = _read_members(path)
    original_mode = stat.S_IMODE(path.stat().st_mode)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as raw_output:
            temporary_path = Path(raw_output.name)
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as normalized:
                    for member, payload in sorted(entries, key=lambda item: item[0].name):
                        canonical = copy.copy(member)
                        canonical.uid = 0
                        canonical.gid = 0
                        canonical.uname = ""
                        canonical.gname = ""
                        canonical.mtime = epoch
                        canonical.pax_headers = {}
                        normalized.addfile(
                            canonical,
                            io.BytesIO(payload) if payload is not None else None,
                        )
            raw_output.flush()
            os.fsync(raw_output.fileno())
        os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_sdist(path: Path, epoch: int) -> list[str]:
    errors: list[str] = []
    if path.is_symlink() or not path.is_file():
        return [f"sdist must be a regular, non-symlink file: {path}"]
    raw = path.read_bytes()
    if len(raw) < 10 or raw[:2] != b"\x1f\x8b":
        return [f"sdist is not a gzip stream: {path}"]
    if raw[3] != 0:
        errors.append("gzip header contains non-canonical optional fields")
    if raw[8] != 2 or raw[9] != 255:
        errors.append("gzip header does not use canonical maximum compression metadata")
    if int.from_bytes(raw[4:8], "little") != epoch:
        errors.append("gzip header timestamp does not match the build epoch")
    try:
        entries = _read_members(path)
    except (OSError, tarfile.TarError, ValueError) as exc:
        return [str(exc)]
    names = [member.name for member, _ in entries]
    if names != sorted(names):
        errors.append("sdist members are not in canonical name order")
    for member, _ in entries:
        if member.mtime != epoch:
            errors.append(f"{member.name!r} timestamp does not match the build epoch")
        if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
            errors.append(f"{member.name!r} contains host-specific ownership metadata")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize a Python sdist reproducibly")
    parser.add_argument("sdist", type=Path)
    parser.add_argument(
        "--epoch",
        default=os.environ.get("SOURCE_DATE_EPOCH", ""),
        help="Unix timestamp; defaults to SOURCE_DATE_EPOCH",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        epoch = _validated_epoch(args.epoch)
        if args.check:
            errors = check_sdist(args.sdist, epoch)
            if errors:
                for error in errors:
                    print(f"sdist normalization error: {error}")
                return 1
            digest = hashlib.sha256(args.sdist.read_bytes()).hexdigest()
        else:
            digest = normalize_sdist(args.sdist, epoch)
    except (OSError, tarfile.TarError, ValueError) as exc:
        print(f"sdist normalization failed: {exc}")
        return 2
    print(f"normalized sdist sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
