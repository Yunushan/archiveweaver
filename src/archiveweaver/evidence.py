from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from .json_utils import load_json_document
from .path_utils import has_symlink_component


WINDOWS_ABSOLUTE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]{2})")
MAX_EVIDENCE_INDEX_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_INDEX_FILES = 10_000
MAX_EVIDENCE_BUNDLE_ENTRIES = MAX_EVIDENCE_INDEX_FILES * 4


def _bundle_paths(root: Path) -> list[Path]:
    """Enumerate a bundle as a bounded operation that reports traversal errors."""
    paths: list[Path] = []
    try:
        for path in root.rglob("*"):
            if len(paths) >= MAX_EVIDENCE_BUNDLE_ENTRIES:
                raise ValueError(
                    "evidence bundle exceeds the "
                    f"{MAX_EVIDENCE_BUNDLE_ENTRIES}-entry safety limit"
                )
            paths.append(path)
    except (OSError, RuntimeError) as exc:
        raise OSError(f"cannot enumerate evidence bundle safely: {root}: {exc}") from exc
    return sorted(paths)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Capture identity and mutation-sensitive metadata for one file."""
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _safe_file(root: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or candidate.anchor
        or candidate.drive
        or WINDOWS_ABSOLUTE_RE.match(relative)
        or "\\" in relative
        or "\x00" in relative
        or not relative
        or any(part == ".." for part in candidate.parts)
    ):
        return None
    candidate_path = root / candidate
    try:
        current = root
        for part in candidate.parts:
            current = current / part
            if current.is_symlink():
                return None
    except OSError:
        return None
    try:
        resolved_root = root.resolve()
        resolved = candidate_path.resolve()
        resolved.relative_to(resolved_root)
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _inspect_regular_file(
    path: Path,
    *,
    capture: bool,
    max_bytes: int | None = None,
    label: str = "evidence",
) -> tuple[int, str, bytes | None]:
    """Inspect one stable regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    measured = 0
    captured: list[bytes] | None = [] if capture else None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"{label} path is not a regular file: {path}")
        if before.st_nlink != 1:
            raise OSError(
                f"{label} path must have exactly one hard link: {path}"
            )
        if max_bytes is not None and before.st_size > max_bytes:
            raise OSError(
                f"{label} path exceeds the {max_bytes}-byte safety limit: {path}"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                measured += len(chunk)
                if max_bytes is not None and measured > max_bytes:
                    raise OSError(
                        f"{label} path exceeds the {max_bytes}-byte safety limit: {path}"
                    )
                digest.update(chunk)
                if captured is not None:
                    captured.append(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if (
        _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(path_after)
        or after.st_nlink != 1
        or measured != after.st_size
        or has_symlink_component(path)
    ):
        raise OSError(f"{label} file changed while it was being measured: {path}")
    return measured, digest.hexdigest(), None if captured is None else b"".join(captured)


def _measure_regular_file(
    path: Path,
    *,
    max_bytes: int | None = None,
    label: str = "evidence",
) -> tuple[int, str]:
    measured, digest, _ = _inspect_regular_file(
        path,
        capture=False,
        max_bytes=max_bytes,
        label=label,
    )
    return measured, digest


def _read_stable_bytes(
    path: Path,
    *,
    max_bytes: int | None = None,
) -> tuple[bytes, str]:
    """Return bytes and SHA-256 from the same stable file observation."""
    _, digest, content = _inspect_regular_file(
        path,
        capture=True,
        max_bytes=max_bytes,
    )
    if content is None:  # pragma: no cover - enforced by capture=True
        raise OSError(f"could not capture evidence file: {path}")
    return content, digest


def build_evidence_index(directory: Path, output: Path) -> dict[str, Any]:
    root = directory.resolve()
    if has_symlink_component(directory):
        raise ValueError(f"evidence directory must not resolve through a symlink: {directory}")
    if not root.is_dir():
        raise ValueError(f"evidence directory does not exist: {directory}")
    if has_symlink_component(output):
        raise ValueError("evidence index output must not be a symlink")
    output_resolved = output.resolve()
    try:
        output_resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("evidence index must be written inside the evidence directory") from exc

    files: list[dict[str, Any]] = []
    for path in _bundle_paths(root):
        if has_symlink_component(path):
            raise ValueError(f"evidence bundle must not contain symlinked paths: {path}")
        if not path.is_file() or path.resolve() == output_resolved:
            continue
        relative = path.relative_to(root).as_posix()
        measured_bytes, digest = _measure_regular_file(path)
        files.append({"path": relative, "bytes": measured_bytes, "sha256": digest})
        if len(files) > MAX_EVIDENCE_INDEX_FILES:
            raise ValueError(
                f"evidence bundle exceeds the {MAX_EVIDENCE_INDEX_FILES}-file safety limit"
            )
    index = {"schema_version": 1, "algorithm": "sha256", "files": files}
    payload = json.dumps(index, indent=2, sort_keys=True) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass
    return index


def verify_evidence_index(
    index_path: Path,
    *,
    expected_sha256: str | None = None,
    include_entries: bool = False,
) -> dict[str, Any]:
    if has_symlink_component(index_path) or not index_path.is_file():
        return {"status": "fail", "errors": ["evidence index must be a regular, non-symlink file"]}
    try:
        index_bytes, index_digest = _read_stable_bytes(
            index_path,
            max_bytes=MAX_EVIDENCE_INDEX_BYTES,
        )
        index = load_json_document(index_bytes.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {"status": "fail", "errors": [f"cannot read evidence index: {exc}"]}
    if expected_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            return {
                "status": "fail",
                "errors": [
                    "expected evidence index SHA-256 must be 64 lowercase hexadecimal characters"
                ],
            }
        if index_digest != expected_sha256:
            return {
                "status": "fail",
                "errors": ["evidence index digest mismatch"],
                "sha256": index_digest,
            }
    if (
        not isinstance(index, dict)
        or set(index) != {"schema_version", "algorithm", "files"}
        or index.get("schema_version") != 1
        or index.get("algorithm") != "sha256"
    ):
        return {"status": "fail", "errors": ["unsupported evidence index schema"]}
    entries = index.get("files")
    if not isinstance(entries, list):
        return {"status": "fail", "errors": ["evidence index files must be a list"]}
    if len(entries) > MAX_EVIDENCE_INDEX_FILES:
        return {
            "status": "fail",
            "errors": [
                f"evidence index exceeds the {MAX_EVIDENCE_INDEX_FILES}-file safety limit"
            ],
        }

    root = index_path.parent
    try:
        resolved_index_path = index_path.resolve()
    except (OSError, RuntimeError) as exc:
        return {
            "status": "fail",
            "errors": [f"cannot resolve evidence index safely: {exc}"],
        }
    errors: list[str] = []
    indexed: set[str] = set()
    seen_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            errors.append("evidence index contains a malformed file entry")
            continue
        relative = entry["path"]
        if relative in seen_paths:
            errors.append(f"duplicate evidence index entry: {relative}")
            continue
        seen_paths.add(relative)
        if (
            set(entry) != {"path", "bytes", "sha256"}
            or type(entry.get("bytes")) is not int
            or entry["bytes"] < 0
            or not isinstance(entry.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        ):
            errors.append("evidence index contains a malformed file entry")
            continue
        indexed.add(relative)
        path = _safe_file(root, relative)
        if path is None:
            errors.append(f"evidence file is missing, unsafe, or a symlink: {relative}")
            continue
        try:
            measured_bytes, digest = _measure_regular_file(path)
        except OSError as exc:
            errors.append(f"evidence file could not be measured safely: {relative}: {exc}")
            continue
        if entry["bytes"] != measured_bytes:
            errors.append(f"evidence size mismatch: {relative}")
        if entry["sha256"] != digest:
            errors.append(f"evidence digest mismatch: {relative}")

    actual: set[str] = set()
    try:
        for path in _bundle_paths(root):
            relative = path.relative_to(root).as_posix()
            if has_symlink_component(path):
                errors.append(f"symlink is not permitted in evidence bundle: {relative}")
            elif path.is_file() and path.resolve() != resolved_index_path:
                actual.add(relative)
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append(f"evidence bundle could not be enumerated safely: {exc}")
    for relative in sorted(actual - indexed):
        errors.append(f"unindexed evidence file: {relative}")
    for relative in sorted(indexed - actual):
        errors.append(f"indexed evidence file is not present: {relative}")
    report: dict[str, Any] = {
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "files": len(entries),
        "sha256": index_digest,
    }
    if include_entries and not errors:
        report["_entries"] = {
            entry["path"]: (entry["bytes"], entry["sha256"])
            for entry in entries
        }
    return report
