from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .json_utils import load_json_document
from .path_utils import has_symlink_component


WINDOWS_ABSOLUTE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]{2})")


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    for path in sorted(root.rglob("*")):
        if has_symlink_component(path):
            raise ValueError(f"evidence bundle must not contain symlinked paths: {path}")
        if not path.is_file() or path.resolve() == output_resolved:
            continue
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "bytes": path.stat().st_size, "sha256": _sha256(path)})
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


def verify_evidence_index(index_path: Path) -> dict[str, Any]:
    if has_symlink_component(index_path) or not index_path.is_file():
        return {"status": "fail", "errors": ["evidence index must be a regular, non-symlink file"]}
    try:
        index = load_json_document(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return {"status": "fail", "errors": [f"cannot read evidence index: {exc}"]}
    if not isinstance(index, dict) or index.get("schema_version") != 1 or index.get("algorithm") != "sha256":
        return {"status": "fail", "errors": ["unsupported evidence index schema"]}
    entries = index.get("files")
    if not isinstance(entries, list):
        return {"status": "fail", "errors": ["evidence index files must be a list"]}

    root = index_path.parent
    errors: list[str] = []
    indexed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            errors.append("evidence index contains a malformed file entry")
            continue
        relative = entry["path"]
        if relative in indexed:
            errors.append(f"duplicate evidence index entry: {relative}")
            continue
        indexed.add(relative)
        path = _safe_file(root, relative)
        if path is None:
            errors.append(f"evidence file is missing, unsafe, or a symlink: {relative}")
            continue
        if entry.get("bytes") != path.stat().st_size:
            errors.append(f"evidence size mismatch: {relative}")
        if entry.get("sha256") != _sha256(path):
            errors.append(f"evidence digest mismatch: {relative}")

    actual: set[str] = set()
    for path in root.rglob("*"):
        if has_symlink_component(path):
            errors.append(f"symlink is not permitted in evidence bundle: {path.relative_to(root).as_posix()}")
        elif path.is_file() and path.resolve() != index_path.resolve():
            actual.add(path.relative_to(root).as_posix())
    for relative in sorted(actual - indexed):
        errors.append(f"unindexed evidence file: {relative}")
    for relative in sorted(indexed - actual):
        errors.append(f"indexed evidence file is not present: {relative}")
    return {"status": "pass" if not errors else "fail", "errors": errors, "files": len(entries)}
