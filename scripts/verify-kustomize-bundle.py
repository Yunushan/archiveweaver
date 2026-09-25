#!/usr/bin/env python3
"""Verify a complete, local-only staged Kustomize input tree.

The Ansible control host supplies file contents and stat results through stdin.
This verifier runs in the pinned controller environment, where PyYAML is present.
It binds the contents actually slurped to the approved canonical tree digest and
rejects remote inputs, references outside the tree, and execution-capable
Kustomize features before the control host renders or applies any resource.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import posixpath
import re
import sys
from collections.abc import Hashable
from pathlib import PurePosixPath
from typing import Any

try:
    import yaml
except ImportError:  # Fail deterministically if the controller image is incomplete.
    yaml = None  # type: ignore[assignment]


MAX_INPUT_BYTES = 48 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 1000
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
PORTABLE_PATH = re.compile(r"[A-Za-z0-9._/-]+\Z")
KUSTOMIZATION_NAMES = ("kustomization.yaml", "kustomization.yml", "Kustomization")
KUSTOMIZATION_KEYS = frozenset({
    "apiVersion", "kind", "resources", "bases", "components", "namespace",
    "namePrefix", "nameSuffix", "commonLabels", "commonAnnotations", "labels",
    "annotations", "images", "patches", "patchesStrategicMerge", "patchesJson6902",
    "configMapGenerator", "secretGenerator", "generatorOptions", "replacements",
    "replicas", "vars", "configurations", "crds", "openapi", "sortOptions",
    "buildMetadata",
})


class InvalidBundle(ValueError):
    """The staged tree or its Kustomize closure is not an approved local bundle."""


if yaml is not None:
    class _StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise InvalidBundle("Kustomization YAML must not contain aliases")
            return super().compose_node(parent, index)

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[Hashable, Any]:
            if not isinstance(node, yaml.MappingNode):
                raise InvalidBundle("Kustomization YAML has an invalid mapping")
            mapping: dict[Hashable, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key in mapping:
                    raise InvalidBundle("Kustomization YAML has a non-string or duplicate key")
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping


def _json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBundle("duplicate input JSON key")
        result[key] = value
    return result


def _safe_relative(path: Any) -> str:
    if (
        not isinstance(path, str)
        or not path
        or PORTABLE_PATH.fullmatch(path) is None
        or path.startswith("/")
        or "//" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise InvalidBundle("Kustomize input path is not a portable in-tree relative path")
    return path


def _entry_path(root: str, value: Any) -> str:
    if not isinstance(value, str) or not value.startswith(root + "/"):
        raise InvalidBundle("staged entry is outside the approved Kustomize root")
    return _safe_relative(value[len(root) + 1:])


def _protected_mode(entry: dict[str, Any], *, directory: bool) -> None:
    if entry.get("uid") != 0 or entry.get("gid") != 0:
        raise InvalidBundle("staged Kustomize input must be root-owned")
    mode = entry.get("mode")
    if not isinstance(mode, str) or re.fullmatch(r"0[0-7]{3}", mode) is None:
        raise InvalidBundle("staged Kustomize input has an invalid mode")
    if int(mode, 8) & 0o022:
        raise InvalidBundle("staged Kustomize input is group- or world-writable")
    if directory and (int(mode, 8) & 0o100) == 0:
        raise InvalidBundle("staged Kustomize directory is not traversable by root")
    if entry.get("islnk") is True:
        raise InvalidBundle("staged Kustomize input contains a symlink")


def _local_path(current_dir: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or PORTABLE_PATH.fullmatch(value) is None
        or value.startswith("/")
        or "//" in value
    ):
        raise InvalidBundle("Kustomize reference is not a portable local path")
    raw = value
    resolved = posixpath.normpath(posixpath.join(current_dir, raw))
    if resolved == "." or resolved.startswith("../") or resolved == "..":
        raise InvalidBundle("Kustomize reference escapes the staged tree")
    return _safe_relative(resolved)


def _paths(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise InvalidBundle(f"{label} must be a list of local paths")
    return value


def _check_closure(files: dict[str, bytes], file_modes: dict[str, str]) -> None:
    if yaml is None:
        raise InvalidBundle("PyYAML is required in the pinned controller environment")
    active: set[str] = set()
    visited: set[str] = set()

    def file_ref(directory: str, value: Any, label: str, *, private: bool = False) -> None:
        path = _local_path(directory, value)
        if path not in files:
            raise InvalidBundle(f"{label} references a missing or nonlocal file")
        if private and file_modes[path] not in {"0400", "0600"}:
            raise InvalidBundle(f"{label} must reference a root-private 0400 or 0600 file")

    def directory_ref(directory: str, value: Any, label: str, expected_kind: str) -> None:
        path = _local_path(directory, value)
        if path in files:
            if expected_kind == "Component":
                raise InvalidBundle(f"{label} must reference a local component directory")
            return
        prefix = path + "/"
        if not any(name.startswith(prefix) for name in files):
            raise InvalidBundle(f"{label} references a missing or remote Kustomize input")
        walk(path, expected_kind)

    def walk(directory: str, expected_kind: str = "Kustomization") -> None:
        if directory in active:
            raise InvalidBundle("Kustomize input contains a recursive directory reference")
        if directory in visited:
            return
        names = [posixpath.join(directory, name) if directory else name
                 for name in KUSTOMIZATION_NAMES]
        present = [name for name in names if name in files]
        if len(present) != 1:
            raise InvalidBundle("each referenced Kustomize directory needs exactly one Kustomization file")
        path = present[0]
        try:
            source = files[path].decode("utf-8", errors="strict")
            documents = list(yaml.load_all(source, Loader=_StrictLoader))
        except (UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
            raise InvalidBundle("Kustomization file is invalid or ambiguous YAML") from exc
        if len(documents) != 1 or not isinstance(documents[0], dict):
            raise InvalidBundle("Kustomization file must contain one mapping")
        model = documents[0]
        if model.get("kind") != expected_kind or model.get("apiVersion") not in (
            "kustomize.config.k8s.io/v1beta1", "kustomize.config.k8s.io/v1alpha1"
        ):
            raise InvalidBundle("Kustomization has an unsupported apiVersion or kind")
        if set(model) - KUSTOMIZATION_KEYS:
            raise InvalidBundle("Kustomization uses an unsupported or execution-capable field")
        active.add(directory)
        try:
            for key in ("resources", "bases"):
                for reference in _paths(model.get(key), key):
                    directory_ref(directory, reference, key, "Kustomization")
            for reference in _paths(model.get("components"), "components"):
                directory_ref(directory, reference, "components", "Component")
            for key in ("configurations", "crds", "patchesStrategicMerge"):
                for reference in _paths(model.get(key), key):
                    file_ref(directory, reference, key)
            for key in ("patches", "patchesJson6902", "replacements"):
                entries = model.get(key, [])
                if not isinstance(entries, list):
                    raise InvalidBundle(f"{key} must be a list")
                for entry in entries:
                    if key == "patchesStrategicMerge" and isinstance(entry, str):
                        file_ref(directory, entry, key)
                    elif isinstance(entry, dict):
                        if "path" in entry:
                            file_ref(directory, entry["path"], key)
                        elif key != "replacements" and "patch" not in entry:
                            raise InvalidBundle(f"{key} needs a local path or inline patch")
                    else:
                        raise InvalidBundle(f"{key} has an invalid entry")
            for key in ("configMapGenerator", "secretGenerator"):
                entries = model.get(key, [])
                if not isinstance(entries, list):
                    raise InvalidBundle(f"{key} must be a list")
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise InvalidBundle(f"{key} has an invalid generator")
                    if set(entry) - {"name", "namespace", "behavior", "type", "files", "envs", "literals", "options"}:
                        raise InvalidBundle(f"{key} has an unsupported generator field")
                    if key == "secretGenerator" and "literals" in entry:
                        raise InvalidBundle("secretGenerator literals embed secrets in public Kustomization bytes")
                    for reference in _paths(entry.get("files"), key + ".files"):
                        file_ref(directory, reference.split("=", 1)[-1], key + ".files",
                                 private=key == "secretGenerator")
                    for reference in _paths(entry.get("envs"), key + ".envs"):
                        file_ref(directory, reference, key + ".envs",
                                 private=key == "secretGenerator")
            openapi = model.get("openapi")
            if openapi is not None:
                if not isinstance(openapi, dict):
                    raise InvalidBundle("openapi must be a mapping")
                if "path" in openapi:
                    file_ref(directory, openapi["path"], "openapi.path")
        finally:
            active.remove(directory)
        visited.add(directory)

    walk("")


def verify(envelope: Any, expected_digest: str) -> None:
    if DIGEST.fullmatch(expected_digest) is None:
        raise InvalidBundle("approved Kustomize tree digest is invalid")
    if not isinstance(envelope, dict) or set(envelope) != {"root", "ancestors", "directories", "all_entries", "files"}:
        raise InvalidBundle("Kustomize input envelope has an invalid shape")
    root = envelope["root"]
    if (
        not isinstance(root, str)
        or len(PurePosixPath(root).parts) != 5
        or PurePosixPath(root).parts[:3] != ("/", "etc", "archiveweaver")
        or root.endswith("/")
        or ".." in root
    ):
        raise InvalidBundle("Kustomize root is outside the approved host path")
    ancestors = envelope["ancestors"]
    if not isinstance(ancestors, list) or len(ancestors) != 4:
        raise InvalidBundle("Kustomize root ancestry was not inspected")
    for entry in ancestors:
        if not isinstance(entry, dict) or not entry.get("isdir"):
            raise InvalidBundle("Kustomize root has a missing or non-directory ancestor")
        _protected_mode(entry, directory=True)
    expected_ancestors = ["/etc", "/etc/archiveweaver", str(PurePosixPath(root).parent), root]
    if [entry.get("path") for entry in ancestors] != expected_ancestors:
        raise InvalidBundle("Kustomize root ancestry differs from the approved path")
    directories = envelope["directories"]
    all_entries = envelope["all_entries"]
    file_rows = envelope["files"]
    if not all(isinstance(value, list) and len(value) <= MAX_ENTRIES for value in (directories, all_entries, file_rows)):
        raise InvalidBundle("Kustomize tree has an invalid or oversized entry list")
    dir_paths: set[str] = set()
    for entry in directories:
        if not isinstance(entry, dict) or entry.get("isdir") is not True:
            raise InvalidBundle("Kustomize tree contains a non-directory entry")
        _protected_mode(entry, directory=True)
        path = _entry_path(root, entry.get("path"))
        if path in dir_paths:
            raise InvalidBundle("Kustomize tree has a duplicate directory")
        dir_paths.add(path)
    files: dict[str, bytes] = {}
    file_modes: dict[str, str] = {}
    digest_rows: list[str] = []
    total_bytes = 0
    for row in file_rows:
        if not isinstance(row, dict) or not isinstance(row.get("item"), dict):
            raise InvalidBundle("Kustomize file observation is malformed")
        entry = row["item"]
        if entry.get("isreg") is not True or row.get("encoding") != "base64":
            raise InvalidBundle("Kustomize file observation is not a regular file")
        _protected_mode(entry, directory=False)
        if entry.get("nlink", 1) != 1:
            raise InvalidBundle("Kustomize file has multiple hard links")
        path = _entry_path(root, entry.get("path"))
        if path in files or path in dir_paths:
            raise InvalidBundle("Kustomize tree has a duplicate path")
        encoded = row.get("content")
        if not isinstance(encoded, str):
            raise InvalidBundle("Kustomize file content is missing")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InvalidBundle("Kustomize file content is not valid base64") from exc
        if len(content) > MAX_FILE_BYTES or entry.get("size") != len(content):
            raise InvalidBundle("Kustomize file size changed or exceeds its limit")
        total_bytes += len(content)
        if total_bytes > MAX_TREE_BYTES:
            raise InvalidBundle("Kustomize tree exceeds its content limit")
        observed = hashlib.sha256(content).hexdigest()
        if entry.get("checksum") != observed:
            raise InvalidBundle("Kustomize file changed between find and slurp")
        files[path] = content
        file_modes[path] = entry["mode"]
        digest_rows.append(f"{path}:{observed}")
    if not files:
        raise InvalidBundle("Kustomize tree contains no regular files")
    all_paths: set[str] = set()
    for entry in all_entries:
        if not isinstance(entry, dict):
            raise InvalidBundle("Kustomize tree has a malformed entry")
        path = _entry_path(root, entry.get("path"))
        if path in all_paths or path not in files and path not in dir_paths:
            raise InvalidBundle("Kustomize tree contains a duplicate or special entry")
        if path in files and entry.get("isreg") is not True:
            raise InvalidBundle("Kustomize tree file became a non-file")
        if path in dir_paths and entry.get("isdir") is not True:
            raise InvalidBundle("Kustomize tree directory became a non-directory")
        all_paths.add(path)
    if all_paths != set(files) | dir_paths:
        raise InvalidBundle("Kustomize tree enumeration is incomplete")
    canonical = "\n".join(sorted(digest_rows)).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != expected_digest:
        raise InvalidBundle("staged Kustomize bytes differ from the approved tree digest")
    _check_closure(files, file_modes)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify-kustomize-bundle.py <approved-tree-sha256> < input.json", file=sys.stderr)
        return 2
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES:
        print("Kustomize bundle input is empty or too large", file=sys.stderr)
        return 2
    try:
        envelope = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_json_no_duplicates)
        verify(envelope, argv[1])
    except (UnicodeDecodeError, json.JSONDecodeError, InvalidBundle, RecursionError) as exc:
        print(f"Kustomize bundle rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
