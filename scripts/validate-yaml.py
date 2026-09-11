#!/usr/bin/env python3
"""Parse every repository YAML document with strict duplicate-key handling."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver


ROOT = Path(__file__).resolve().parents[1]
IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "build",
    "dist",
    "dist-reproducibility",
    "node_modules",
    "site-packages",
    "venv",
}


class UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _ignored_directory(name: str) -> bool:
    return name in IGNORED_DIRECTORIES or name.startswith(".codex-")


def repository_yaml_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory, child_directories, child_files in os.walk(root, followlinks=False):
        child_directories[:] = sorted(
            name for name in child_directories if not _ignored_directory(name)
        )
        current = Path(directory)
        files.extend(
            current / name
            for name in sorted(child_files)
            if Path(name).suffix.lower() in {".yaml", ".yml"}
        )
    return sorted(files)


def validate_yaml_file(path: Path) -> int:
    if path.is_symlink() or not path.is_file():
        raise ValueError("YAML input must be a regular, non-symlink file")
    text = path.read_text(encoding="utf-8")
    documents = list(yaml.load_all(text, Loader=UniqueKeyLoader))
    if not documents:
        raise ValueError("YAML input must contain at least one document")
    return len(documents)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strictly parse repository YAML files",
    )
    parser.add_argument("paths", nargs="*", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    files = args.paths or repository_yaml_files(ROOT)
    if not files:
        print("YAML validation found no input files", file=sys.stderr)
        return 1

    errors: list[str] = []
    documents = 0
    for path in files:
        try:
            documents += validate_yaml_file(path)
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        for error in errors:
            print(f"YAML validation error: {error}", file=sys.stderr)
        return 1
    print(f"YAML validation passed: files={len(files)}, documents={documents}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
