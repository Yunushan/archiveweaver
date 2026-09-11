from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from .json_utils import load_json_document


DATA_DIR = Path(__file__).resolve().parent / "data"


def _read(name: str) -> Any:
    return load_json_document((DATA_DIR / name).read_text(encoding="utf-8"))


def _index_records(value: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"catalog {label} must be a list")
    records: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"catalog {label} entry {position} must be an object")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError(f"catalog {label} entry {position} must have a non-empty string id")
        if identifier in records:
            raise ValueError(f"catalog {label} contains duplicate id '{identifier}'")
        records[identifier] = cast(dict[str, Any], item)
    return records


class Catalog:
    """Read-only access to the generated solution/runtime catalog."""

    def __init__(self) -> None:
        loaded = _read("catalog.json")
        if not isinstance(loaded, dict):
            raise ValueError("catalog root must be an object")
        self.data = cast(dict[str, Any], loaded)
        self.solutions = _index_records(self.data.get("solutions"), "solutions")
        self.runtimes = _index_records(self.data.get("runtimes"), "runtimes")
        self.operating_systems = _index_records(
            self.data.get("operating_systems"), "operating systems"
        )
        formats = self.data.get("formats")
        if not isinstance(formats, dict) or not all(
            isinstance(key, str) and isinstance(value, dict)
            for key, value in formats.items()
        ):
            raise ValueError("catalog formats must be an object of objects")
        self.formats = cast(dict[str, dict[str, Any]], formats)

    def solution(self, solution_id: str) -> dict[str, Any]:
        try:
            return self.solutions[solution_id]
        except KeyError as exc:
            choices = ", ".join(sorted(self.solutions))
            raise ValueError(f"Unknown solution '{solution_id}'. Choose one of: {choices}") from exc

    def runtime(self, mode: str) -> dict[str, Any]:
        try:
            return self.runtimes[mode]
        except KeyError as exc:
            choices = ", ".join(sorted(self.runtimes))
            raise ValueError(f"Unknown mode '{mode}'. Choose one of: {choices}") from exc

    def operating_system(self, os_id: str) -> dict[str, Any]:
        try:
            return self.operating_systems[os_id]
        except KeyError as exc:
            choices = ", ".join(sorted(self.operating_systems))
            raise ValueError(f"Unknown OS '{os_id}'. Choose one of: {choices}") from exc

