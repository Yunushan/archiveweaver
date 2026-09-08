from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parent / "data"


def _read(name: str) -> Any:
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


class Catalog:
    """Read-only access to the generated solution/runtime catalog."""

    def __init__(self) -> None:
        self.data = _read("catalog.json")
        self.solutions = {item["id"]: item for item in self.data["solutions"]}
        self.runtimes = {item["id"]: item for item in self.data["runtimes"]}
        self.operating_systems = {item["id"]: item for item in self.data["operating_systems"]}
        self.formats = self.data["formats"]

    def solution(self, solution_id: str) -> dict:
        try:
            return self.solutions[solution_id]
        except KeyError as exc:
            choices = ", ".join(sorted(self.solutions))
            raise ValueError(f"Unknown solution '{solution_id}'. Choose one of: {choices}") from exc

    def runtime(self, mode: str) -> dict:
        try:
            return self.runtimes[mode]
        except KeyError as exc:
            choices = ", ".join(sorted(self.runtimes))
            raise ValueError(f"Unknown mode '{mode}'. Choose one of: {choices}") from exc

    def operating_system(self, os_id: str) -> dict:
        try:
            return self.operating_systems[os_id]
        except KeyError as exc:
            choices = ", ".join(sorted(self.operating_systems))
            raise ValueError(f"Unknown OS '{os_id}'. Choose one of: {choices}") from exc

