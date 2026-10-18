from __future__ import annotations

import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_catalog.py"
MODULE = runpy.run_path(str(SCRIPT))


def solution(source_repo: str, *, notes: list[str] | None = None, image_hint: str = "") -> dict:
    return {
        "id": "alpha",
        "name": "Alpha",
        "category": "cms",
        "license": "MIT",
        "mode_support": {"raw": "native", "docker": "validated", "rke2": "portable"},
        "upstream_repo": "https://example.invalid/alpha",
        "source_repo": source_repo,
        "official_docs": "https://example.invalid/alpha/docs",
        "homepage": "https://example.invalid/alpha",
        "health": {
            "default_port": 8080,
            "checks": ["/health"],
            "service_aliases": ["alpha"],
            "http_paths": ["/health"],
        },
        "image_hint": image_hint,
        "architecture_components": ["web", "worker"],
        "dependencies": ["postgres"],
        "format_profiles": ["documents"],
        "notes": [] if notes is None else notes,
    }


def topology(mode: str) -> dict[str, str]:
    return {"1": mode, "2": mode, "3": mode, "3+": mode}


def fixture_catalog(source_repos: list[str], **solution_kwargs) -> dict:
    return {
        "solutions": [solution(repo, **solution_kwargs) for repo in source_repos],
        "runtimes": [
            {"id": "raw", "name": "Raw", "topology": topology("native")},
            {"id": "docker", "name": "Docker", "topology": topology("validated")},
            {"id": "rke2", "name": "RKE2", "topology": topology("portable")},
        ],
        "operating_systems": [{"name": "Ubuntu", "family": "debian", "tier": "preferred"}],
        "formats": {
            "documents": {
                "label": "Documents",
                "extensions": ".pdf",
                "mime_examples": "application/pdf",
            }
        },
    }


class CatalogHelperTests(unittest.TestCase):
    def test_write_creates_parents_and_trims_trailing_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "page.md"
            MODULE["write"](path, "# Title\n\n\n")
            self.assertEqual(path.read_text(encoding="utf-8"), "# Title\n")

    def test_markdown_table_renders_headers_and_rows(self) -> None:
        rendered = MODULE["markdown_table"](["A", "B"], [["1", "2"], ["3", "4"]])
        self.assertEqual(
            rendered,
            "| A | B |\n| --- | --- |\n| 1 | 2 |\n| 3 | 4 |",
        )

    def test_mode_matrix_lists_every_runtime(self) -> None:
        data = fixture_catalog(["https://github.com/example/alpha"])
        rendered = MODULE["mode_matrix"](data["solutions"][0], data["runtimes"])
        self.assertIn("| Raw | native |", rendered)
        self.assertIn("| RKE2 | portable |", rendered)

    def test_solution_page_records_caveats_and_image_hints(self) -> None:
        data = fixture_catalog(["https://github.com/example/alpha"])
        plain = MODULE["solution_page"](
            data["solutions"][0], data["runtimes"], data["formats"]
        )
        self.assertIn("No product-specific caveat recorded yet.", plain)
        self.assertIn("No image pinned; use the upstream release", plain)

        annotated = solution(
            "https://github.com/example/alpha",
            notes=["Requires an external index."],
            image_hint="ghcr.io/example/alpha:1.0",
        )
        rendered = MODULE["solution_page"](annotated, data["runtimes"], data["formats"])
        self.assertIn("- Requires an external index.", rendered)
        self.assertIn("`ghcr.io/example/alpha:1.0`", rendered)


class CatalogMainTests(unittest.TestCase):
    def _sandbox(self, source_repos: list[str], **solution_kwargs) -> tuple[Path, "tempfile.TemporaryDirectory"]:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        data = fixture_catalog(source_repos, **solution_kwargs)
        with mock.patch.dict(MODULE["main"].__globals__, {"ROOT": root, "catalog": lambda: data}):
            MODULE["main"]()
        return root, directory

    def test_main_writes_every_generated_artifact(self) -> None:
        root, directory = self._sandbox(["https://github.com/example/alpha"])
        try:
            data_dir = root / "src" / "archiveweaver" / "data"
            self.assertEqual(
                sorted(path.name for path in data_dir.iterdir()),
                ["catalog.json", "formats.json", "operating_systems.json", "runtimes.json", "solutions.json"],
            )
            catalog_document = json.loads((data_dir / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual([entry["id"] for entry in catalog_document["solutions"]], ["alpha"])
            for relative in (
                "docs/solutions/alpha.md",
                "docs/reference/solutions-catalog.md",
                "docs/reference/support-matrix.md",
                "docs/reference/upstream-sources.md",
                "docs/reference/formats.md",
                "docs/reference/format-matrix.md",
                "docs/deployment/os-matrix.md",
            ):
                self.assertTrue((root / relative).is_file(), relative)
        finally:
            directory.cleanup()

    def test_single_external_source_is_named(self) -> None:
        root, directory = self._sandbox(["https://gitlab.example/alpha"])
        try:
            text = (root / "docs" / "reference" / "upstream-sources.md").read_text(encoding="utf-8")
        finally:
            directory.cleanup()
        self.assertIn("; Alpha use other official channels.", text)

    def test_multiple_external_sources_are_summarized(self) -> None:
        root, directory = self._sandbox(["https://gitlab.example/a", "https://codeberg.example/b"])
        try:
            text = (root / "docs" / "reference" / "upstream-sources.md").read_text(encoding="utf-8")
        finally:
            directory.cleanup()
        self.assertIn("Alpha, and Alpha use other official channels.", text)

    def test_github_only_sources_need_no_external_summary(self) -> None:
        root, directory = self._sandbox(["https://github.com/example/alpha"])
        try:
            text = (root / "docs" / "reference" / "upstream-sources.md").read_text(encoding="utf-8")
        finally:
            directory.cleanup()
        self.assertIn(";  use other official channels.", text)

    def test_main_guard_regenerates_without_writing(self) -> None:
        with mock.patch.object(Path, "write_text", return_value=None):
            runpy.run_path(str(SCRIPT), run_name="__main__")


if __name__ == "__main__":
    unittest.main()
