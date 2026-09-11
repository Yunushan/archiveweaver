from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path

import yaml


MODULE = runpy.run_path("scripts/validate-yaml.py")
repository_yaml_files = MODULE["repository_yaml_files"]
validate_yaml_file = MODULE["validate_yaml_file"]


class YAMLValidationTests(unittest.TestCase):
    def test_repository_yaml_is_strictly_parseable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        files = repository_yaml_files(root)
        self.assertGreaterEqual(len(files), 50)
        self.assertGreaterEqual(sum(validate_yaml_file(path) for path in files), len(files))

    def test_duplicate_keys_and_empty_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.yml"
            duplicate.write_text("key: first\nkey: second\n", encoding="utf-8")
            with self.assertRaisesRegex(yaml.YAMLError, "duplicate key"):
                validate_yaml_file(duplicate)

            empty = root / "empty.yml"
            empty.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "at least one document"):
                validate_yaml_file(empty)

    def test_discovery_excludes_generated_and_audit_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github").mkdir()
            (root / ".github" / "workflow.yml").write_text("name: CI\n", encoding="utf-8")
            for ignored in (".git", ".codex-audit", "build", "dist", ".venv"):
                path = root / ignored
                path.mkdir()
                (path / "ignored.yml").write_text("bad: [\n", encoding="utf-8")
            self.assertEqual(
                [path.relative_to(root).as_posix() for path in repository_yaml_files(root)],
                [".github/workflow.yml"],
            )


if __name__ == "__main__":
    unittest.main()
