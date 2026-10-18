from __future__ import annotations

import contextlib
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_unhashable_mapping_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unhashable = root / "unhashable.yml"
            unhashable.write_text("? [one, two]\n: value\n", encoding="utf-8")
            with self.assertRaisesRegex(yaml.YAMLError, "unhashable mapping key"):
                validate_yaml_file(unhashable)

    def test_non_file_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "document.yml"
            target.write_text("name: real\n", encoding="utf-8")
            link = root / "linked.yml"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular, non-symlink file"):
                validate_yaml_file(root)
            with self.assertRaisesRegex(ValueError, "regular, non-symlink file"):
                validate_yaml_file(link)

    def test_parse_args_defaults_to_an_empty_path_list(self) -> None:
        self.assertEqual(MODULE["parse_args"]([]).paths, [])

    def test_main_validates_explicit_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.yml"
            first.write_text("name: first\n", encoding="utf-8")
            second = root / "second.yaml"
            second.write_text("---\nname: one\n---\nname: two\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(MODULE["main"]([str(first), str(second)]), 0)
            self.assertIn("files=2, documents=3", stdout.getvalue())

    def test_main_reports_invalid_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            broken = root / "broken.yml"
            broken.write_text("key: [\n", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(MODULE["main"]([str(broken)]), 1)
            self.assertIn("YAML validation error:", stderr.getvalue())

    def test_main_rejects_an_empty_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with mock.patch.dict(MODULE["main"].__globals__, {"ROOT": Path(directory)}):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(MODULE["main"]([]), 1)
            self.assertIn("found no input files", stderr.getvalue())

    def test_main_guard_exits_with_the_validation_status(self) -> None:
        with mock.patch.object(sys, "argv", ["validate-yaml.py"]):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path("scripts/validate-yaml.py", run_name="__main__")
        self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
