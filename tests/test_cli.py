from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from archiveweaver.cli import _print_plan, _write_render_output, main


class CLITests(unittest.TestCase):
    def test_render_output_rejects_unsafe_targets_and_cleans_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "rendered.yml"

            with patch("archiveweaver.cli.has_symlink_component", return_value=True):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    _write_render_output(output, "safe: true\n")

            non_file = root / "directory"
            non_file.mkdir()
            with self.assertRaisesRegex(ValueError, "regular file"):
                _write_render_output(non_file, "safe: true\n")

            with patch(
                "archiveweaver.cli.has_symlink_component",
                side_effect=(False, True),
            ):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    _write_render_output(output, "safe: true\n")
            self.assertEqual(list(root.glob(".rendered.yml.*.tmp")), [])

            with (
                patch(
                    "archiveweaver.cli.has_symlink_component",
                    side_effect=(False, True),
                ),
                patch.object(Path, "unlink", side_effect=OSError("denied")),
            ):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    _write_render_output(output, "safe: true\n")

    def test_human_plan_output_includes_runtime_risks_and_actions(self) -> None:
        plan = {
            "solution_name": "Paperless-ngx",
            "mode_name": "Ansible",
            "os_name": "Ubuntu",
            "nodes": "3",
            "underlying_mode": "rke2",
            "status": "blocked",
            "support_level": "conditional",
            "topology_level": "conditional",
            "blockers": ["review topology"],
            "warnings": ["validate storage"],
            "prerequisites": ["sealed backup"],
            "steps": ["review", "deploy"],
            "commands": ["archiveweaver check"],
            "data_safety": ["preserve originals"],
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _print_plan(plan)
        rendered = output.getvalue()
        self.assertIn("underlying runtime: rke2", rendered)
        self.assertIn("Blockers\n- review topology", rendered)
        self.assertIn("Warnings\n- validate storage", rendered)
        self.assertIn("2. deploy", rendered)

    def test_evidence_index_accepts_an_absolute_output_inside_the_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir()
            (evidence / "report.txt").write_text("verified\n", encoding="utf-8")
            index = evidence / "absolute-index.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "evidence-index",
                        "--directory",
                        str(evidence),
                        "--output",
                        str(index),
                        "--json",
                    ]
                )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["index"], str(index))

    def test_render_json_without_output_returns_the_rendered_content(self) -> None:
        output = io.StringIO()
        with (
            patch(
                "archiveweaver.cli.render",
                return_value=({"status": "ready"}, "safe: true\n"),
            ),
            contextlib.redirect_stdout(output),
        ):
            result = main(
                [
                    "render",
                    "--solution",
                    "paperless-ngx",
                    "--mode",
                    "docker",
                    "--json",
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["content"], "safe: true\n")

    def test_unknown_future_command_fails_closed(self) -> None:
        parser = type(
            "Parser",
            (),
            {"parse_args": lambda self, argv: SimpleNamespace(command="future", json=False)},
        )()
        with patch("archiveweaver.cli.build_parser", return_value=parser):
            self.assertEqual(main([]), 2)

    def test_main_module_is_safe_to_import(self) -> None:
        try:
            module = importlib.import_module("archiveweaver.__main__")
            self.assertTrue(callable(module.main))
        finally:
            sys.modules.pop("archiveweaver.__main__", None)

    def test_incomplete_health_check_returns_warning_exit_status(self) -> None:
        report = {
            "summary": {
                "status": "warn",
                "failures": 0,
                "warnings": 0,
                "skipped": 3,
                "meaningful_passes": 0,
            }
        }
        with patch("archiveweaver.cli.run_checks", return_value=report):
            with contextlib.redirect_stdout(io.StringIO()):
                result = main(["check", "--solution", "paperless-ngx", "--json"])
        self.assertEqual(result, 1)

    def test_hook_digest_reports_executable_and_complete_argv_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "reviewed-hook"
            executable.write_bytes(b"reviewed hook\n")
            argv = [str(executable.resolve()), "safe argument"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["hook-digest", "--json", *argv])
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(
                payload["executable_sha256"],
                hashlib.sha256(executable.read_bytes()).hexdigest(),
            )
            self.assertRegex(payload["argv_sha256"], r"^[0-9a-f]{64}$")

    def test_list_solutions_exposes_ansible_support(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["list-solutions"])
        self.assertEqual(result, 0)
        self.assertIn("Ansible", output.getvalue())

    def test_catalog_load_failure_is_a_stable_json_error(self) -> None:
        output = io.StringIO()
        error = io.StringIO()
        with patch("archiveweaver.cli.Catalog", side_effect=ValueError("catalog is invalid")):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                result = main(["list-solutions", "--json"])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), '{\n  "status": "fail",\n  "errors": [\n    "catalog is invalid"\n  ]\n}\n')
        self.assertEqual(error.getvalue(), "")

    def test_render_rejects_symlinked_output_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            output = io.StringIO()
            error = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                result = main([
                    "render",
                    "--solution", "paperless-ngx",
                    "--mode", "docker",
                    "--output", str(link / "rendered.yml"),
                ])
            self.assertEqual(result, 2)
            self.assertIn("symlink", error.getvalue())

    def test_atomic_render_output_does_not_follow_a_swapped_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside.yml"
            target.write_text("original\n", encoding="utf-8")
            output = root / "rendered.yml"
            try:
                output.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"file symlinks are unavailable: {exc}")

            # Model a final-component swap after the path inspection. Atomic
            # replacement must replace the link, never truncate its target.
            with patch("archiveweaver.cli.has_symlink_component", return_value=False):
                _write_render_output(output, "safe: true\n")

            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            self.assertFalse(output.is_symlink())
            self.assertEqual(output.read_text(encoding="utf-8"), "safe: true\n")
