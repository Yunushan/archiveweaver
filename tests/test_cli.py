from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver.cli import _write_render_output, main


class CLITests(unittest.TestCase):
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
