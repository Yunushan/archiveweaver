from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver.cli import main


class CLITests(unittest.TestCase):
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
