from __future__ import annotations

import contextlib
import importlib.util
import io
import runpy
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-catalog.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_catalog", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


class VerifyCatalogScriptTests(unittest.TestCase):
    def test_valid_catalog_prints_a_summary(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(MODULE.main(), 0)
        self.assertIn("catalog valid:", stdout.getvalue())

    def test_invalid_catalog_reports_every_error(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(MODULE, "validate_catalog", return_value=["first problem", "second problem"]):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(MODULE.main(), 1)
        self.assertIn("first problem", stderr.getvalue())
        self.assertIn("second problem", stderr.getvalue())

    def test_reload_keeps_the_module_importable(self) -> None:
        self.assertEqual(load_module().main(), 0)

    def test_main_guard_exits_with_the_catalog_result(self) -> None:
        with mock.patch.object(sys, "argv", ["verify-catalog.py"]):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
