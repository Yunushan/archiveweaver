from __future__ import annotations

import contextlib
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-path-boundary.py"
SOURCE_ROOT = str(ROOT / "src")


def load():
    return runpy.run_path(str(SCRIPT))


class PathBoundaryScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.main = load()["main"]

    def test_usage_without_arguments(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self.main([]), 2)
        self.assertIn("usage: verify-path-boundary.py", stderr.getvalue())

    def test_reads_process_arguments_when_argv_is_none(self) -> None:
        with mock.patch.object(sys, "argv", ["verify-path-boundary.py", "definitely/missing"]):
            self.assertEqual(self.main(), 0)

    def test_plain_path_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.main([directory, str(Path(directory) / "child")]), 0)

    def test_symlinked_component_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            link = root / "link"
            link.symlink_to(root / "target", target_is_directory=True)
            self.assertEqual(self.main([str(link / "leaf")]), 1)

    def test_missing_source_root_is_added_to_the_search_path(self) -> None:
        original = list(sys.path)
        try:
            sys.path[:] = [entry for entry in sys.path if entry != SOURCE_ROOT]
            load()
            self.assertIn(SOURCE_ROOT, sys.path)
        finally:
            sys.path[:] = original

    def test_existing_source_root_is_not_duplicated(self) -> None:
        original = list(sys.path)
        try:
            sys.path[:] = [entry for entry in sys.path if entry != SOURCE_ROOT]
            load()
            load()
            self.assertEqual(sys.path.count(SOURCE_ROOT), 1)
        finally:
            sys.path[:] = original

    def test_main_guard_exits_with_the_usage_code(self) -> None:
        with mock.patch.object(sys, "argv", ["verify-path-boundary.py"]):
            with self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
