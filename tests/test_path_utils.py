from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from archiveweaver.path_utils import has_symlink_component


class PathBoundaryTests(unittest.TestCase):
    def test_detects_symlink_before_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            unresolved = link / ".." / "target"
            self.assertTrue(has_symlink_component(unresolved))

