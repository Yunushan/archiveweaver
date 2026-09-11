from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from archiveweaver.path_utils import has_symlink_component


class PathBoundaryTests(unittest.TestCase):
    def test_fails_closed_when_a_component_cannot_be_inspected(self) -> None:
        with patch(
            "archiveweaver.path_utils.os.lstat", side_effect=OSError("access denied")
        ):
            self.assertTrue(has_symlink_component(Path("uninspectable/provider.yml")))

    def test_detects_windows_reparse_points_without_following_them(self) -> None:
        with (
            patch(
                "archiveweaver.path_utils.os.lstat",
                return_value=SimpleNamespace(st_mode=0, st_file_attributes=0x400),
            ),
        ):
            self.assertTrue(has_symlink_component(Path("junction/provider.yml")))

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
