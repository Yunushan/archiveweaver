from __future__ import annotations

import hashlib
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = runpy.run_path("scripts/install-local-artifact.py")
install_artifact = MODULE["install_artifact"]


class InstallLocalArtifactTests(unittest.TestCase):
    def _install_and_capture(self, path: Path) -> tuple[int, list[str], str]:
        captured_command: list[str] = []
        captured_requirement = ""

        def fake_run(command: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
            nonlocal captured_command, captured_requirement
            captured_command = command
            self.assertFalse(check)
            requirement_path = Path(command[-1])
            captured_requirement = requirement_path.read_text(encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(MODULE["subprocess"], "run", side_effect=fake_run):
            result = install_artifact(path)
        return result, captured_command, captured_requirement

    def test_wheel_is_installed_offline_through_a_hash_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "archiveweaver-0.1.0-py3-none-any.whl"
            artifact.write_bytes(b"validated wheel")

            result, command, requirement = self._install_and_capture(artifact)

        digest = hashlib.sha256(b"validated wheel").hexdigest()
        self.assertEqual(result, 0)
        self.assertIn("--no-index", command)
        self.assertIn("--require-hashes", command)
        self.assertNotIn("--no-build-isolation", command)
        self.assertEqual(
            requirement,
            f"{artifact.resolve().as_uri()} --hash=sha256:{digest}\n",
        )

    def test_sdist_uses_the_preinstalled_locked_build_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "archiveweaver-0.1.0.tar.gz"
            artifact.write_bytes(b"validated sdist")

            result, command, _ = self._install_and_capture(artifact)

        self.assertEqual(result, 0)
        self.assertIn("--no-build-isolation", command)

    def test_unsupported_or_missing_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsupported = root / "archiveweaver.zip"
            unsupported.write_bytes(b"not a distribution")
            with self.assertRaisesRegex(ValueError, "wheel or .tar.gz"):
                install_artifact(unsupported)
            with self.assertRaisesRegex(ValueError, "regular, non-symlink"):
                install_artifact(root / "missing.whl")

    def test_pip_failure_is_propagated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "archiveweaver-0.1.0-py3-none-any.whl"
            artifact.write_bytes(b"wheel")
            completed = subprocess.CompletedProcess([], 19)
            with patch.object(MODULE["subprocess"], "run", return_value=completed):
                self.assertEqual(install_artifact(artifact), 19)
