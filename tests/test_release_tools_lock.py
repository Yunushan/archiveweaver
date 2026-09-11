from __future__ import annotations

import runpy
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/compile-release-tools-lock.py"))
direct_requirements = MODULE["direct_requirements"]
parse_lock = MODULE["parse_lock"]
render_lock = MODULE["render_lock"]
wheel_identity = MODULE["wheel_identity"]


class ReleaseToolsLockTests(unittest.TestCase):
    def test_checked_in_lock_is_complete_and_conflict_free(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/compile-release-tools-lock.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("51 exact, hash-verified packages", result.stdout)
        self.assertIn("shared_with_ansible=7", result.stdout)

    def test_rendered_lock_is_deterministic_and_round_trips(self) -> None:
        packages = {
            ("z-package", "2.0"): {"b" * 64, "a" * 64},
            ("a-package", "1.0"): {"c" * 64},
        }
        rendered = render_lock(packages)
        self.assertEqual(rendered, render_lock(packages))
        self.assertLess(rendered.index("a-package==1.0"), rendered.index("z-package==2.0"))
        self.assertLess(rendered.index("a" * 64), rendered.index("b" * 64))
        self.assertEqual(
            parse_lock(rendered, "test lock"),
            {"a-package": "1.0", "z-package": "2.0"},
        )

    def test_lock_parser_rejects_unbound_or_ambiguous_content(self) -> None:
        digest = "a" * 64
        invalid = (
            "",
            f"    --hash=sha256:{digest}\nexample==1.0 \\\n",
            "example==1.0 \\\n",
            "--index-url=https://example.invalid/simple\n",
            (
                f"example==1.0 \\\n    --hash=sha256:{digest}\n"
                f"example==2.0 \\\n    --hash=sha256:{'b' * 64}\n"
            ),
            (
                f"example==1.0 \\\n    --hash=sha256:{digest} \\\n"
                f"    --hash=sha256:{digest}\n"
            ),
        )
        for content in invalid:
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                parse_lock(content, "test lock")

    def test_direct_requirements_must_be_exact_and_unique(self) -> None:
        self.assertEqual(
            direct_requirements("# tools\nExample_Pkg==1.2.3\n"),
            {"example-pkg": "1.2.3"},
        )
        for content in (
            "",
            "example>=1\n",
            "example==1\nexample==1\n",
        ):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                direct_requirements(content)

    def test_wheel_identity_uses_only_top_level_distribution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "example-1.2.3-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "example-1.2.3.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: Example_Pkg\nVersion: 1.2.3\n",
                )
                archive.writestr(
                    "example/_vendor/vendor-9.9.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: Vendor\nVersion: 9.9\n",
                )
            self.assertEqual(wheel_identity(wheel), ("example-pkg", "1.2.3"))

            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr(
                    "other-1.0.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: Other\nVersion: 1.0\n",
                )
            with self.assertRaises(RuntimeError):
                wheel_identity(wheel)


if __name__ == "__main__":
    unittest.main()
