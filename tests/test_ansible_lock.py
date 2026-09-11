from __future__ import annotations

import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/compile-ansible-lock.py"))
download_wheels = MODULE["download_wheels"]
direct_requirements = MODULE["direct_requirements"]
parse_hashed_lock = MODULE["parse_hashed_lock"]
requirement_groups = MODULE["requirement_groups"]
validate_target_closure = MODULE["validate_target_closure"]


class AnsibleLockTests(unittest.TestCase):
    def test_linux_target_dependency_is_explicit_and_hash_locked(self) -> None:
        source = (ROOT / "deploy/ansible/requirements.in").read_text(encoding="utf-8")
        lock = (ROOT / "deploy/ansible/requirements.txt").read_text(encoding="utf-8")
        self.assertIn("ruamel-yaml-clib==0.2.15", source)
        self.assertIn("ruamel-yaml-clib==0.2.15 \\", lock)

    def test_target_closure_accepts_only_fully_locked_dependencies(self) -> None:
        compiled = "alpha==1.0\nbeta==2.0\n"
        complete = {
            ("alpha", "1.0"): {"a" * 64},
            ("beta", "2.0"): {"b" * 64},
        }
        validate_target_closure(compiled, complete)
        incomplete = dict(complete)
        incomplete[("linux-only", "3.0")] = {"c" * 64}
        with self.assertRaisesRegex(RuntimeError, "linux-only==3.0"):
            validate_target_closure(compiled, incomplete)

    def test_target_download_resolves_dependencies(self) -> None:
        commands: list[list[str]] = []
        function_globals = download_wheels.__globals__
        original_run = function_globals["run"]
        function_globals["run"] = commands.append
        try:
            download_wheels(Path("requirements.txt"), Path("wheelhouse"), "3.13")
        finally:
            function_globals["run"] = original_run
        self.assertEqual(len(commands), 1)
        self.assertNotIn("--no-deps", commands[0])

    def test_requirement_group_parser_normalizes_distribution_names(self) -> None:
        self.assertEqual(
            requirement_groups("Example_Package==1.2.3\n"),
            [("example-package", "1.2.3")],
        )

    def test_hashed_lock_parser_rejects_ambiguous_or_active_content(self) -> None:
        digest = "a" * 64
        valid = f"Example_Package==1.2.3 \\\n    --hash=sha256:{digest}\n"
        self.assertEqual(parse_hashed_lock(valid), {"example-package": "1.2.3"})
        invalid = (
            "",
            f"    --hash=sha256:{digest}\nexample==1.0 \\\n",
            "example==1.0 \\\n",
            f"example==1.0 \\\n    --hash=sha256:{digest}\nexample==2.0 \\\n    --hash=sha256:{'b' * 64}\n",
            f"example==1.0 \\\n    --hash=sha256:{digest} \\\n    --hash=sha256:{digest}\n",
            "--extra-index-url=https://example.invalid/simple\n",
        )
        for content in invalid:
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                parse_hashed_lock(content)

    def test_direct_requirements_are_exact_nonduplicate_pins(self) -> None:
        self.assertEqual(
            direct_requirements("# tools\nExample_Package==1.2.3\n"),
            {"example-package": "1.2.3"},
        )
        for content in ("", "example>=1\n", "example==1\nExample==2\n"):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                direct_requirements(content)


if __name__ == "__main__":
    unittest.main()
