from __future__ import annotations

import importlib.util
import runpy
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compile-ansible-lock.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("compile_ansible_lock", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


module = _load_module()
download_wheels = module.download_wheels
direct_requirements = module.direct_requirements
parse_hashed_lock = module.parse_hashed_lock
requirement_groups = module.requirement_groups
validate_target_closure = module.validate_target_closure


SCOPE = "Approved artifact scope: CPython 3.13 and 3.14 on Linux x86_64"


class AnsibleLockTests(unittest.TestCase):
    def _make_wheel(self, path: Path, name: str = "Example_Package", version: str = "1.2.3") -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                "example_package-1.2.3.dist-info/METADATA",
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            )

    def _fake_lock(self, content: str) -> mock.MagicMock:
        lock = mock.MagicMock()
        lock.read_bytes.return_value = content.encode("utf-8")
        lock.read_text.return_value = content
        return lock

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

    def test_canonical_name_normalizes_separators(self) -> None:
        self.assertEqual(module.canonical_name("Example_Package.Name-suffix"), "example-package-name-suffix")

    def test_run_invokes_subprocess_in_repo_root(self) -> None:
        with mock.patch.object(module.subprocess, "run") as run_mock:
            module.run(["pip", "download"])
        run_mock.assert_called_once_with(["pip", "download"], cwd=module.ROOT, check=True)

    def test_compile_versions_builds_piptools_command(self) -> None:
        destination = Path("out.txt")
        with mock.patch.object(module, "run") as run_mock:
            module.compile_versions(destination)
        command = run_mock.call_args.args[0]
        self.assertIn("piptools", command)
        self.assertIn("compile", command)
        self.assertIn("--strip-extras", command)
        self.assertIn(f"--output-file={destination}", command)
        self.assertEqual(command[-1], str(module.REQUIREMENTS_IN))

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

    def test_wheel_identity_reads_name_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / "pkg.whl"
            self._make_wheel(wheel, name="Example_Package", version="1.2.3")
            self.assertEqual(module.wheel_identity(wheel), ("example-package", "1.2.3"))

    def test_wheel_identity_rejects_ambiguous_or_missing_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ambiguous = root / "ambiguous.whl"
            with zipfile.ZipFile(ambiguous, "w") as archive:
                archive.writestr("a-1.dist-info/METADATA", "Name: a\nVersion: 1\n")
                archive.writestr("b-1.dist-info/METADATA", "Name: b\nVersion: 1\n")
            with self.assertRaisesRegex(RuntimeError, "ambiguous METADATA record"):
                module.wheel_identity(ambiguous)

            missing_name = root / "missing_name.whl"
            with zipfile.ZipFile(missing_name, "w") as archive:
                archive.writestr("pkg-1.dist-info/METADATA", "Version: 1\n")
            with self.assertRaisesRegex(RuntimeError, "missing Name or Version"):
                module.wheel_identity(missing_name)

            missing_version = root / "missing_version.whl"
            with zipfile.ZipFile(missing_version, "w") as archive:
                archive.writestr("pkg-1.dist-info/METADATA", "Name: pkg\n")
            with self.assertRaisesRegex(RuntimeError, "missing Name or Version"):
                module.wheel_identity(missing_version)

    def test_collect_hashes_aggregates_wheelhouses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse_313 = root / "cp313"
            wheelhouse_314 = root / "cp314"
            wheelhouse_313.mkdir()
            wheelhouse_314.mkdir()
            self._make_wheel(wheelhouse_313 / "pkg.whl", name="Pkg", version="1.0")
            self._make_wheel(wheelhouse_314 / "pkg.whl", name="Pkg", version="1.0")
            hashes, availability = module.collect_hashes(
                {"3.13": wheelhouse_313, "3.14": wheelhouse_314}
            )
        self.assertEqual(set(hashes), {("pkg", "1.0")})
        self.assertEqual(len(hashes[("pkg", "1.0")]), 1)
        self.assertEqual(availability[("pkg", "1.0")], {"3.13", "3.14"})

    def test_collect_hashes_rejects_empty_wheelhouse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary) / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(RuntimeError, "no wheels downloaded for Python 3.13"):
                module.collect_hashes({"3.13": empty})

    def test_requirement_group_parser_normalizes_distribution_names(self) -> None:
        self.assertEqual(
            requirement_groups("Example_Package==1.2.3\n"),
            [("example-package", "1.2.3")],
        )

    def test_requirement_group_parser_skips_non_requirement_lines(self) -> None:
        self.assertEqual(
            requirement_groups("# comment\n\nalpha==1.0\n"),
            [("alpha", "1.0")],
        )

    def test_requirement_group_parser_rejects_empty_content(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no exact requirements"):
            requirement_groups("# only comments\n")

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

    def test_hashed_lock_parser_allows_comments_and_blank_lines(self) -> None:
        digest = "a" * 64
        content = f"# header\n\nExample==1.0 \\\n    --hash=sha256:{digest}\n"
        self.assertEqual(parse_hashed_lock(content), {"example": "1.0"})

    def test_render_hashed_lock_emits_sorted_hashes(self) -> None:
        identity = ("alpha", "1.0")
        hashes = {identity: {"b" * 64, "a" * 64}}
        availability = {identity: set(module.PYTHON_VERSIONS)}
        unhashed = "alpha==1.0 \\\n# see " + module.REQUIREMENTS_IN.as_posix() + "\n"
        rendered = module.render_hashed_lock(unhashed, hashes, availability)
        self.assertIn("alpha==1.0 \\", rendered)
        self.assertIn("deploy/ansible/requirements.in", rendered)
        self.assertLess(rendered.index("a" * 64), rendered.index("b" * 64))
        self.assertIn("    --hash=sha256:" + "b" * 64 + "\n", rendered)
        self.assertNotIn("    --hash=sha256:" + "b" * 64 + " \\", rendered)

    def test_render_hashed_lock_rejects_missing_requirements(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no exact requirements"):
            module.render_hashed_lock("# only comments\n", {}, {})

    def test_render_hashed_lock_rejects_unsupported_syntax(self) -> None:
        identity = ("alpha", "1.0")
        hashes = {identity: {"a" * 64}}
        availability = {identity: set(module.PYTHON_VERSIONS)}
        unhashed = "alpha==1.0 \\\n--extra-index-url=https://example.invalid/simple\n"
        with self.assertRaisesRegex(RuntimeError, "unsupported active syntax"):
            module.render_hashed_lock(unhashed, hashes, availability)

    def test_render_hashed_lock_rejects_incomplete_availability(self) -> None:
        identity = ("alpha", "1.0")
        hashes = {identity: {"a" * 64}}
        availability = {identity: {"3.13"}}
        with self.assertRaisesRegex(RuntimeError, "lacks approved wheels for: 3.14"):
            module.render_hashed_lock("alpha==1.0 \\\n", hashes, availability)

    def test_render_hashed_lock_rejects_missing_artifact_hash(self) -> None:
        identity = ("alpha", "1.0")
        availability = {identity: set(module.PYTHON_VERSIONS)}
        with self.assertRaisesRegex(RuntimeError, "no artifact hash collected"):
            module.render_hashed_lock("alpha==1.0 \\\n", {}, availability)

    def test_atomic_write_creates_and_replaces_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "nested" / "requirements.txt"
            module.atomic_write(target, "first\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "first\n")
            module.atomic_write(target, "second\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "second\n")
            self.assertEqual(list(target.parent.glob("*.tmp")), [])

    def test_atomic_write_refuses_symlinked_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary) / "real.txt"
            real.write_text("original\n", encoding="utf-8")
            link = Path(temporary) / "link.txt"
            link.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "refusing to replace symlinked lock"):
                module.atomic_write(link, "new\n")

    def test_atomic_write_propagates_creation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "requirements.txt"
            with mock.patch.object(
                module.tempfile, "NamedTemporaryFile", side_effect=OSError("boom")
            ), self.assertRaises(OSError):
                module.atomic_write(target, "content\n")

    def test_atomic_write_tolerates_missing_temporary_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "requirements.txt"
            temporary_file = mock.MagicMock()
            temporary_file.__enter__.return_value = temporary_file
            temporary_file.name = None
            with mock.patch.object(
                module.tempfile, "NamedTemporaryFile", return_value=temporary_file
            ), mock.patch.object(module, "Path") as path_mock:
                module.atomic_write(target, "content\n")
            path_mock.assert_called_once_with(None)

    def test_direct_requirements_are_exact_nonduplicate_pins(self) -> None:
        self.assertEqual(
            direct_requirements("# tools\nExample_Package==1.2.3\n"),
            {"example-package": "1.2.3"},
        )
        for content in ("", "example>=1\n", "example==1\nExample==2\n"):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                direct_requirements(content)

    def test_direct_requirements_defaults_to_requirements_file(self) -> None:
        pins = direct_requirements()
        self.assertTrue(pins)
        self.assertTrue(all(isinstance(name, str) for name in pins))

    def test_check_lock_accepts_matching_locks(self) -> None:
        content = SCOPE + "\n"
        with mock.patch.object(module, "LOCK", self._fake_lock(content)), \
                mock.patch.object(module, "EE_LOCK", self._fake_lock(content)), \
                mock.patch.object(module, "parse_hashed_lock", return_value={"alpha": "1.0"}), \
                mock.patch.object(module, "direct_requirements", return_value={"alpha": "1.0"}):
            module.check_lock()

    def test_check_lock_rejects_differing_locks(self) -> None:
        with mock.patch.object(module, "LOCK", self._fake_lock(SCOPE + "\n")), \
                mock.patch.object(module, "EE_LOCK", self._fake_lock("different\n")):
            with self.assertRaisesRegex(RuntimeError, "locks differ"):
                module.check_lock()

    def test_check_lock_rejects_missing_scope(self) -> None:
        content = "alpha==1.0\n"
        with mock.patch.object(module, "LOCK", self._fake_lock(content)), \
                mock.patch.object(module, "EE_LOCK", self._fake_lock(content)):
            with self.assertRaisesRegex(RuntimeError, "does not declare its approved artifact scope"):
                module.check_lock()

    def test_check_lock_rejects_machine_specific_path(self) -> None:
        content = f"{SCOPE}\n{module.ROOT}\n"
        with mock.patch.object(module, "LOCK", self._fake_lock(content)), \
                mock.patch.object(module, "EE_LOCK", self._fake_lock(content)):
            with self.assertRaisesRegex(RuntimeError, "machine-specific repository path"):
                module.check_lock()

    def test_check_lock_rejects_direct_pin_mismatch(self) -> None:
        content = SCOPE + "\n"
        with mock.patch.object(module, "LOCK", self._fake_lock(content)), \
                mock.patch.object(module, "EE_LOCK", self._fake_lock(content)), \
                mock.patch.object(module, "parse_hashed_lock", return_value={"alpha": "1.0"}), \
                mock.patch.object(module, "direct_requirements", return_value={"alpha": "2.0"}):
            with self.assertRaisesRegex(RuntimeError, "direct pin is missing from lock"):
                module.check_lock()

    def test_generate_lock_writes_both_locks(self) -> None:
        writes: list[tuple[Path, str]] = []

        def fake_compile(destination: Path) -> None:
            destination.write_text("alpha==1.0\n", encoding="utf-8")

        with mock.patch.object(module, "compile_versions", side_effect=fake_compile), \
                mock.patch.object(module, "download_wheels"), \
                mock.patch.object(module, "collect_hashes", return_value=({}, {})), \
                mock.patch.object(module, "render_hashed_lock", return_value="RENDERED"), \
                mock.patch.object(
                    module, "atomic_write", side_effect=lambda path, content: writes.append((path, content))
                ), \
                mock.patch.object(module, "check_lock") as check_mock:
            module.generate_lock()
        self.assertEqual(writes, [(module.LOCK, "RENDERED"), (module.EE_LOCK, "RENDERED")])
        check_mock.assert_called_once_with()

    def test_main_dispatches_check(self) -> None:
        with mock.patch.object(sys, "argv", ["prog", "--check"]), \
                mock.patch.object(module, "check_lock") as check_mock, \
                mock.patch.object(module, "generate_lock") as generate_mock:
            self.assertEqual(module.main(), 0)
        check_mock.assert_called_once_with()
        generate_mock.assert_not_called()

    def test_main_dispatches_generate(self) -> None:
        with mock.patch.object(sys, "argv", ["prog"]), \
                mock.patch.object(module, "check_lock") as check_mock, \
                mock.patch.object(module, "generate_lock") as generate_mock:
            self.assertEqual(module.main(), 0)
        generate_mock.assert_called_once_with()
        check_mock.assert_not_called()

    def test_main_guard_runs_check(self) -> None:
        with mock.patch.object(sys, "argv", [str(SCRIPT), "--check"]):
            with self.assertRaises(SystemExit) as context:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(context.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
