from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compile-release-tools-lock.py"

_spec = importlib.util.spec_from_file_location("compile_release_tools_lock", SCRIPT)
MODULE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MODULE)


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _make_wheel(directory: Path, filename: str, name: str, version: str) -> Path:
    path = directory / filename
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n",
        )
    return path


def _lock_text(
    packages: list[tuple[str, str]], *, scope: bool = True, extra: str | None = None
) -> str:
    lines: list[str] = []
    if scope:
        lines.append(
            "# Approved artifact scope: CPython 3.14 on Linux x86_64, binary wheels only."
        )
    if extra is not None:
        lines.append(extra)
    digests = ["a" * 64, "b" * 64, "c" * 64]
    for index, (name, version) in enumerate(packages):
        lines.append(f"{name}=={version} \\")
        lines.append(f"    --hash=sha256:{digests[index % len(digests)]}")
    return "\n".join(lines) + "\n"


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
        self.assertRegex(result.stdout, r"\d+ exact, hash-verified packages")
        self.assertIn("shared_with_ansible=7", result.stdout)

    def test_rendered_lock_is_deterministic_and_round_trips(self) -> None:
        packages = {
            ("z-package", "2.0"): {"b" * 64, "a" * 64},
            ("a-package", "1.0"): {"c" * 64},
        }
        rendered = MODULE.render_lock(packages)
        self.assertEqual(rendered, MODULE.render_lock(packages))
        self.assertLess(rendered.index("a-package==1.0"), rendered.index("z-package==2.0"))
        self.assertLess(rendered.index("a" * 64), rendered.index("b" * 64))
        self.assertEqual(
            MODULE.parse_lock(rendered, "test lock"),
            {"a-package": "1.0", "z-package": "2.0"},
        )

    def test_render_lock_rejects_package_without_hashes(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no artifact hash"):
            MODULE.render_lock({("foo", "1.0"): set()})

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
                MODULE.parse_lock(content, "test lock")

    def test_lock_parser_accepts_extras_and_canonicalizes_package_name(self) -> None:
        digest = "a" * 64
        self.assertEqual(
            MODULE.parse_lock(
                (
                    "CacheControl[filecache]==0.14.4 \\\n"
                    f"    --hash=sha256:{digest}\n"
                ),
                "test lock",
            ),
            {"cachecontrol": "0.14.4"},
        )

    def test_direct_requirements_must_be_exact_and_unique(self) -> None:
        self.assertEqual(
            MODULE.direct_requirements("# tools\n\nExample_Pkg==1.2.3\n"),
            {"example-pkg": "1.2.3"},
        )
        for content in (
            "",
            "example>=1\n",
            "example==1\nexample==1\n",
        ):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                MODULE.direct_requirements(content)

    def test_run_invokes_subprocess_in_repo_root(self) -> None:
        with mock.patch.object(MODULE.subprocess, "run") as run_mock:
            MODULE.run(["echo", "hi"])
        run_mock.assert_called_once_with(["echo", "hi"], cwd=MODULE.ROOT, check=True)

    def test_read_regular_rejects_unsafe_paths_and_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            good = _write(base / "good.txt", "content\n")
            self.assertEqual(MODULE.read_regular(good, "label"), "content\n")
            with self.assertRaisesRegex(RuntimeError, "regular non-symlinked"):
                MODULE.read_regular(base, "label")
            with self.assertRaisesRegex(RuntimeError, "regular non-symlinked"):
                MODULE.read_regular(base / "missing.txt", "label")
            link = base / "link.txt"
            os.symlink(good, link)
            with self.assertRaisesRegex(RuntimeError, "regular non-symlinked"):
                MODULE.read_regular(link, "label")
            bad = base / "bad.txt"
            bad.write_bytes(b"\xff\xfe\x00")
            with self.assertRaisesRegex(RuntimeError, "valid UTF-8"):
                MODULE.read_regular(bad, "label")

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
            self.assertEqual(MODULE.wheel_identity(wheel), ("example-pkg", "1.2.3"))

            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr(
                    "other-1.0.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: Other\nVersion: 1.0\n",
                )
            with self.assertRaises(RuntimeError):
                MODULE.wheel_identity(wheel)

    def test_wheel_identity_rejects_missing_metadata_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "bad-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "bad-1.0.dist-info/METADATA",
                    "Metadata-Version: 2.4\nName: Bad\n",
                )
            with self.assertRaisesRegex(RuntimeError, "missing Name or Version"):
                MODULE.wheel_identity(wheel)

    def test_download_wheels_builds_binary_only_command(self) -> None:
        with mock.patch.object(MODULE, "run") as run_mock:
            with tempfile.TemporaryDirectory() as directory:
                MODULE.download_wheels(Path(directory))
        command = run_mock.call_args.args[0]
        self.assertIn("download", command)
        self.assertIn("--only-binary=:all:", command)
        self.assertIn("--abi=cp314", command)
        for platform in MODULE.LINUX_X86_64_PLATFORMS:
            self.assertIn(f"--platform={platform}", command)
        self.assertEqual(command[-2:], ["-r", str(MODULE.REQUIREMENTS_IN)])

    def test_collect_wheels_hashes_wheels_and_rejects_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            _make_wheel(base, "foo-1.0-py3-none-any.whl", "foo", "1.0")
            _make_wheel(base, "bar-2.0-py3-none-any.whl", "bar", "2.0")
            packages = MODULE.collect_wheels(base)
            self.assertEqual(set(packages), {("foo", "1.0"), ("bar", "2.0")})
            self.assertEqual(len(packages[("foo", "1.0")]), 1)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "downloaded no wheels"):
                MODULE.collect_wheels(Path(directory))

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            _make_wheel(base, "foo-1.0-py3-none-any.whl", "foo", "1.0")
            _make_wheel(base, "foo-2.0-py3-none-any.whl", "foo", "2.0")
            with self.assertRaisesRegex(RuntimeError, "multiple versions"):
                MODULE.collect_wheels(base)

    def test_atomic_write_replaces_file_and_rejects_unsafe_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "nested" / "lock.txt"
            MODULE.atomic_write(target, "hello\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "hello\n")

            unsafe = base / "adir"
            unsafe.mkdir()
            with self.assertRaisesRegex(RuntimeError, "unsafe release tools lock"):
                MODULE.atomic_write(unsafe, "x")

            with mock.patch.object(
                MODULE.tempfile, "NamedTemporaryFile", side_effect=OSError("boom")
            ), self.assertRaises(OSError):
                MODULE.atomic_write(base / "other.txt", "x")

            class _AnonymousTemporary:
                name: str | None = None

                def __enter__(self) -> _AnonymousTemporary:
                    return self

                def __exit__(self, *args: object) -> bool:
                    return False

                def write(self, content: str) -> None:
                    return None

            with (
                mock.patch.object(
                    MODULE.tempfile,
                    "NamedTemporaryFile",
                    return_value=_AnonymousTemporary(),
                ),
                mock.patch.object(MODULE, "Path", return_value=mock.MagicMock()),
            ):
                MODULE.atomic_write(base / "unused.txt", "x")

    def test_check_lock_validates_repository_locks(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as out:
            MODULE.check_lock()
        self.assertIn("hash-verified packages", out.getvalue())

    def test_check_lock_rejects_missing_scope_and_machine_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            req = _write(base / "req.in", "foo==1.0\n")
            ansible = _write(base / "ansible.txt", _lock_text([("bar", "9.9")]))
            cases = (
                (_lock_text([("foo", "1.0")], scope=False), "artifact scope"),
                (
                    _lock_text([("foo", "1.0")], extra=f"# {MODULE.ROOT}"),
                    "machine-specific",
                ),
            )
            for lock, message in cases:
                lock_path = _write(base / "lock.txt", lock)
                with (
                    self.subTest(message=message),
                    mock.patch.object(MODULE, "REQUIREMENTS_IN", req),
                    mock.patch.object(MODULE, "LOCK", lock_path),
                    mock.patch.object(MODULE, "ANSIBLE_LOCK", ansible),
                    self.assertRaisesRegex(RuntimeError, message),
                ):
                    MODULE.check_lock()

    def test_check_lock_rejects_missing_direct_pin_and_ansible_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            req = _write(base / "req.in", "foo==1.0\n")

            lock_path = _write(base / "lock.txt", _lock_text([("other", "1.0")]))
            ansible = _write(base / "ansible.txt", _lock_text([("bar", "9.9")]))
            with (
                mock.patch.object(MODULE, "REQUIREMENTS_IN", req),
                mock.patch.object(MODULE, "LOCK", lock_path),
                mock.patch.object(MODULE, "ANSIBLE_LOCK", ansible),
                self.assertRaisesRegex(RuntimeError, "direct release tool pin is missing"),
            ):
                MODULE.check_lock()

            lock_path = _write(
                base / "lock.txt", _lock_text([("foo", "1.0"), ("bar", "2.0")])
            )
            ansible = _write(base / "ansible.txt", _lock_text([("bar", "3.0")]))
            with (
                mock.patch.object(MODULE, "REQUIREMENTS_IN", req),
                mock.patch.object(MODULE, "LOCK", lock_path),
                mock.patch.object(MODULE, "ANSIBLE_LOCK", ansible),
                self.assertRaisesRegex(RuntimeError, "conflicting shared packages"),
            ):
                MODULE.check_lock()

    def test_generate_lock_writes_and_validates_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            req = _write(base / "req.in", "foo==1.0\n")
            lock_path = base / "lock.txt"
            ansible = _write(base / "ansible.txt", _lock_text([("bar", "9.9")]))
            with (
                mock.patch.object(MODULE, "REQUIREMENTS_IN", req),
                mock.patch.object(MODULE, "LOCK", lock_path),
                mock.patch.object(MODULE, "ANSIBLE_LOCK", ansible),
                mock.patch.object(MODULE, "download_wheels") as download_mock,
                mock.patch.object(
                    MODULE,
                    "collect_wheels",
                    return_value={("foo", "1.0"): {"a" * 64}},
                ),
            ):
                MODULE.generate_lock()
            download_mock.assert_called_once()
            self.assertIn("foo==1.0", lock_path.read_text(encoding="utf-8"))

    def test_generate_lock_rejects_omitted_direct_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            req = _write(base / "req.in", "foo==1.0\n")
            with (
                mock.patch.object(MODULE, "REQUIREMENTS_IN", req),
                mock.patch.object(MODULE, "LOCK", base / "lock.txt"),
                mock.patch.object(MODULE, "download_wheels"),
                mock.patch.object(
                    MODULE,
                    "collect_wheels",
                    return_value={("bar", "1.0"): {"a" * 64}},
                ),
                self.assertRaisesRegex(RuntimeError, "resolver omitted direct"),
            ):
                MODULE.generate_lock()

    def test_main_dispatches_and_reports_errors(self) -> None:
        with (
            mock.patch.object(MODULE, "check_lock") as check_mock,
            mock.patch.object(sys, "argv", ["prog", "--check"]),
        ):
            self.assertEqual(MODULE.main(), 0)
        check_mock.assert_called_once_with()

        with (
            mock.patch.object(MODULE, "generate_lock") as generate_mock,
            mock.patch.object(sys, "argv", ["prog"]),
        ):
            self.assertEqual(MODULE.main(), 0)
        generate_mock.assert_called_once_with()

        with (
            mock.patch.object(MODULE, "check_lock", side_effect=RuntimeError("boom")),
            mock.patch.object(sys, "argv", ["prog", "--check"]),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(MODULE.main(), 1)
        self.assertIn("boom", err.getvalue())

    def test_module_guard_runs_main(self) -> None:
        with (
            mock.patch.object(sys, "argv", ["compile-release-tools-lock.py", "--check"]),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as context,
        ):
            runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(context.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
