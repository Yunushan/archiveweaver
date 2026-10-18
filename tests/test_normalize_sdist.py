from __future__ import annotations

import contextlib
import gzip
import io
import os
import runpy
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE = runpy.run_path("scripts/normalize-sdist.py")
check_sdist = MODULE["check_sdist"]
normalize_sdist = MODULE["normalize_sdist"]
validated_epoch = MODULE["_validated_epoch"]
read_members = MODULE["_read_members"]

EPOCH = 1_700_000_000


def build(path: Path, specs: list[dict], *, compresslevel: int = 9, filename: str = "", gz_mtime: int = EPOCH) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename=filename,
            mode="wb",
            compresslevel=compresslevel,
            fileobj=raw,
            mtime=gz_mtime,
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for spec in specs:
                    name = spec["name"]
                    member = tarfile.TarInfo(name)
                    member.mtime = spec.get("mtime", gz_mtime)
                    member.uid = spec.get("uid", 0)
                    member.gid = spec.get("gid", 0)
                    member.uname = spec.get("uname", "")
                    member.gname = spec.get("gname", "")
                    if spec.get("directory"):
                        member.type = tarfile.DIRTYPE
                        archive.addfile(member)
                        continue
                    payload = name.encode("utf-8")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))


def legacy_build(path: Path, names: tuple[str, ...]) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="host-specific.tar", mode="wb", fileobj=raw) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name in names:
                    payload = name.encode("utf-8")
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    member.mtime = 123
                    member.uid = 1000
                    member.gid = 1000
                    member.uname = "builder"
                    member.gname = "builder"
                    archive.addfile(member, io.BytesIO(payload))


class FakeMember:
    def __init__(self, name: str, size: int, payload) -> None:
        self.name = name
        self.size = size
        self._payload = payload
        self.mtime = 0
        self.uid = 0
        self.gid = 0
        self.uname = ""
        self.gname = ""

    def isdir(self) -> bool:
        return False

    def isfile(self) -> bool:
        return True


class FakeArchive:
    def __init__(self, members: list[FakeMember]) -> None:
        self._members = members

    def __enter__(self) -> "FakeArchive":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False

    def getmembers(self) -> list[FakeMember]:
        return self._members

    def extractfile(self, member: FakeMember):
        return member._payload


class FakeTarfile:
    def __init__(self, members: list[FakeMember]) -> None:
        self._members = members

    def open(self, path, mode) -> FakeArchive:
        return FakeArchive(self._members)


class NormalizeSdistTests(unittest.TestCase):
    def test_normalization_is_byte_stable_and_metadata_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            legacy_build(path, ("example/z.txt", "example/a.txt"))

            first_digest = normalize_sdist(path, EPOCH)
            first_bytes = path.read_bytes()
            second_digest = normalize_sdist(path, EPOCH)

            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_bytes, path.read_bytes())
            self.assertEqual(check_sdist(path, EPOCH), [])

    def test_normalization_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.tar.gz"
            legacy_build(path, ("../outside.txt",))
            with self.assertRaisesRegex(ValueError, "unsafe or duplicate"):
                normalize_sdist(path, EPOCH)

    def test_unsupported_member_types_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "link.tar.gz"
            with path.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as archive:
                        member = tarfile.TarInfo("example/link")
                        member.type = tarfile.SYMTYPE
                        member.linkname = "target"
                        archive.addfile(member)
            with self.assertRaisesRegex(ValueError, "unsupported sdist member type"):
                normalize_sdist(path, EPOCH)

    def test_directory_members_are_normalized_without_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            build(path, [{"name": "example", "directory": True}, {"name": "example/a.txt"}])
            digest = normalize_sdist(path, EPOCH)
            self.assertEqual(check_sdist(path, EPOCH), [])
            self.assertEqual(len(digest), 64)
            with tarfile.open(path, mode="r:gz") as archive:
                self.assertEqual(
                    [member.name for member in archive.getmembers()],
                    ["example", "example/a.txt"],
                )


class EpochValidationTests(unittest.TestCase):
    def test_epoch_must_be_an_integer(self) -> None:
        with self.assertRaisesRegex(ValueError, "integer Unix timestamp"):
            validated_epoch("not-a-number")

    def test_epoch_must_be_within_the_gzip_range(self) -> None:
        for value in ("-1", str((1 << 32))):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "build epoch must be between"):
                    validated_epoch(value)

    def test_epoch_accepts_the_bounds(self) -> None:
        self.assertEqual(validated_epoch("0"), 0)
        self.assertEqual(validated_epoch(str((1 << 32) - 1)), (1 << 32) - 1)


class ReadMembersTests(unittest.TestCase):
    def _read(self, members: list[FakeMember]) -> list[tuple[FakeMember, bytes | None]]:
        with mock.patch.dict(read_members.__globals__, {"tarfile": FakeTarfile(members)}):
            return read_members(Path("ignored.tar.gz"))

    def test_missing_payload_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "could not read regular sdist member"):
            self._read([FakeMember("example/a.txt", 1, None)])

    def test_short_read_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "short read for sdist member"):
            self._read([FakeMember("example/a.txt", 5, io.BytesIO(b"ab"))])

    def test_multiple_roots_are_rejected(self) -> None:
        members = [FakeMember("one/a.txt", 1, io.BytesIO(b"a")), FakeMember("two/b.txt", 1, io.BytesIO(b"b"))]
        with self.assertRaisesRegex(ValueError, "one non-empty top-level directory"):
            self._read(members)

    def test_empty_archive_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "one non-empty top-level directory"):
            self._read([])

    def test_valid_members_are_returned_in_archive_order(self) -> None:
        entries = self._read([FakeMember("example/b.txt", 1, io.BytesIO(b"b")), FakeMember("example/a.txt", 1, io.BytesIO(b"a"))])
        self.assertEqual([member.name for member, _ in entries], ["example/b.txt", "example/a.txt"])


class NormalizeRejectionTests(unittest.TestCase):
    def test_non_file_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "example.tar.gz"
            legacy_build(target, ("example/a.txt",))
            link = root / "linked.tar.gz"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular, non-symlink file"):
                normalize_sdist(root, EPOCH)
            with self.assertRaisesRegex(ValueError, "regular, non-symlink file"):
                normalize_sdist(link, EPOCH)

    def test_out_of_range_epoch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            legacy_build(path, ("example/a.txt",))
            with self.assertRaisesRegex(ValueError, "build epoch must be between"):
                normalize_sdist(path, -1)

    def test_failed_replace_removes_the_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "example.tar.gz"
            legacy_build(path, ("example/a.txt",))
            with mock.patch("os.replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    normalize_sdist(path, EPOCH)
            self.assertEqual([entry.name for entry in root.iterdir()], ["example.tar.gz"])


class CheckSdistTests(unittest.TestCase):
    def test_non_file_input_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = check_sdist(Path(directory), EPOCH)
        self.assertEqual(len(errors), 1)
        self.assertIn("regular, non-symlink file", errors[0])

    def test_non_gzip_input_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            path.write_bytes(b"not a gzip stream at all")
            errors = check_sdist(path, EPOCH)
        self.assertEqual(len(errors), 1)
        self.assertIn("not a gzip stream", errors[0])

    def test_host_specific_headers_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            legacy_build(path, ("example/a.txt",))
            errors = check_sdist(path, 100)
        self.assertTrue(any("optional fields" in error for error in errors))
        self.assertTrue(any("timestamp does not match the build epoch" in error for error in errors))
        self.assertTrue(any("host-specific ownership metadata" in error for error in errors))

    def test_unsorted_members_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            build(path, [{"name": "example/b.txt"}, {"name": "example/a.txt"}])
            errors = check_sdist(path, EPOCH)
        self.assertEqual(errors, ["sdist members are not in canonical name order"])

    def test_member_timestamp_mismatch_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            build(path, [{"name": "example/a.txt", "mtime": EPOCH - 5}])
            errors = check_sdist(path, EPOCH)
        self.assertEqual(errors, ["'example/a.txt' timestamp does not match the build epoch"])

    def test_non_relaxed_compression_level_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            build(path, [{"name": "example/a.txt"}], compresslevel=1)
            errors = check_sdist(path, EPOCH)
        self.assertTrue(any("maximum compression metadata" in error for error in errors))

    def test_unreadable_archive_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            build(path, [{"name": "example/a.txt"}])
            with mock.patch.dict(check_sdist.__globals__, {"_read_members": mock.Mock(side_effect=tarfile.TarError("broken"))}):
                errors = check_sdist(path, EPOCH)
        self.assertEqual(errors, ["broken"])

    def test_canonical_archive_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            build(path, [{"name": "example/a.txt"}, {"name": "example/b.txt"}])
            self.assertEqual(check_sdist(path, EPOCH), [])


class NormalizeSdistMainTests(unittest.TestCase):
    def _archive(self, directory: str) -> Path:
        path = Path(directory) / "example.tar.gz"
        build(path, [{"name": "example/a.txt"}])
        return path

    def test_main_normalizes_and_reports_the_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(directory)
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["normalize-sdist.py", str(path), "--epoch", str(EPOCH)]):
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(MODULE["main"](), 0)
            self.assertIn("normalized sdist sha256:", stdout.getvalue())

    def test_main_checks_a_normalized_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(directory)
            normalize_sdist(path, EPOCH)
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["normalize-sdist.py", str(path), "--epoch", str(EPOCH), "--check"]):
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(MODULE["main"](), 0)
            self.assertIn("normalized sdist sha256:", stdout.getvalue())

    def test_main_reports_check_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            legacy_build(path, ("example/a.txt",))
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["normalize-sdist.py", str(path), "--epoch", str(EPOCH), "--check"]):
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(MODULE["main"](), 1)
            self.assertIn("sdist normalization error:", stdout.getvalue())

    def test_main_reports_invalid_epochs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(directory)
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["normalize-sdist.py", str(path), "--epoch", "nope"]):
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(MODULE["main"](), 2)
            self.assertIn("sdist normalization failed:", stdout.getvalue())

    def test_main_defaults_to_the_source_date_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(directory)
            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": str(EPOCH)}):
                with mock.patch.object(sys, "argv", ["normalize-sdist.py", str(path)]):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(MODULE["main"](), 0)
            self.assertEqual(check_sdist(path, EPOCH), [])

    def test_main_guard_exits_with_the_normalization_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(directory)
            with mock.patch.object(sys, "argv", ["normalize-sdist.py", str(path), "--epoch", str(EPOCH)]):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        runpy.run_path("scripts/normalize-sdist.py", run_name="__main__")
            self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
