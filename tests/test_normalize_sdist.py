from __future__ import annotations

import gzip
import io
import runpy
import tarfile
import tempfile
import unittest
from pathlib import Path


MODULE = runpy.run_path("scripts/normalize-sdist.py")
check_sdist = MODULE["check_sdist"]
normalize_sdist = MODULE["normalize_sdist"]


class NormalizeSdistTests(unittest.TestCase):
    def _write_archive(self, path: Path, names: tuple[str, ...]) -> None:
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

    def test_normalization_is_byte_stable_and_metadata_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.tar.gz"
            self._write_archive(path, ("example/z.txt", "example/a.txt"))

            first_digest = normalize_sdist(path, 1_700_000_000)
            first_bytes = path.read_bytes()
            second_digest = normalize_sdist(path, 1_700_000_000)

            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_bytes, path.read_bytes())
            self.assertEqual(check_sdist(path, 1_700_000_000), [])

    def test_normalization_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.tar.gz"
            self._write_archive(path, ("../outside.txt",))
            with self.assertRaisesRegex(ValueError, "unsafe or duplicate"):
                normalize_sdist(path, 1_700_000_000)
