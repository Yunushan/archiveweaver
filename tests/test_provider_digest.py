from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from archiveweaver.provider_digest import digest_file, digest_quadlet, digest_tree


class ProviderDigestTests(unittest.TestCase):
    def test_file_and_tree_digests_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.txt").write_bytes(b"bravo\n")
            (root / "a.txt").write_bytes(b"alpha\n")
            alpha = hashlib.sha256(b"alpha\n").hexdigest()
            bravo = hashlib.sha256(b"bravo\n").hexdigest()
            expected = "sha256:" + hashlib.sha256(f"a.txt:{alpha}\nb.txt:{bravo}".encode()).hexdigest()
            self.assertEqual(digest_file(root / "a.txt"), f"sha256:{alpha}")
            self.assertEqual(digest_tree(root), expected)

    def test_quadlet_digest_matches_the_ansible_canonical_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = {
                "archiveweaver-paperless-ngx.network": b"[Network]\nNetworkName=archiveweaver-paperless-ngx\n",
                "archiveweaver-paperless-ngx.volume": b"[Volume]\nVolumeName=paperless-ngx-data\n",
                "paperless-ngx.container": b"[Container]\nImage=registry.example/paperless@sha256:abc\n",
            }
            for name, content in contents.items():
                (root / name).write_bytes(content)
            entries = [
                f"network:{hashlib.sha256(contents['archiveweaver-paperless-ngx.network']).hexdigest()}",
                f"volume:{hashlib.sha256(contents['archiveweaver-paperless-ngx.volume']).hexdigest()}",
                f"container:{hashlib.sha256(contents['paperless-ngx.container']).hexdigest()}",
            ]
            expected = "sha256:" + hashlib.sha256("\n".join(entries).encode()).hexdigest()
            self.assertEqual(digest_quadlet(root, "paperless-ngx"), expected)

    def test_provider_digest_rejects_missing_or_empty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                digest_file(root / "missing")
            with self.assertRaises(ValueError):
                digest_tree(root)

    def test_provider_digest_rejects_symlinked_directory_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            (real / "provider.yml").write_text("kind: reviewed\n", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            with self.assertRaisesRegex(ValueError, "real directory"):
                digest_tree(link)

    def test_provider_digest_rejects_nested_symlink_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            (real / "provider.yml").write_text("kind: reviewed\n", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            nested = root / "bundle"
            nested.mkdir()
            nested_link = nested / "redirected"
            nested_link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinked paths"):
                digest_tree(nested)
