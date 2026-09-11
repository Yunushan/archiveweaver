from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver import provider_digest
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

    def test_tree_digest_rejects_ambiguous_or_nonportable_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unsafe name.yml").write_text("kind: ConfigMap\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "provider filenames"):
                digest_tree(root)

    def test_quadlet_digest_rejects_unsafe_name_and_missing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "safe lowercase systemd name"):
                digest_quadlet(root, "Unsafe Name")
            with self.assertRaisesRegex(ValueError, "regular file"):
                digest_quadlet(root, "paperless-ngx")

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

    def test_provider_digest_enforces_file_entry_and_total_byte_limits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "a.yml"
            second = root / "b.yml"
            first.write_bytes(b"aa")
            second.write_bytes(b"bb")

            with patch("archiveweaver.provider_digest.MAX_PROVIDER_FILE_BYTES", 1):
                with self.assertRaisesRegex(OSError, "1-byte safety limit"):
                    digest_file(first)
            with patch("archiveweaver.provider_digest.MAX_PROVIDER_TREE_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "1-entry safety limit"):
                    digest_tree(root)
            with patch("archiveweaver.provider_digest.MAX_PROVIDER_TREE_FILES", 1):
                with self.assertRaisesRegex(ValueError, "1-file safety limit"):
                    digest_tree(root)
            with patch("archiveweaver.provider_digest.MAX_PROVIDER_TREE_BYTES", 3):
                with self.assertRaisesRegex(ValueError, "3-byte safety limit"):
                    digest_tree(root)

    def test_provider_digest_rejects_tree_mutation_during_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "a.yml"
            second = root / "b.yml"
            first.write_bytes(b"first\n")
            second.write_bytes(b"second\n")
            original_measure = provider_digest._measure_regular_file

            def mutate_after_first(path: Path, **kwargs: object) -> tuple[int, str]:
                result = original_measure(path, **kwargs)
                if path == first:
                    second.write_bytes(b"changed\n")
                return result

            with patch(
                "archiveweaver.provider_digest._measure_regular_file",
                side_effect=mutate_after_first,
            ):
                with self.assertRaisesRegex(OSError, "tree changed"):
                    digest_tree(root)

    def test_provider_digest_rejects_hard_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.yml"
            alias = root / "alias.yml"
            original.write_bytes(b"provider\n")
            try:
                os.link(original, alias)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"hard links are unavailable: {exc}")
            with self.assertRaisesRegex(OSError, "exactly one hard link"):
                digest_tree(root)

    def test_provider_digest_rejects_case_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Provider.yml").write_bytes(b"first\n")
            (root / "provider.yml").write_bytes(b"second\n")
            if len(list(root.iterdir())) < 2:
                self.skipTest("case-colliding paths are unavailable")
            with self.assertRaisesRegex(ValueError, "case-insensitive"):
                digest_tree(root)
