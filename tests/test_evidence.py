from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver.evidence import (
    _safe_file,
    build_evidence_index,
    verify_evidence_index,
)


class EvidenceTests(unittest.TestCase):
    def test_builder_rejects_missing_root_and_external_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            missing = temporary / "missing"
            with self.assertRaisesRegex(ValueError, "does not exist"):
                build_evidence_index(missing, missing / "evidence-index.json")

            root = temporary / "evidence"
            root.mkdir()
            (root / "host.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inside the evidence directory"):
                build_evidence_index(root, temporary / "external-index.json")

    def test_builder_cleans_temporary_index_after_atomic_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text("{}\n", encoding="utf-8")
            output = root / "evidence-index.json"
            with patch("archiveweaver.evidence.os.replace", side_effect=OSError("denied")):
                with self.assertRaisesRegex(OSError, "denied"):
                    build_evidence_index(root, output)
            self.assertEqual(
                [path.name for path in root.iterdir()],
                ["host.json"],
            )

    def test_safe_file_rejects_malformed_and_uninspectable_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text("{}\n", encoding="utf-8")
            for relative in (
                "",
                "../host.json",
                "/host.json",
                "C:\\outside.json",
                "nested\\host.json",
                "host.json\x00suffix",
            ):
                with self.subTest(relative=relative):
                    self.assertIsNone(_safe_file(root, relative))

            with patch("archiveweaver.evidence.Path.is_symlink", side_effect=OSError("denied")):
                self.assertIsNone(_safe_file(root, "host.json"))
            with patch("archiveweaver.evidence.Path.resolve", side_effect=OSError("denied")):
                self.assertIsNone(_safe_file(root, "host.json"))

    def test_index_round_trip_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text('{"status":"pass"}\n', encoding="utf-8")
            (root / "plan.json").write_text('{"change":"CHG-1234"}\n', encoding="utf-8")
            index_path = root / "evidence-index.json"
            result = build_evidence_index(root, index_path)
            self.assertEqual(len(result["files"]), 2)
            expected_digest = hashlib.sha256(index_path.read_bytes()).hexdigest()
            verified = verify_evidence_index(
                index_path,
                expected_sha256=expected_digest,
            )
            self.assertEqual(verified["status"], "pass")
            self.assertEqual(verified["sha256"], expected_digest)
            mismatch = verify_evidence_index(
                index_path,
                expected_sha256="0" * 64,
            )
            self.assertEqual(mismatch["status"], "fail")
            self.assertIn("evidence index digest mismatch", mismatch["errors"])
            malformed = verify_evidence_index(
                index_path,
                expected_sha256="not-a-digest",
            )
            self.assertEqual(malformed["status"], "fail")
            self.assertTrue(
                any("64 lowercase hexadecimal" in error for error in malformed["errors"])
            )
            (root / "host.json").write_text('{"status":"tampered"}\n', encoding="utf-8")
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("digest mismatch" in error for error in report["errors"]))

    def test_index_rejects_unindexed_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text("{}\n", encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            (root / "late.json").write_text("{}\n", encoding="utf-8")
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertIn("unindexed evidence file: late.json", report["errors"])

    def test_index_rejects_missing_size_and_digest_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "host.json"
            evidence.write_text("first\n", encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)

            evidence.write_text("other\n", encoding="utf-8")
            digest_report = verify_evidence_index(index_path)
            self.assertTrue(
                any("digest mismatch" in error for error in digest_report["errors"])
            )
            self.assertFalse(
                any("size mismatch" in error for error in digest_report["errors"])
            )

            evidence.write_text("different-size\n", encoding="utf-8")
            size_report = verify_evidence_index(index_path)
            self.assertTrue(
                any("size mismatch" in error for error in size_report["errors"])
            )

            evidence.unlink()
            missing_report = verify_evidence_index(index_path)
            self.assertTrue(
                any("missing, unsafe" in error for error in missing_report["errors"])
            )
            self.assertIn(
                "indexed evidence file is not present: host.json",
                missing_report["errors"],
            )

    def test_index_rejects_schema_and_entry_shape_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = root / "evidence-index.json"

            index_path.write_text("{}\n", encoding="utf-8")
            self.assertIn(
                "unsupported evidence index schema",
                verify_evidence_index(index_path)["errors"],
            )

            index_path.write_text(
                json.dumps(
                    {"schema_version": 1, "algorithm": "sha256", "files": {}},
                ),
                encoding="utf-8",
            )
            self.assertIn(
                "evidence index files must be a list",
                verify_evidence_index(index_path)["errors"],
            )

            (root / "host.json").write_text("{}\n", encoding="utf-8")
            index_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "algorithm": "sha256",
                        "files": [
                            "bad-entry",
                            {"path": 7},
                            {"path": "host.json", "bytes": 3, "sha256": "bad"},
                            {"path": "host.json", "bytes": 3, "sha256": "bad"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(
                sum("malformed file entry" in error for error in report["errors"]),
                3,
            )
            self.assertIn("duplicate evidence index entry: host.json", report["errors"])

    def test_index_size_and_entry_count_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = root / "evidence-index.json"
            index_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "algorithm": "sha256",
                        "files": [],
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "archiveweaver.evidence.MAX_EVIDENCE_INDEX_BYTES",
                index_path.stat().st_size - 1,
            ):
                report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(
                any("safety limit" in error for error in report["errors"])
            )

            (root / "first.json").write_text("{}\n", encoding="utf-8")
            (root / "second.json").write_text("{}\n", encoding="utf-8")
            with patch("archiveweaver.evidence.MAX_EVIDENCE_INDEX_FILES", 1):
                with self.assertRaisesRegex(ValueError, "file safety limit"):
                    build_evidence_index(root, index_path)

            index_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "algorithm": "sha256",
                        "files": [{}, {}],
                    }
                ),
                encoding="utf-8",
            )
            with patch("archiveweaver.evidence.MAX_EVIDENCE_INDEX_FILES", 1):
                report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertIn(
                "evidence index exceeds the 1-file safety limit",
                report["errors"],
            )

    def test_index_rejects_noncanonical_types_digests_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text("x", encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            pristine = json.loads(index_path.read_text(encoding="utf-8"))

            unknown_schema_field = {**pristine, "comment": "not-canonical"}
            index_path.write_text(json.dumps(unknown_schema_field), encoding="utf-8")
            self.assertIn(
                "unsupported evidence index schema",
                verify_evidence_index(index_path)["errors"],
            )

            for field, value in (
                ("bytes", True),
                ("bytes", -1),
                ("sha256", pristine["files"][0]["sha256"].upper()),
            ):
                with self.subTest(field=field, value=value):
                    malformed = json.loads(json.dumps(pristine))
                    malformed["files"][0][field] = value
                    index_path.write_text(json.dumps(malformed), encoding="utf-8")
                    self.assertIn(
                        "evidence index contains a malformed file entry",
                        verify_evidence_index(index_path)["errors"],
                    )

    def test_index_rejects_noncanonical_cross_platform_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text("{}\n", encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["files"][0]["path"] = r"C:\outside\host.json"
            index_path.write_text(json.dumps(index), encoding="utf-8")
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("unsafe" in error for error in report["errors"]))

    def test_index_must_be_a_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index_path = Path(directory) / "evidence-index.json"
            index_path.mkdir()
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertIn("regular, non-symlink", report["errors"][0])

    def test_index_rejects_symlinked_directory_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            (real / "host.json").write_text("{}\n", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            with self.assertRaisesRegex(ValueError, "symlink"):
                build_evidence_index(link, link / "evidence-index.json")

            build_evidence_index(real, real / "evidence-index.json")
            report = verify_evidence_index(link / "evidence-index.json")
            self.assertEqual(report["status"], "fail")
            self.assertIn("regular, non-symlink", report["errors"][0])

    def test_index_rejects_nested_symlink_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            (real / "host.json").write_text("{}\n", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            index_path = root / "evidence-index.json"
            with self.assertRaisesRegex(ValueError, "symlinked paths"):
                build_evidence_index(root, index_path)

    def test_index_rejects_hard_link_aliases_inside_or_outside_the_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            root = temporary / "evidence"
            root.mkdir()
            evidence = root / "host.json"
            evidence.write_text("{}\n", encoding="utf-8")
            outside_alias = temporary / "outside-alias.json"
            try:
                os.link(evidence, outside_alias)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hard links are unavailable: {exc}")

            with self.assertRaisesRegex(OSError, "exactly one hard link"):
                build_evidence_index(root, root / "evidence-index.json")

            outside_alias.unlink()
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            index_alias = temporary / "index-alias.json"
            os.link(index_path, index_alias)
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(
                any("exactly one hard link" in error for error in report["errors"])
            )

    def test_verifier_rejects_symlinked_paths_added_after_sealing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text("{}\n", encoding="utf-8")
            index_path = root / "evidence-index.json"
            build_evidence_index(root, index_path)
            real = root / "real"
            real.mkdir()
            (real / "late.json").write_text("{}\n", encoding="utf-8")
            link = root / "redirected"
            try:
                link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("symlink is not permitted" in error for error in report["errors"]))

    def test_invalid_utf8_index_is_reported_as_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index_path = Path(directory) / "evidence-index.json"
            index_path.write_bytes(b"{\xff")
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")

    def test_duplicate_index_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index_path = Path(directory) / "evidence-index.json"
            index_path.write_text(
                '{"schema_version": 1, "schema_version": 1, "algorithm": "sha256", "files": []}',
                encoding="utf-8",
            )
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(any("duplicate JSON object key" in error for error in report["errors"]))
