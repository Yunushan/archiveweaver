from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from archiveweaver.evidence import build_evidence_index, verify_evidence_index


class EvidenceTests(unittest.TestCase):
    def test_index_round_trip_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "host.json").write_text('{"status":"pass"}\n', encoding="utf-8")
            (root / "plan.json").write_text('{"change":"CHG-1234"}\n', encoding="utf-8")
            index_path = root / "evidence-index.json"
            result = build_evidence_index(root, index_path)
            self.assertEqual(len(result["files"]), 2)
            self.assertEqual(verify_evidence_index(index_path)["status"], "pass")
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

    def test_invalid_utf8_index_is_reported_as_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index_path = Path(directory) / "evidence-index.json"
            index_path.write_bytes(b"{\xff")
            report = verify_evidence_index(index_path)
            self.assertEqual(report["status"], "fail")
