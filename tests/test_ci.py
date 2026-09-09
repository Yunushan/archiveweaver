from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CIWorkflowTests(unittest.TestCase):
    def test_github_actions_are_pinned_to_immutable_commit_shas(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        uses_lines = [line.strip() for line in workflow.splitlines() if "uses:" in line]
        self.assertTrue(uses_lines)
        for line in uses_lines:
            self.assertRegex(line, r"uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+#.*)?$")
            self.assertNotRegex(line, r"@[vV][0-9]")

    def test_controller_contract_verifies_signed_source_identity(self) -> None:
        workflow = (ROOT / "deploy/ansible/controller/workflow.yml").read_text(encoding="utf-8")
        controller_readme = (ROOT / "deploy/ansible/controller/README.md").read_text(encoding="utf-8")
        verifier = ROOT / "scripts/verify-source-identity.sh"
        manifest_verifier = ROOT / "scripts/verify-readiness-manifest.py"
        self.assertTrue(verifier.is_file())
        self.assertTrue(manifest_verifier.is_file())
        self.assertIn("source-integrity", workflow)
        self.assertIn("verify-source-identity.sh", workflow)
        self.assertIn("ARCHIVEWEAVER_IMMUTABLE_REF", workflow)
        self.assertIn("ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS", workflow)
        self.assertIn("ARCHIVEWEAVER_READINESS_MANIFEST_SHA256", workflow)
        self.assertIn("scripts/verify-readiness-manifest.py", workflow)
        self.assertIn("product-certification", workflow)
        self.assertIn("backup-and-restore-gate", workflow)
        self.assertIn("source_verification: signed-commit-and-clean-checkout", workflow)
        self.assertLess(workflow.index("- id: source-integrity"), workflow.index("- id: catalog-and-tests"))
        self.assertIn("verify-source-identity.sh", controller_readme)
        self.assertIn("git ls-files --others --exclude-standard -z", verifier.read_text(encoding="utf-8"))
        self.assertIn("GIT_OPTIONAL_LOCKS=0", verifier.read_text(encoding="utf-8"))
        self.assertIn("{40}|[0-9a-fA-F]{64}", verifier.read_text(encoding="utf-8"))
        self.assertIn("VALIDSIG", verifier.read_text(encoding="utf-8"))
        self.assertIn("ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS", verifier.read_text(encoding="utf-8"))
        self.assertIn("git ls-files --others --ignored --exclude-standard -z", verifier.read_text(encoding="utf-8"))
        self.assertIn("is_allowed_operator_path", verifier.read_text(encoding="utf-8"))
        self.assertIn("operator_path_is_safe", verifier.read_text(encoding="utf-8"))
        self.assertIn("! -L", verifier.read_text(encoding="utf-8"))
        self.assertIn("release-manifest-restore.json", verifier.read_text(encoding="utf-8"))

    def test_readiness_manifest_binding_verifier_accepts_only_exact_bytes(self) -> None:
        manifest = ROOT / "deploy/ansible/release-manifest.example.json"
        verifier = ROOT / "scripts/verify-readiness-manifest.py"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        accepted = subprocess.run(
            [sys.executable, str(verifier), str(manifest), digest],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        rejected = subprocess.run(
            [sys.executable, str(verifier), str(manifest), "0" * 64],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("does not match", rejected.stderr)

    def test_ci_rejects_generated_catalog_drift(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/generate_catalog.py", workflow)
        self.assertIn("git diff --exit-code", workflow)
