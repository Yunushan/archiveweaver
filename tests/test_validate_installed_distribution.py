from __future__ import annotations

import contextlib
import io
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import archiveweaver
from archiveweaver import catalog as catalog_module
from archiveweaver import repair as repair_module


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-installed-distribution.py"

INSTALLED_PACKAGE = "/opt/archiveweaver/lib/python3.14/site-packages/archiveweaver/__init__.py"

ANSIBLE_FILES = (
    "ansible.cfg",
    "repair.yml",
    "filter_plugins/archiveweaver_swarm.py",
    "roles/archiveweaver_preflight/tasks/main.yml",
    "roles/archiveweaver_provider/tasks/record-release.yml",
    "roles/archiveweaver_provider/tasks/verify-kustomize-tree.yml",
    "roles/archiveweaver_repair/tasks/require-kubernetes-record.yml",
)

BUNDLE_FILES = (
    "scripts/compile-ansible-lock.py",
    "scripts/generate-ansible-sbom.py",
    "scripts/run-ansible-operational.sh",
    "scripts/verify-bootstrap-authorization.py",
    "scripts/verify-kustomize-bundle.py",
    "scripts/verify-live-kubernetes-workloads.py",
    "scripts/verify-live-kubernetes-resources.py",
    "scripts/verify-paperless-rke2-model.py",
    "scripts/verify-provider-image-coverage.py",
    "scripts/verify-staging-seed-authorization.py",
    "deploy/paperless-ngx/rke2/kustomization.yaml",
    "deploy/paperless-ngx/rke2/README.md",
)

READY_PLAN = {"status": "ready", "actions": [1, 2, 3, 4]}


def build_bundle(base: Path) -> Path:
    ansible_root = base / "share" / "archiveweaver" / "deploy" / "ansible"
    for relative in ANSIBLE_FILES:
        path = ansible_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    bundle_root = ansible_root.parent.parent
    for relative in BUNDLE_FILES:
        path = bundle_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    return ansible_root


class ValidateInstalledDistributionTests(unittest.TestCase):
    def _run(self, ansible_root: Path, plan: dict, package_file: str = INSTALLED_PACKAGE) -> tuple[int, str]:
        with mock.patch.object(archiveweaver, "__file__", package_file):
            with mock.patch.object(repair_module, "_find_ansible_root", return_value=ansible_root):
                with mock.patch.object(repair_module, "build_repair_plan", return_value=plan):
                    with mock.patch.object(catalog_module, "Catalog", return_value=object()):
                        stdout = io.StringIO()
                        with contextlib.redirect_stdout(stdout):
                            code = runpy.run_path(str(SCRIPT))["main"]()
        return code, stdout.getvalue()

    def test_complete_bundle_is_reported_as_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            code, stdout = self._run(ansible_root, READY_PLAN)
        self.assertEqual(code, 0)
        self.assertIn("installed distribution valid:", stdout)

    def test_source_checkout_import_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            with self.assertRaisesRegex(RuntimeError, "imported ArchiveWeaver from the source checkout"):
                self._run(
                    ansible_root,
                    READY_PLAN,
                    package_file=str(ROOT / "src" / "archiveweaver" / "__init__.py"),
                )

    def test_incomplete_bundle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            (ansible_root / "repair.yml").unlink()
            with self.assertRaisesRegex(RuntimeError, "installed operational bundle is incomplete"):
                self._run(ansible_root, READY_PLAN)

    def test_production_secret_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            secret = ansible_root.parent.parent / "deploy" / "paperless-ngx" / "rke2" / "paperless.env"
            secret.write_text("SECRET=1", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "contains a production secret input"):
                self._run(ansible_root, READY_PLAN)

    def test_unready_repair_plan_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            with self.assertRaisesRegex(RuntimeError, "repair planner did not become ready"):
                self._run(ansible_root, {"status": "blocked", "actions": []})

    def test_repair_plan_with_the_wrong_action_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            with self.assertRaisesRegex(RuntimeError, "repair planner did not become ready"):
                self._run(ansible_root, {"status": "ready", "actions": [1, 2, 3]})

    def test_main_guard_exits_with_the_validation_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ansible_root = build_bundle(Path(directory))
            with mock.patch.object(archiveweaver, "__file__", INSTALLED_PACKAGE):
                with mock.patch.object(repair_module, "_find_ansible_root", return_value=ansible_root):
                    with mock.patch.object(repair_module, "build_repair_plan", return_value=READY_PLAN):
                        with mock.patch.object(catalog_module, "Catalog", return_value=object()):
                            with contextlib.redirect_stdout(io.StringIO()):
                                with self.assertRaises(SystemExit) as caught:
                                    runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
