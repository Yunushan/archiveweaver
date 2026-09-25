"""The first production apply requires an exact, independent approval binding."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-bootstrap-authorization.py"
SPEC = importlib.util.spec_from_file_location("verify_bootstrap_authorization", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)

SOURCE = "a" * 40
EE = "sha256:" + "b" * 64
PROVIDER = "sha256:" + "c" * 64
KUSTOMIZE = "d" * 64
KUBECONFIG = "e" * 64
INVENTORY = "f" * 64
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
ARGS = (
    SOURCE,
    EE,
    PROVIDER,
    KUSTOMIZE,
    KUBECONFIG,
    INVENTORY,
    "rke2-production",
    "paperless",
    "CHG-1234",
    "APR-1234",
)


def manifest() -> dict[str, object]:
    service = {
        "solution_id": "paperless-ngx",
        "runtime": "ansible",
        "underlying_runtime": "rke2",
        "os_id": "ubuntu-24.04",
        "environment": "production",
    }
    return {
        "service": service,
        "release": {
            "version": "2.17.0",
            "source_repository": "owner/archiveweaver",
            "source_repository_id": 12345,
            "source_revision": SOURCE,
            "execution_environment": {"digest": EE},
            "provider_bundle": {
                "digest": PROVIDER,
                "remote_digest": "sha256:" + KUSTOMIZE,
            },
        },
        "control": {"change_ticket": "CHG-1234", "operator": "deploy-operator"},
        "governance": {
            "change_ticket": "CHG-1234",
            "approved_by": "release-approver",
            "approved_at": "2026-09-20T12:00:00Z",
            "valid_until": "2026-10-01T12:00:00Z",
        },
        "bootstrap_authorization": {
            "schema_version": 1,
            "purpose": "first-production-apply",
            "service": copy.deepcopy(service),
            "release_version": "2.17.0",
            "source_repository": "owner/archiveweaver",
            "source_repository_id": 12345,
            "source_revision": SOURCE,
            "execution_environment_digest": EE,
            "provider_bundle_digest": PROVIDER,
            "kustomize_bundle_sha256": KUSTOMIZE,
            "kubeconfig_sha256": KUBECONFIG,
            "inventory_sha256": INVENTORY,
            "kube_context": "rke2-production",
            "namespace": "paperless",
            "change_ticket": "CHG-1234",
            "approval_ticket": "APR-1234",
            "approved_by": "release-approver",
            "issued_at": "2026-09-25T11:00:00Z",
            "expires_at": "2026-09-25T13:00:00Z",
        },
    }


def check(value: dict[str, object], *, now: datetime = NOW) -> list[str]:
    authorization = value["bootstrap_authorization"]
    assert isinstance(authorization, dict)
    digest = bootstrap.authorization_digest(authorization)
    return bootstrap.validate_authorization(value, digest, *ARGS, now=now)


class BootstrapAuthorizationTests(unittest.TestCase):
    def test_valid_exact_binding(self) -> None:
        self.assertEqual(check(manifest()), [])

    def test_protected_digest_is_independent_of_manifest_digest(self) -> None:
        value = manifest()
        authorization = value["bootstrap_authorization"]
        assert isinstance(authorization, dict)
        digest = bootstrap.authorization_digest(authorization)
        authorization["approval_ticket"] = "APR-OTHER"
        self.assertIn("protected digest", bootstrap.validate_authorization(value, digest, *ARGS, now=NOW)[0])

    def test_rejects_changed_release_and_target_bindings(self) -> None:
        edits = (
            ("release", "version", "2.18.0"),
            ("release", "source_repository", "other/archiveweaver"),
            ("release", "source_repository_id", 54321),
            ("release", "source_revision", "f" * 40),
            ("control", "change_ticket", "CHG-OTHER"),
            ("governance", "approved_by", "other-approver"),
        )
        for section_name, key, replacement in edits:
            with self.subTest(section=section_name, key=key):
                value = manifest()
                section = value[section_name]
                assert isinstance(section, dict)
                section[key] = replacement
                self.assertNotEqual(check(value), [])
        value = manifest()
        release = value["release"]
        assert isinstance(release, dict)
        provider = release["provider_bundle"]
        assert isinstance(provider, dict)
        provider["remote_digest"] = "sha256:" + "0" * 64
        self.assertNotEqual(check(value), [])

    def test_rejects_wrong_purpose_service_and_approval(self) -> None:
        for field, replacement in (
            ("purpose", "first-staging-apply"),
            ("schema_version", True),
            ("approval_ticket", "CHG-1234"),
            ("approved_by", "REPLACE_WITH_APPROVER"),
        ):
            with self.subTest(field=field):
                value = manifest()
                authorization = value["bootstrap_authorization"]
                assert isinstance(authorization, dict)
                authorization[field] = replacement
                self.assertNotEqual(check(value), [])
        value = manifest()
        service = value["service"]
        authorization = value["bootstrap_authorization"]
        assert isinstance(service, dict) and isinstance(authorization, dict)
        service["environment"] = "staging"
        authorized_service = authorization["service"]
        assert isinstance(authorized_service, dict)
        authorized_service["environment"] = "staging"
        self.assertNotEqual(check(value), [])

    def test_rejects_changed_controller_and_cluster_job_bindings(self) -> None:
        value = manifest()
        authorization = value["bootstrap_authorization"]
        assert isinstance(authorization, dict)
        digest = bootstrap.authorization_digest(authorization)
        replacements = (
            "f" * 40,
            "sha256:" + "f" * 64,
            "sha256:" + "f" * 64,
            "f" * 64,
            "f" * 64,
            "0" * 64,
            "other-context",
            "other-namespace",
            "CHG-OTHER",
            "APR-OTHER",
        )
        for index, replacement in enumerate(replacements):
            with self.subTest(binding=index):
                changed = list(ARGS)
                changed[index] = replacement
                self.assertNotEqual(
                    bootstrap.validate_authorization(value, digest, *changed, now=NOW),
                    [],
                )

    def test_rejects_approval_outside_governance_window_or_by_operator(self) -> None:
        value = manifest()
        governance = value["governance"]
        assert isinstance(governance, dict)
        governance["valid_until"] = "2026-09-25T12:30:00Z"
        self.assertNotEqual(check(value), [])
        value = manifest()
        control = value["control"]
        assert isinstance(control, dict)
        control["operator"] = "release-approver"
        self.assertNotEqual(check(value), [])

    def test_rejects_expired_future_and_long_lived_approval(self) -> None:
        for issued, expires in (
            ("2026-09-23T11:00:00Z", "2026-09-25T13:00:00Z"),
            ("2026-09-25T13:00:00Z", "2026-09-25T14:00:00Z"),
            ("2026-09-24T11:00:00Z", "2026-09-25T11:59:59Z"),
            ("2026-09-25T11:00:00", "2026-09-25T13:00:00Z"),
        ):
            with self.subTest(issued=issued, expires=expires):
                value = manifest()
                authorization = value["bootstrap_authorization"]
                assert isinstance(authorization, dict)
                authorization["issued_at"] = issued
                authorization["expires_at"] = expires
                self.assertNotEqual(check(value), [])

    def test_cli_rejects_ambiguous_duplicate_keys(self) -> None:
        value = manifest()
        authorization = value["bootstrap_authorization"]
        assert isinstance(authorization, dict)
        current_time = datetime.now(timezone.utc)
        authorization["issued_at"] = (current_time - timedelta(hours=1)).isoformat()
        authorization["expires_at"] = (current_time + timedelta(hours=1)).isoformat()
        governance = value["governance"]
        assert isinstance(governance, dict)
        governance["approved_at"] = (current_time - timedelta(days=1)).isoformat()
        governance["valid_until"] = (current_time + timedelta(days=1)).isoformat()
        digest = bootstrap.authorization_digest(authorization)
        original_reader = bootstrap._read_stable_bytes
        path = ROOT / "deploy/ansible/release-manifest.example.json"
        try:
            payload = json.dumps(value).encode("utf-8")
            bootstrap._read_stable_bytes = lambda *_args, **_kwargs: (payload, "0" * 64)
            self.assertEqual(bootstrap.main([str(SCRIPT), str(path), "0" * 64, digest, *ARGS]), 0)
            self.assertEqual(bootstrap.main([str(SCRIPT), str(path), "1" * 64, digest, *ARGS]), 1)
            self.assertEqual(bootstrap.main([str(SCRIPT), str(path), "INVALID", digest, *ARGS]), 2)
            payload = b'{"bootstrap_authorization":{},"bootstrap_authorization":{}}'
            self.assertEqual(bootstrap.main([str(SCRIPT), str(path), "0" * 64, digest, *ARGS]), 1)
        finally:
            bootstrap._read_stable_bytes = original_reader


if __name__ == "__main__":
    unittest.main()
