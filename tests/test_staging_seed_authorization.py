"""The first staging installation has its own protected authorization."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-staging-seed-authorization.py"
SPEC = importlib.util.spec_from_file_location("verify_staging_seed_authorization", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
seed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed)

NOW = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)
SOURCE = "a" * 40
EE = "sha256:" + "b" * 64
PROVIDER = "sha256:" + "c" * 64
KUSTOMIZE = "d" * 64
KUBECONFIG = "e" * 64
INVENTORY = "f" * 64
ARGS = (SOURCE, EE, PROVIDER, KUSTOMIZE, KUBECONFIG, INVENTORY, "rke2-staging", "paperless-staging", "CHG-1234", "APR-1234")


def manifest() -> dict[str, object]:
    service = {
        "solution_id": "paperless-ngx", "runtime": "ansible", "underlying_runtime": "rke2",
        "os_id": "ubuntu-24.04", "environment": "staging",
    }
    return {
        "service": service,
        "release": {
            "version": "2.17.0", "source_repository": "owner/archiveweaver",
            "source_repository_id": 12345, "source_revision": SOURCE,
            "execution_environment": {"digest": EE},
            "provider_bundle": {"digest": PROVIDER, "remote_digest": "sha256:" + KUSTOMIZE},
        },
        "control": {"change_ticket": "CHG-1234", "operator": "deploy-operator"},
        "governance": {
            "change_ticket": "CHG-1234", "approved_by": "release-approver",
            "approved_at": "2026-09-20T12:00:00Z", "valid_until": "2026-10-01T12:00:00Z",
        },
        "staging_seed_authorization": {
            "schema_version": 1, "purpose": "first-staging-apply", "service": copy.deepcopy(service),
            "release_version": "2.17.0", "source_repository": "owner/archiveweaver",
            "source_repository_id": 12345, "source_revision": SOURCE,
            "execution_environment_digest": EE, "provider_bundle_digest": PROVIDER,
            "kustomize_bundle_sha256": KUSTOMIZE, "kubeconfig_sha256": KUBECONFIG,
            "inventory_sha256": INVENTORY,
            "kube_context": "rke2-staging", "namespace": "paperless-staging",
            "change_ticket": "CHG-1234", "approval_ticket": "APR-1234",
            "approved_by": "release-approver", "issued_at": "2026-09-25T11:00:00Z",
            "expires_at": "2026-09-25T13:00:00Z",
        },
    }


def check(value: dict[str, object]) -> list[str]:
    authorization = value["staging_seed_authorization"]
    assert isinstance(authorization, dict)
    return seed.validate_authorization(value, seed.authorization_digest(authorization), *ARGS, now=NOW)


class StagingSeedAuthorizationTests(unittest.TestCase):
    def test_exact_staging_binding(self) -> None:
        self.assertEqual(check(manifest()), [])

    def test_production_authorization_cannot_seed_staging(self) -> None:
        value = manifest()
        value["bootstrap_authorization"] = value.pop("staging_seed_authorization")
        self.assertNotEqual(seed.validate_authorization(value, "f" * 64, *ARGS, now=NOW), [])
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        authorization["purpose"] = "first-production-apply"
        self.assertNotEqual(check(value), [])

    def test_rejects_changed_release_or_target(self) -> None:
        for section, key, replacement in (
            ("release", "source_revision", "f" * 40),
            ("release", "version", "2.18.0"),
            ("control", "change_ticket", "CHG-OTHER"),
            ("governance", "approved_by", "other-approver"),
        ):
            with self.subTest(section=section, key=key):
                value = manifest()
                selected = value[section]
                assert isinstance(selected, dict)
                selected[key] = replacement
                self.assertNotEqual(check(value), [])
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        authorization["namespace"] = "another-namespace"
        self.assertNotEqual(check(value), [])
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        digest = seed.authorization_digest(authorization)
        changed_args = list(ARGS)
        changed_args[5] = "0" * 64
        self.assertNotEqual(seed.validate_authorization(value, digest, *changed_args, now=NOW), [])

    def test_requires_independent_fresh_approval(self) -> None:
        value = manifest()
        control = value["control"]
        assert isinstance(control, dict)
        control["operator"] = "release-approver"
        self.assertNotEqual(check(value), [])
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        authorization["expires_at"] = "2026-09-27T13:00:00Z"
        self.assertNotEqual(check(value), [])

    def test_cli_rehashes_full_manifest_on_its_own_read(self) -> None:
        value = manifest()
        authorization = value["staging_seed_authorization"]
        governance = value["governance"]
        assert isinstance(authorization, dict) and isinstance(governance, dict)
        current = datetime.now(timezone.utc)
        authorization["issued_at"] = (current - timedelta(hours=1)).isoformat()
        authorization["expires_at"] = (current + timedelta(hours=1)).isoformat()
        governance["approved_at"] = (current - timedelta(days=1)).isoformat()
        governance["valid_until"] = (current + timedelta(days=1)).isoformat()
        payload = json.dumps(value).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        auth_digest = seed.authorization_digest(authorization)
        path = ROOT / "deploy/ansible/staging-seed-authorization.example.json"
        original = seed._read_stable_bytes
        try:
            seed._read_stable_bytes = lambda *_args, **_kwargs: (payload, digest)
            self.assertEqual(seed.main([str(SCRIPT), str(path), digest, auth_digest, *ARGS]), 0)
            self.assertEqual(seed.main([str(SCRIPT), str(path), "f" * 64, auth_digest, *ARGS]), 1)
        finally:
            seed._read_stable_bytes = original


if __name__ == "__main__":
    unittest.main()
