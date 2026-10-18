"""The first staging installation has its own protected authorization."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import runpy
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


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

    def test_timestamp_must_be_a_real_calendar_value(self) -> None:
        self.assertIsNone(seed._timestamp("not-a-timestamp"))
        self.assertIsNone(seed._timestamp("2026-13-45T99:99:99Z"))

    def test_invalid_binding_values_are_rejected_before_the_digest(self) -> None:
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        digest = seed.authorization_digest(authorization)
        for replacement in ("not-a-digest", "REPLACE_WITH_DIGEST", " " + "a" * 63):
            with self.subTest(replacement=replacement):
                changed = list(ARGS)
                changed[0] = replacement
                self.assertEqual(
                    seed.validate_authorization(value, digest, *changed, now=NOW),
                    ["invalid source revision binding"],
                )

    def test_approval_ticket_must_differ_from_the_change_ticket(self) -> None:
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        digest = seed.authorization_digest(authorization)
        changed = list(ARGS)
        changed[-1] = "CHG-1234"
        self.assertEqual(
            seed.validate_authorization(value, digest, *changed, now=NOW),
            ["approval ticket must be independent of the change ticket"],
        )

    def test_manifest_must_be_an_object_with_an_authorization(self) -> None:
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        digest = seed.authorization_digest(authorization)
        self.assertEqual(
            seed.validate_authorization("text", digest, *ARGS, now=NOW),
            ["readiness manifest must be an object"],
        )
        self.assertEqual(
            seed.validate_authorization({}, digest, *ARGS, now=NOW),
            ["staging seed authorization is missing or has an invalid shape"],
        )

    def test_protected_digest_mismatch_is_reported(self) -> None:
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        digest = seed.authorization_digest(authorization)
        authorization["approval_ticket"] = "APR-OTHER"
        self.assertEqual(
            seed.validate_authorization(value, digest, *ARGS, now=NOW),
            ["staging seed authorization does not match the protected digest"],
        )

    def test_service_identity_must_stay_on_the_staging_target(self) -> None:
        value = manifest()
        service = value["service"]
        authorization = value["staging_seed_authorization"]
        assert isinstance(service, dict) and isinstance(authorization, dict)
        service["environment"] = "production"
        authorized_service = authorization["service"]
        assert isinstance(authorized_service, dict)
        authorized_service["environment"] = "production"
        self.assertEqual(
            check(value), ["staging seed service identity does not match the staging target"]
        )

    def test_cli_usage_and_input_errors_are_reported(self) -> None:
        self.assertEqual(seed.main([str(SCRIPT)]), 2)
        path = ROOT / "deploy/ansible/staging-seed-authorization.example.json"
        self.assertEqual(seed.main([str(SCRIPT), str(path), "INVALID", "0" * 64, *ARGS]), 2)
        absent = ROOT / "deploy/ansible/staging-seed-authorization.absent.json"
        self.assertEqual(seed.main([str(SCRIPT), str(absent), "0" * 64, "0" * 64, *ARGS]), 1)

    def test_cli_fails_closed_on_unreadable_manifests(self) -> None:
        def explode(*_args, **_kwargs):
            raise RuntimeError("boom")

        path = ROOT / "deploy/ansible/staging-seed-authorization.example.json"
        original = seed._read_stable_bytes
        try:
            seed._read_stable_bytes = explode
            self.assertEqual(seed.main([str(SCRIPT), str(path), "0" * 64, "0" * 64, *ARGS]), 1)
        finally:
            seed._read_stable_bytes = original

    def test_cli_reports_authorization_failures(self) -> None:
        value = manifest()
        authorization = value["staging_seed_authorization"]
        assert isinstance(authorization, dict)
        current = datetime.now(timezone.utc)
        authorization["issued_at"] = (current - timedelta(hours=1)).isoformat()
        authorization["expires_at"] = (current + timedelta(hours=1)).isoformat()
        authorization["purpose"] = "first-production-apply"
        governance = value["governance"]
        assert isinstance(governance, dict)
        governance["approved_at"] = (current - timedelta(days=1)).isoformat()
        governance["valid_until"] = (current + timedelta(days=1)).isoformat()
        payload = json.dumps(value).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        auth_digest = seed.authorization_digest(authorization)
        path = ROOT / "deploy/ansible/staging-seed-authorization.example.json"
        original = seed._read_stable_bytes
        try:
            seed._read_stable_bytes = lambda *_args, **_kwargs: (payload, digest)
            self.assertEqual(seed.main([str(SCRIPT), str(path), digest, auth_digest, *ARGS]), 1)
        finally:
            seed._read_stable_bytes = original

    def test_main_guard_exits_with_the_usage_code(self) -> None:
        with mock.patch.object(sys, "argv", [str(SCRIPT)]):
            with self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
