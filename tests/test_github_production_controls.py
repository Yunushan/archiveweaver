from __future__ import annotations

import copy
import io
import json
import runpy
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit-github-production-controls.py"


class GitHubProductionControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = runpy.run_path(str(SCRIPT), run_name="github_production_controls")

    def passing_snapshot(self) -> Any:
        checks = sorted(self.audit["EXPECTED_STATUS_CHECKS"])
        branch_ruleset = {
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
            },
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {"type": "required_signatures"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "dismiss_stale_reviews_on_push": True,
                        "require_code_owner_review": True,
                        "require_last_push_approval": True,
                        "required_approving_review_count": 1,
                        "required_review_thread_resolution": True,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {"context": context, "integration_id": 15368}
                            for context in checks
                        ],
                    },
                },
            ],
        }
        tag_ruleset = {
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "rules": [{"type": "update"}, {"type": "deletion"}],
        }
        security = {
            name: {"status": "enabled"}
            for name in (
                "advanced_security",
                "secret_scanning",
                "secret_scanning_push_protection",
                "secret_scanning_validity_checks",
            )
        }
        return self.audit["GitHubSnapshot"](
            repository={
                "id": 123456,
                "node_id": "R_repoidentity",
                "full_name": "example/archiveweaver",
                "default_branch": "main",
                "archived": False,
                "disabled": False,
                "security_and_analysis": security,
            },
            github_actions_app={
                "id": 15368,
                "slug": "github-actions",
                "html_url": "https://github.com/apps/github-actions",
                "owner": {"login": "github"},
            },
            actions_permissions={
                "enabled": True,
                "allowed_actions": "selected",
                "sha_pinning_required": True,
            },
            selected_actions={
                "github_owned_allowed": False,
                "verified_allowed": False,
                "patterns_allowed": sorted(self.audit["EXPECTED_ACTION_PATTERNS"]),
            },
            workflow_permissions={
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            },
            vulnerability_alerts=True,
            automated_security_fixes=True,
            private_vulnerability_reporting={"enabled": True},
            immutable_releases={"enabled": True, "enforced_by_owner": False},
            release_environment={
                "name": "release",
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [{"type": "User", "reviewer": {"id": 7}}],
                    }
                ],
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            },
            environment_policies=[
                {"id": 9, "name": "v*", "type": "tag", "node_id": "policy"}
            ],
            environment_variables=[
                {"name": "ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE"},
                {"name": "ARCHIVEWEAVER_RELEASE_ACTORS_JSON"},
            ],
            environment_secrets=[{"name": "ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN"}],
            rulesets=[branch_ruleset, tag_ruleset],
        )

    def results(self, snapshot: Any) -> dict[str, bool]:
        return {
            result.name: result.passed
            for result in self.audit["evaluate_snapshot"](snapshot)
        }

    def test_complete_enterprise_control_snapshot_passes_all_twelve_gates(self) -> None:
        results = self.results(self.passing_snapshot())
        self.assertEqual(len(results), 12)
        self.assertTrue(all(results.values()))

    def test_malformed_control_types_fail_closed_without_crashing(self) -> None:
        snapshot = self.passing_snapshot()
        malformed = replace(
            snapshot,
            release_environment={
                **snapshot.release_environment,
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [{"type": [], "reviewer": {"id": 7}}],
                    }
                ],
            },
            environment_policies=[
                {**snapshot.environment_policies[0], "type": []}
            ],
        )
        results = self.results(malformed)
        self.assertFalse(results["release-environment"])

    def test_scheduled_scorecard_is_not_a_required_pull_request_check(self) -> None:
        checks = self.audit["EXPECTED_STATUS_CHECKS"]
        self.assertNotIn("Scorecards analysis", checks)
        self.assertIn("ClusterFuzzLite Python", checks)
        self.assertIn("CodeQL", checks)
        self.assertIn("Dependency review", checks)

    def test_report_binds_authoritative_repository_commit_and_observation_time(self) -> None:
        snapshot = self.passing_snapshot()
        results = self.audit["evaluate_snapshot"](snapshot)
        report = self.audit["build_report"](
            "EXAMPLE/archiveweaver",
            "a" * 40,
            snapshot,
            results,
            audited_at=datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            set(report),
            {
                "api_version",
                "audited_at",
                "controls",
                "passed",
                "repository",
                "repository_id",
                "repository_node_id",
                "schema_version",
                "source_revision",
            },
        )
        self.assertEqual(report["repository"], "example/archiveweaver")
        self.assertEqual(report["repository_id"], 123456)
        self.assertEqual(report["source_revision"], "a" * 40)
        self.assertEqual(report["audited_at"], "2026-09-11T12:00:00Z")
        self.assertTrue(report["passed"])

        for repository, revision, replacement in (
            ("other/archiveweaver", "a" * 40, snapshot),
            ("example/archiveweaver", "not-a-sha", snapshot),
            (
                "example/archiveweaver",
                "a" * 40,
                replace(snapshot, repository={**snapshot.repository, "id": True}),
            ),
        ):
            with self.subTest(repository=repository, revision=revision):
                with self.assertRaises(self.audit["GitHubAuditError"]):
                    self.audit["build_report"](
                        repository,
                        revision,
                        replacement,
                        results,
                    )

        with self.assertRaises(self.audit["GitHubAuditError"]):
            self.audit["build_report"](
                "example/archiveweaver",
                [],
                snapshot,
                results,
            )

    def test_paginated_objects_must_be_complete(self) -> None:
        self.assertEqual(
            self.audit["_items"](
                {"total_count": 1, "variables": [{"name": "EXPECTED"}]},
                "variables",
            ),
            [{"name": "EXPECTED"}],
        )
        for payload in (
            {"variables": []},
            {"total_count": True, "variables": []},
            {"total_count": 2, "variables": [{"name": "TRUNCATED"}]},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(self.audit["GitHubAuditError"]):
                    self.audit["_items"](payload, "variables")

    def test_github_client_fails_closed_on_api_timeout(self) -> None:
        with patch.object(
            self.audit["subprocess"],
            "run",
            side_effect=self.audit["subprocess"].TimeoutExpired(["gh", "api"], 30),
        ), self.assertRaisesRegex(self.audit["GitHubAuditError"], "timed out"):
            self.audit["GitHubClient"]("example/archiveweaver").object(
                "repos/example/archiveweaver"
            )

    def test_github_client_fails_closed_on_excessively_nested_json(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        payload = "[" * 2000 + "0" + "]" * 2000
        with patch.object(client, "_run", return_value=payload):
            with self.assertRaisesRegex(self.audit["GitHubAuditError"], "malformed JSON"):
                client.object("repos/example/archiveweaver")
            with self.assertRaisesRegex(self.audit["GitHubAuditError"], "malformed JSON"):
                client.array("repos/example/archiveweaver/rulesets")

    def test_github_client_rejects_non_standard_json_numbers(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        for payload in (
            '{"id": NaN}',
            '{"id": 1e9999}',
            '{"id": ' + ("9" * 4301) + "}",
        ):
            with self.subTest(payload=payload[:40]), patch.object(
                client, "_run", return_value=payload
            ), self.assertRaisesRegex(
                self.audit["GitHubAuditError"], "malformed JSON"
            ):
                client.object("repos/example/archiveweaver")

    def test_github_client_rejects_duplicate_json_keys(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        with patch.object(client, "_run", return_value='{"id": 1, "id": 2}'):
            with self.assertRaisesRegex(
                self.audit["GitHubAuditError"], "malformed JSON"
            ):
                client.object("repos/example/archiveweaver")

    def test_github_client_rejects_oversized_json(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        with patch.object(client, "_run", return_value="{}"), patch.dict(
            self.audit["_load_api_json"].__globals__,
            {"MAX_API_JSON_BYTES": 1},
        ), self.assertRaisesRegex(
            self.audit["GitHubAuditError"], "oversized JSON"
        ):
            client.object("repos/example/archiveweaver")

    def test_source_revision_must_be_an_existing_verified_commit(self) -> None:
        revision = "a" * 40
        client = Mock(repository="example/archiveweaver")
        client.object.side_effect = (
            {
                "sha": revision,
                "commit": {"verification": {"verified": True}},
            },
            {"status": "ahead"},
        )
        self.audit["verify_source_commit"](client, revision, "main")
        self.assertEqual(
            client.object.call_args_list,
            [
                call(f"repos/example/archiveweaver/commits/{revision}"),
                call(f"repos/example/archiveweaver/compare/{revision}...main"),
            ],
        )

        for response in (
            {"sha": "b" * 40, "commit": {"verification": {"verified": True}}},
            {"sha": revision, "commit": {"verification": {"verified": False}}},
            {"sha": revision, "commit": {}},
        ):
            with self.subTest(response=response):
                client.reset_mock()
                client.object.side_effect = None
                client.object.return_value = response
                with self.assertRaisesRegex(
                    self.audit["GitHubAuditError"], "verified repository commit"
                ):
                    self.audit["verify_source_commit"](client, revision, "main")

        client.object.return_value = {
            "sha": revision,
            "commit": {"verification": {"verified": True}},
        }
        with self.assertRaisesRegex(
            self.audit["GitHubAuditError"], "default branch main"
        ):
            self.audit["verify_source_commit"](client, revision, "develop")

        client.object.side_effect = (
            {
                "sha": revision,
                "commit": {"verification": {"verified": True}},
            },
            {"status": "diverged"},
        )
        with self.assertRaisesRegex(
            self.audit["GitHubAuditError"], "reachable from the protected main"
        ):
            self.audit["verify_source_commit"](client, revision, "main")

    def test_collection_does_not_query_an_inapplicable_selected_actions_endpoint(self) -> None:
        class FakeClient:
            repository = "example/archiveweaver"

            def __init__(self) -> None:
                self.endpoints: list[str] = []

            def object(
                self, endpoint: str, *, allow_not_found: bool = False
            ) -> dict[str, Any] | None:
                del allow_not_found
                self.endpoints.append(endpoint)
                if endpoint.endswith("/actions/permissions"):
                    return {
                        "enabled": True,
                        "allowed_actions": "all",
                        "sha_pinning_required": False,
                    }
                if endpoint == "apps/github-actions":
                    return {
                        "id": 15368,
                        "slug": "github-actions",
                        "html_url": "https://github.com/apps/github-actions",
                        "owner": {"login": "github"},
                    }
                if endpoint.endswith("/actions/permissions/workflow"):
                    return {
                        "default_workflow_permissions": "read",
                        "can_approve_pull_request_reviews": False,
                    }
                if endpoint.endswith("/environments/release"):
                    return None
                if endpoint.endswith("/immutable-releases"):
                    return None
                if endpoint.endswith("/private-vulnerability-reporting"):
                    return {"enabled": False}
                if endpoint == "repos/example/archiveweaver":
                    return {
                        "id": 123456,
                        "node_id": "R_repoidentity",
                        "full_name": "example/archiveweaver",
                        "default_branch": "main",
                        "archived": False,
                        "disabled": False,
                    }
                self.fail_unexpected(endpoint)
                return None

            def array(self, endpoint: str) -> list[dict[str, Any]]:
                self.endpoints.append(endpoint)
                return []

            def enabled_endpoint(self, endpoint: str) -> bool:
                self.endpoints.append(endpoint)
                return False

            @staticmethod
            def fail_unexpected(endpoint: str) -> None:
                raise AssertionError(f"unexpected endpoint: {endpoint}")

        client = FakeClient()
        snapshot = self.audit["collect_snapshot"](client)
        self.assertEqual(snapshot.selected_actions, {})
        self.assertIn("apps/github-actions", client.endpoints)
        self.assertFalse(
            any(endpoint.endswith("/selected-actions") for endpoint in client.endpoints)
        )

    def test_repository_security_and_automation_controls_fail_independently(self) -> None:
        snapshot = self.passing_snapshot()
        cases = (
            (
                "repository",
                replace(snapshot, repository={**snapshot.repository, "archived": True}),
            ),
            (
                "secret-scanning",
                replace(
                    snapshot,
                    repository={
                        **snapshot.repository,
                        "security_and_analysis": {
                            **snapshot.repository["security_and_analysis"],
                            "secret_scanning_validity_checks": {"status": "disabled"},
                        },
                    },
                ),
            ),
            (
                "actions-policy",
                replace(
                    snapshot,
                    actions_permissions={
                        **snapshot.actions_permissions,
                        "sha_pinning_required": False,
                    },
                ),
            ),
            (
                "actions-allowlist",
                replace(
                    snapshot,
                    selected_actions={
                        **snapshot.selected_actions,
                        "github_owned_allowed": True,
                    },
                ),
            ),
            (
                "actions-allowlist",
                replace(
                    snapshot,
                    selected_actions={
                        **snapshot.selected_actions,
                        "patterns_allowed": [
                            *snapshot.selected_actions["patterns_allowed"],
                            snapshot.selected_actions["patterns_allowed"][0],
                        ],
                    },
                ),
            ),
            (
                "workflow-token",
                replace(
                    snapshot,
                    workflow_permissions={
                        **snapshot.workflow_permissions,
                        "can_approve_pull_request_reviews": True,
                    },
                ),
            ),
        )
        for expected_failure, candidate in cases:
            with self.subTest(expected_failure=expected_failure):
                self.assertFalse(self.results(candidate)[expected_failure])

    def test_security_feature_controls_fail_closed_when_missing(self) -> None:
        snapshot = self.passing_snapshot()
        cases = (
            ("vulnerability-alerts", replace(snapshot, vulnerability_alerts=False)),
            (
                "dependabot-security-updates",
                replace(snapshot, automated_security_fixes=False),
            ),
            (
                "private-vulnerability-reporting",
                replace(snapshot, private_vulnerability_reporting=None),
            ),
            ("immutable-releases", replace(snapshot, immutable_releases=None)),
        )
        for expected_failure, candidate in cases:
            with self.subTest(expected_failure=expected_failure):
                self.assertFalse(self.results(candidate)[expected_failure])

    def test_release_environment_requires_reviewers_exact_secret_and_tag_policy(self) -> None:
        snapshot = self.passing_snapshot()
        environment = copy.deepcopy(snapshot.release_environment)
        environment["protection_rules"][0]["prevent_self_review"] = False
        candidates = (
            replace(snapshot, release_environment=environment),
            replace(
                snapshot,
                release_environment={
                    **snapshot.release_environment,
                    "protection_rules": [
                        {
                            "type": "required_reviewers",
                            "prevent_self_review": True,
                            "reviewers": [{}],
                        }
                    ],
                },
            ),
            replace(snapshot, environment_policies=[{"name": "*", "type": "tag"}]),
            replace(snapshot, environment_policies=[{"name": "v*", "type": "branch"}]),
            replace(snapshot, environment_variables=[]),
            replace(
                snapshot,
                environment_secrets=[
                    {"name": "ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN"},
                    {"name": "UNRELATED_PRIVILEGED_SECRET"},
                ],
            ),
            replace(
                snapshot,
                environment_secrets=[
                    {"name": "ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN"},
                    {"name": "ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN"},
                ],
            ),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertFalse(self.results(candidate)["release-environment"])

        without_undocumented_type = replace(
            snapshot, environment_policies=[{"id": 9, "name": "v*"}]
        )
        self.assertTrue(self.results(without_undocumented_type)["release-environment"])

    def test_main_ruleset_requires_every_review_and_status_invariant(self) -> None:
        snapshot = self.passing_snapshot()
        branch = copy.deepcopy(snapshot.rulesets[0])
        pull_request = next(rule for rule in branch["rules"] if rule["type"] == "pull_request")
        pull_request["parameters"]["require_last_push_approval"] = False
        self.assertFalse(
            self.results(replace(snapshot, rulesets=[branch, snapshot.rulesets[1]]))[
                "main-ruleset"
            ]
        )

        branch = copy.deepcopy(snapshot.rulesets[0])
        status = next(
            rule for rule in branch["rules"] if rule["type"] == "required_status_checks"
        )
        status["parameters"]["required_status_checks"].append(
            {"context": "Additional check"}
        )
        self.assertFalse(
            self.results(replace(snapshot, rulesets=[branch, snapshot.rulesets[1]]))[
                "main-ruleset"
            ]
        )

        branch = copy.deepcopy(snapshot.rulesets[0])
        status = next(
            rule for rule in branch["rules"] if rule["type"] == "required_status_checks"
        )
        status["parameters"]["required_status_checks"].pop()
        self.assertFalse(
            self.results(replace(snapshot, rulesets=[branch, snapshot.rulesets[1]]))[
                "main-ruleset"
            ]
        )

    def test_main_ruleset_requires_checks_from_github_actions_app(self) -> None:
        snapshot = self.passing_snapshot()
        for malformed in (
            {"context": "CodeQL"},
            {"context": "CodeQL", "integration_id": None},
            {"context": "CodeQL", "integration_id": True},
            {"context": "CodeQL", "integration_id": 0},
            {"context": "CodeQL", "integration_id": "15368"},
            {"context": "CodeQL", "integration_id": 15369},
            {"context": "", "integration_id": 15368},
        ):
            with self.subTest(malformed=malformed):
                branch = copy.deepcopy(snapshot.rulesets[0])
                status = next(
                    rule
                    for rule in branch["rules"]
                    if rule["type"] == "required_status_checks"
                )
                checks = status["parameters"]["required_status_checks"]
                codeql_index = next(
                    i for i, item in enumerate(checks) if item["context"] == "CodeQL"
                )
                checks[codeql_index] = malformed
                self.assertFalse(
                    self.results(replace(snapshot, rulesets=[branch, snapshot.rulesets[1]]))[
                        "main-ruleset"
                    ]
                )

        branch = copy.deepcopy(snapshot.rulesets[0])
        status = next(
            rule for rule in branch["rules"] if rule["type"] == "required_status_checks"
        )
        status["parameters"]["required_status_checks"].append(
            {"context": "CodeQL", "integration_id": 15368}
        )
        self.assertFalse(
            self.results(replace(snapshot, rulesets=[branch, snapshot.rulesets[1]]))[
                "main-ruleset"
            ]
        )

    def test_main_ruleset_requires_authoritative_github_actions_app_identity(self) -> None:
        snapshot = self.passing_snapshot()
        for malformed in (
            None,
            [],
            {"id": 15368},
            {**snapshot.github_actions_app, "id": True},
            {**snapshot.github_actions_app, "id": 0},
            {**snapshot.github_actions_app, "id": "15368"},
            {**snapshot.github_actions_app, "id": 15369},
            {**snapshot.github_actions_app, "slug": "other-app"},
            {**snapshot.github_actions_app, "owner": {"login": "other"}},
            {**snapshot.github_actions_app, "html_url": "https://example.com"},
        ):
            with self.subTest(malformed=malformed):
                self.assertFalse(
                    self.results(replace(snapshot, github_actions_app=malformed))[
                        "main-ruleset"
                    ]
                )

    def test_rulesets_reject_bypass_exclusions_and_mutable_tags(self) -> None:
        snapshot = self.passing_snapshot()
        branch = copy.deepcopy(snapshot.rulesets[0])
        branch["bypass_actors"] = [{"actor_type": "RepositoryRole"}]
        tag = copy.deepcopy(snapshot.rulesets[1])
        tag["rules"] = [{"type": "deletion"}]
        results = self.results(replace(snapshot, rulesets=[branch, tag]))
        self.assertFalse(results["main-ruleset"])
        self.assertFalse(results["release-tag-ruleset"])

        duplicate_rule = copy.deepcopy(snapshot.rulesets[0])
        duplicate_rule["rules"].append({"type": "required_signatures"})
        self.assertFalse(
            self.results(replace(snapshot, rulesets=[duplicate_rule, snapshot.rulesets[1]]))[
                "main-ruleset"
            ]
        )

    def test_json_mode_is_machine_readable_and_exit_status_is_fail_closed(self) -> None:
        snapshot = self.passing_snapshot()
        output = io.StringIO()
        with (
            patch.object(self.audit["shutil"], "which", return_value="gh"),
            patch.dict(
                self.audit["main"].__globals__,
                {
                    "collect_snapshot": lambda _client: snapshot,
                    "verify_source_commit": lambda _client, _revision, _branch: None,
                },
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(
                self.audit["main"](
                    [
                        "--repository",
                        "example/archiveweaver",
                        "--source-revision",
                        "a" * 40,
                        "--json",
                    ]
                ),
                0,
            )
        report = json.loads(output.getvalue())
        self.assertTrue(report["passed"])
        self.assertEqual(len(report["controls"]), 12)
        self.assertEqual(report["repository_id"], 123456)
        self.assertEqual(report["source_revision"], "a" * 40)

        output = io.StringIO()
        failing = replace(snapshot, immutable_releases=None)
        with (
            patch.object(self.audit["shutil"], "which", return_value="gh"),
            patch.dict(
                self.audit["main"].__globals__,
                {"collect_snapshot": lambda _client: failing},
            ),
            patch.dict(self.audit["os"].environ, {"GITHUB_SHA": ""}, clear=False),
            redirect_stdout(output),
        ):
            self.assertEqual(
                self.audit["main"](["--repository", "example/archiveweaver"]), 1
            )
        self.assertIn("FAIL immutable-releases", output.getvalue())

    def test_invalid_repository_and_api_errors_are_distinct_audit_failures(self) -> None:
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic):
            self.assertEqual(self.audit["main"](["--repository", "../unsafe"]), 2)
        self.assertIn("invalid owner/repository slug", diagnostic.getvalue())

        diagnostic = io.StringIO()
        with patch.dict(self.audit["os"].environ, {"GITHUB_SHA": ""}, clear=False):
            with redirect_stderr(diagnostic):
                self.assertEqual(
                    self.audit["main"](
                        ["--repository", "example/archiveweaver", "--json"]
                    ),
                    2,
                )
        self.assertIn("required for JSON evidence", diagnostic.getvalue())

        diagnostic = io.StringIO()
        with (
            patch.object(self.audit["shutil"], "which", return_value="gh"),
            patch.dict(
                self.audit["main"].__globals__,
                {
                    "collect_snapshot": lambda _client: (_ for _ in ()).throw(
                        self.audit["GitHubAuditError"]("denied")
                    )
                },
            ),
            redirect_stderr(diagnostic),
        ):
            self.assertEqual(
                self.audit["main"](["--repository", "example/archiveweaver"]), 2
            )
        self.assertIn("denied", diagnostic.getvalue())

    def test_json_scanner_accepts_escaped_strings_and_nesting(self) -> None:
        payload = json.dumps({"k": "line\n\ttab\\slash\"quote", "n": [{"x": 1}]})
        self.audit["_reject_excessive_json_nesting"](payload, "endpoint")

    def test_json_client_accepts_floats_and_plain_objects(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        with patch.object(client, "_run", return_value='{"id": 1, "ratio": 1.5}'):
            value = client.object("repos/example/archiveweaver")
        self.assertEqual(value, {"id": 1, "ratio": 1.5})

        oversized_float = "0." + "1" * 4300
        with patch.object(
            client, "_run", return_value='{"value": ' + oversized_float + "}"
        ), self.assertRaisesRegex(self.audit["GitHubAuditError"], "malformed JSON"):
            client.object("repos/example/archiveweaver")

    def test_github_client_surfaces_process_and_http_failures(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        with patch.object(self.audit["subprocess"], "run", side_effect=OSError("boom")):
            with self.assertRaisesRegex(self.audit["GitHubAuditError"], "cannot execute"):
                client.object("repos/example/archiveweaver")

        with patch.object(
            self.audit["subprocess"],
            "run",
            return_value=Mock(returncode=1, stdout="", stderr="graphql: denied"),
        ), self.assertRaisesRegex(self.audit["GitHubAuditError"], "denied"):
            client.object("repos/example/archiveweaver")

        with patch.object(
            self.audit["subprocess"],
            "run",
            return_value=Mock(returncode=1, stdout="", stderr="HTTP 404: Not Found"),
        ):
            self.assertIsNone(
                client.object("repos/example/archiveweaver", allow_not_found=True)
            )
            self.assertFalse(client.enabled_endpoint("repos/example/archiveweaver"))

        with patch.object(
            self.audit["subprocess"],
            "run",
            return_value=Mock(returncode=1, stdout="", stderr=""),
        ), self.assertRaisesRegex(self.audit["GitHubAuditError"], "no diagnostic"):
            client.object("repos/example/archiveweaver")

    def test_github_client_rejects_wrong_json_shapes(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        with patch.object(client, "_run", return_value="[]"):
            with self.assertRaisesRegex(self.audit["GitHubAuditError"], "non-object"):
                client.object("repos/example/archiveweaver")
        for payload in ("{}", "[1]"):
            with self.subTest(payload=payload), patch.object(
                client, "_run", return_value=payload
            ), self.assertRaisesRegex(
                self.audit["GitHubAuditError"], "non-object array"
            ):
                client.array("repos/example/archiveweaver/rulesets")

    def test_pagination_items_handle_absent_and_malformed_arrays(self) -> None:
        self.assertEqual(self.audit["_items"](None, "variables"), [])
        with self.assertRaises(self.audit["GitHubAuditError"]):
            self.audit["_items"]({"total_count": 1, "variables": [1]}, "variables")

    def test_collection_requires_authoritative_control_responses(self) -> None:
        client = Mock(repository="example/archiveweaver")
        client.object.return_value = None
        with self.assertRaisesRegex(
            self.audit["GitHubAuditError"], "required GitHub repository control response"
        ):
            self.audit["collect_snapshot"](client)

    def test_collection_rejects_ambiguous_ruleset_pagination(self) -> None:
        client = Mock(repository="example/archiveweaver")

        def object_response(endpoint: str, *, allow_not_found: bool = False) -> Any:
            del allow_not_found
            if endpoint.endswith("/actions/permissions"):
                return {"allowed_actions": "all"}
            if endpoint.endswith(
                (
                    "/immutable-releases",
                    "/private-vulnerability-reporting",
                    "/environments/release",
                )
            ):
                return None
            return {}

        client.object.side_effect = object_response
        client.array.return_value = [{"id": index + 1} for index in range(100)]
        client.enabled_endpoint.return_value = False
        with self.assertRaisesRegex(
            self.audit["GitHubAuditError"], "pagination exceeded 100 items"
        ):
            self.audit["collect_snapshot"](client)

    def test_collection_reads_selected_actions_environment_and_rulesets(self) -> None:
        class FakeClient:
            repository = "example/archiveweaver"

            def object(self, endpoint: str, *, allow_not_found: bool = False) -> Any:
                del allow_not_found
                if endpoint == "repos/example/archiveweaver":
                    return {"id": 1, "default_branch": "main"}
                if endpoint == "apps/github-actions":
                    return {"id": 15368}
                if endpoint.endswith("/actions/permissions/workflow"):
                    return {}
                if endpoint.endswith("/actions/permissions"):
                    return {"allowed_actions": "selected"}
                if endpoint.endswith("/actions/permissions/selected-actions"):
                    return {"github_owned_allowed": False}
                if endpoint.endswith("/immutable-releases"):
                    return None
                if endpoint.endswith("/private-vulnerability-reporting"):
                    return None
                if endpoint.endswith("/environments/release"):
                    return {"name": "release"}
                if endpoint.endswith("/deployment-branch-policies?per_page=100"):
                    return {"total_count": 1, "branch_policies": [{"name": "v*"}]}
                if endpoint.endswith("/variables?per_page=100"):
                    return {"total_count": 1, "variables": [{"name": "V"}]}
                if endpoint.endswith("/secrets?per_page=100"):
                    return {"total_count": 0, "secrets": []}
                if endpoint.endswith("/rulesets/7"):
                    return {"id": 7, "target": "tag"}
                raise AssertionError(endpoint)

            def array(self, endpoint: str) -> list[dict[str, Any]]:
                return [{"id": 7}]

            def enabled_endpoint(self, endpoint: str) -> bool:
                return True

        snapshot = self.audit["collect_snapshot"](FakeClient())
        self.assertEqual(snapshot.selected_actions, {"github_owned_allowed": False})
        self.assertEqual(snapshot.environment_variables, [{"name": "V"}])
        self.assertEqual(snapshot.environment_policies, [{"name": "v*"}])
        self.assertEqual(snapshot.rulesets, [{"id": 7, "target": "tag"}])

    def test_ruleset_helpers_fail_closed_on_malformed_shapes(self) -> None:
        ref = self.audit["_ref_ruleset"]
        self.assertFalse(
            ref(
                {"target": "branch", "enforcement": "active", "conditions": []},
                "branch",
                "~DEFAULT_BRANCH",
            )
        )
        self.assertFalse(
            ref(
                {
                    "target": "branch",
                    "enforcement": "active",
                    "conditions": {"ref_name": []},
                },
                "branch",
                "~DEFAULT_BRANCH",
            )
        )
        rules = self.audit["_rules"]
        self.assertEqual(rules({"rules": "nope"}), {})
        self.assertEqual(rules({"rules": [{"type": 1}]}), {})

        branch = copy.deepcopy(self.passing_snapshot().rulesets[0])
        pull_request = next(
            rule for rule in branch["rules"] if rule["type"] == "pull_request"
        )
        pull_request["parameters"] = []
        self.assertFalse(self.audit["_branch_ruleset_passes"](branch, 15368))

        branch = copy.deepcopy(self.passing_snapshot().rulesets[0])
        status = next(
            rule for rule in branch["rules"] if rule["type"] == "required_status_checks"
        )
        status["parameters"] = []
        self.assertFalse(self.audit["_branch_ruleset_passes"](branch, 15368))

        branch = copy.deepcopy(self.passing_snapshot().rulesets[0])
        status = next(
            rule for rule in branch["rules"] if rule["type"] == "required_status_checks"
        )
        status["parameters"] = {"required_status_checks": [1]}
        self.assertFalse(self.audit["_branch_ruleset_passes"](branch, 15368))

        self.assertFalse(
            self.audit["_reviewer_rule_passes"](
                {"prevent_self_review": True, "reviewers": []}
            )
        )

    def test_release_environment_absent_or_malformed_fails_closed(self) -> None:
        snapshot = self.passing_snapshot()
        self.assertFalse(
            self.results(replace(snapshot, release_environment=None))[
                "release-environment"
            ]
        )
        malformed = replace(
            snapshot,
            release_environment={
                **snapshot.release_environment,
                "protection_rules": "nope",
            },
        )
        self.assertFalse(self.results(malformed)["release-environment"])

    def test_report_rejects_naive_or_non_datetime_observation(self) -> None:
        snapshot = self.passing_snapshot()
        results = self.audit["evaluate_snapshot"](snapshot)
        for audited_at in (datetime(2026, 1, 1), "2026-01-01"):
            with self.subTest(audited_at=audited_at):
                with self.assertRaisesRegex(self.audit["GitHubAuditError"], "timezone"):
                    self.audit["build_report"](
                        "example/archiveweaver",
                        "a" * 40,
                        snapshot,
                        results,
                        audited_at=audited_at,
                    )

    def test_main_rejects_invalid_revision_and_missing_cli(self) -> None:
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic):
            self.assertEqual(
                self.audit["main"](
                    [
                        "--repository",
                        "example/archiveweaver",
                        "--source-revision",
                        "not-a-sha",
                    ]
                ),
                2,
            )
        self.assertIn("40-character commit SHA", diagnostic.getvalue())

        diagnostic = io.StringIO()
        with (
            patch.object(self.audit["shutil"], "which", return_value=None),
            redirect_stderr(diagnostic),
        ):
            self.assertEqual(
                self.audit["main"](["--repository", "example/archiveweaver"]), 2
            )
        self.assertIn("GitHub CLI is unavailable", diagnostic.getvalue())

    def test_github_client_returns_successful_responses(self) -> None:
        client = self.audit["GitHubClient"]("example/archiveweaver")
        with patch.object(
            self.audit["subprocess"],
            "run",
            return_value=Mock(returncode=0, stdout='{"id": 1}', stderr=""),
        ):
            self.assertEqual(
                client.object("repos/example/archiveweaver"), {"id": 1}
            )
        with patch.object(client, "_run", return_value='[{"id": 7}]'):
            self.assertEqual(
                client.array("repos/example/archiveweaver/rulesets"), [{"id": 7}]
            )

    def test_collection_rejects_ruleset_with_invalid_identifier(self) -> None:
        client = Mock(repository="example/archiveweaver")

        def object_response(endpoint: str, *, allow_not_found: bool = False) -> Any:
            del allow_not_found
            if endpoint.endswith("/actions/permissions"):
                return {"allowed_actions": "all"}
            if endpoint.endswith(
                (
                    "/immutable-releases",
                    "/private-vulnerability-reporting",
                    "/environments/release",
                )
            ):
                return None
            return {}

        client.object.side_effect = object_response
        client.array.return_value = [{"id": True}]
        client.enabled_endpoint.return_value = False
        with self.assertRaisesRegex(self.audit["GitHubAuditError"], "invalid ID"):
            self.audit["collect_snapshot"](client)

    def test_module_entrypoint_invokes_main_under_main_guard(self) -> None:
        with (
            patch.object(self.audit["shutil"], "which", return_value=None),
            patch.object(
                sys, "argv", ["audit", "--repository", "example/archiveweaver"]
            ),self.assertRaises(SystemExit) as caught
        ):
            runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
