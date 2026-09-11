#!/usr/bin/env python3
"""Audit ArchiveWeaver's required GitHub production controls without mutation."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Sequence
from urllib.parse import quote


API_VERSION = "2026-03-10"
AUDIT_REPORT_SCHEMA_VERSION = 1
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
NOT_FOUND_RE = re.compile(r"\bHTTP\s+404\b", re.IGNORECASE)
EXPECTED_ACTION_PATTERNS = frozenset(
    {
        "actions/attest-build-provenance@*",
        "actions/checkout@*",
        "actions/dependency-review-action@*",
        "actions/download-artifact@*",
        "actions/setup-python@*",
        "actions/upload-artifact@*",
        "anchore/sbom-action@*",
        "anchore/scan-action@*",
        "docker/login-action@*",
        "github/codeql-action/*@*",
        "ossf/scorecard-action@*",
        "sigstore/cosign-installer@*",
        "sigstore/gh-action-sigstore-python@*",
    }
)
EXPECTED_STATUS_CHECKS = frozenset(
    {
        "Built distributions",
        "CodeQL",
        "Dependency review",
        "Python lint and types",
        "Python static analysis",
        "ansible (3.13)",
        "ansible (3.14)",
        "test (3.9)",
        "test (3.10)",
        "test (3.11)",
        "test (3.12)",
        "test (3.13)",
        "test (3.14)",
        "test (3.15)",
        "yaml-and-shell",
    }
)
REQUIRED_BRANCH_RULES = frozenset(
    {
        "deletion",
        "non_fast_forward",
        "pull_request",
        "required_linear_history",
        "required_signatures",
        "required_status_checks",
    }
)
REQUIRED_ENVIRONMENT_VARIABLES = frozenset(
    {"ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE", "ARCHIVEWEAVER_RELEASE_ACTORS_JSON"}
)
REQUIRED_ENVIRONMENT_SECRETS = frozenset({"ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN"})
MAX_API_JSON_NESTING = 128


class GitHubAuditError(RuntimeError):
    """Raised when authoritative GitHub state cannot be read safely."""


def _reject_excessive_json_nesting(payload: str, endpoint: str) -> None:
    """Reject API JSON that exceeds a bounded parser nesting depth."""
    depth = 0
    in_string = False
    escaped = False
    for character in payload:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_API_JSON_NESTING:
                raise GitHubAuditError(
                    f"GitHub returned malformed JSON for {endpoint}"
                )
        elif character in "]}" and depth:
            depth -= 1


@dataclass(frozen=True)
class ControlResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class GitHubSnapshot:
    repository: dict[str, Any]
    actions_permissions: dict[str, Any]
    selected_actions: dict[str, Any]
    workflow_permissions: dict[str, Any]
    vulnerability_alerts: bool
    automated_security_fixes: bool
    private_vulnerability_reporting: dict[str, Any] | None
    immutable_releases: dict[str, Any] | None
    release_environment: dict[str, Any] | None
    environment_policies: list[dict[str, Any]]
    environment_variables: list[dict[str, Any]]
    environment_secrets: list[dict[str, Any]]
    rulesets: list[dict[str, Any]]


class GitHubClient:
    """Small argv-only wrapper around authenticated read-only `gh api` calls."""

    def __init__(self, repository: str) -> None:
        self.repository = repository

    def _run(self, endpoint: str, *, allow_not_found: bool = False) -> str | None:
        command = [
            "gh",
            "api",
            endpoint,
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
        ]
        try:
            completed = subprocess.run(  # nosec B603
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitHubAuditError(
                f"GitHub API audit timed out for {endpoint}"
            ) from exc
        except OSError as exc:
            raise GitHubAuditError(f"cannot execute the GitHub CLI: {exc}") from exc
        if completed.returncode == 0:
            return completed.stdout
        diagnostic = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        if allow_not_found and NOT_FOUND_RE.search(diagnostic):
            return None
        raise GitHubAuditError(f"GitHub API audit failed for {endpoint}: {diagnostic}")

    def object(self, endpoint: str, *, allow_not_found: bool = False) -> dict[str, Any] | None:
        raw = self._run(endpoint, allow_not_found=allow_not_found)
        if raw is None:
            return None
        _reject_excessive_json_nesting(raw, endpoint)
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise GitHubAuditError(f"GitHub returned malformed JSON for {endpoint}") from exc
        if not isinstance(value, dict):
            raise GitHubAuditError(f"GitHub returned a non-object for {endpoint}")
        return value

    def array(self, endpoint: str) -> list[dict[str, Any]]:
        raw = self._run(endpoint)
        if raw is None:  # pragma: no cover - impossible without allow_not_found
            raise GitHubAuditError(f"GitHub returned no response for {endpoint}")
        _reject_excessive_json_nesting(raw, endpoint)
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise GitHubAuditError(f"GitHub returned malformed JSON for {endpoint}") from exc
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise GitHubAuditError(f"GitHub returned a non-object array for {endpoint}")
        return value

    def enabled_endpoint(self, endpoint: str) -> bool:
        return self._run(endpoint, allow_not_found=True) is not None


def _items(payload: dict[str, Any] | None, key: str) -> list[dict[str, Any]]:
    if payload is None:
        return []
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise GitHubAuditError(f"GitHub returned malformed {key} data")
    total_count = payload.get("total_count")
    if (
        isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count < 0
        or total_count != len(value)
    ):
        raise GitHubAuditError(
            f"GitHub returned incomplete or malformed {key} pagination data"
        )
    return value


def collect_snapshot(client: GitHubClient) -> GitHubSnapshot:
    repository = client.object(f"repos/{client.repository}")
    actions = client.object(f"repos/{client.repository}/actions/permissions")
    workflow = client.object(f"repos/{client.repository}/actions/permissions/workflow")
    if repository is None or actions is None or workflow is None:
        raise GitHubAuditError("a required GitHub repository control response was absent")
    selected: dict[str, Any] = {}
    if actions.get("allowed_actions") == "selected":
        selected_response = client.object(
            f"repos/{client.repository}/actions/permissions/selected-actions"
        )
        if selected_response is None:  # pragma: no cover - request does not allow 404
            raise GitHubAuditError("the selected Actions policy response was absent")
        selected = selected_response

    immutable = client.object(
        f"repos/{client.repository}/immutable-releases", allow_not_found=True
    )
    private_reporting = client.object(
        f"repos/{client.repository}/private-vulnerability-reporting",
        allow_not_found=True,
    )
    environment_name = quote("release", safe="")
    environment = client.object(
        f"repos/{client.repository}/environments/{environment_name}",
        allow_not_found=True,
    )
    environment_policies: list[dict[str, Any]] = []
    environment_variables: list[dict[str, Any]] = []
    environment_secrets: list[dict[str, Any]] = []
    if environment is not None:
        environment_policies = _items(
            client.object(
                f"repos/{client.repository}/environments/{environment_name}/"
                "deployment-branch-policies?per_page=100"
            ),
            "branch_policies",
        )
        environment_variables = _items(
            client.object(
                f"repos/{client.repository}/environments/{environment_name}/variables?per_page=100"
            ),
            "variables",
        )
        environment_secrets = _items(
            client.object(
                f"repos/{client.repository}/environments/{environment_name}/secrets?per_page=100"
            ),
            "secrets",
        )

    summaries = client.array(
        f"repos/{client.repository}/rulesets?includes_parents=true&per_page=100"
    )
    if len(summaries) == 100:
        raise GitHubAuditError("ruleset audit is ambiguous because pagination exceeded 100 items")
    rulesets: list[dict[str, Any]] = []
    for summary in summaries:
        ruleset_id = summary.get("id")
        if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
            raise GitHubAuditError("GitHub returned a ruleset with an invalid ID")
        ruleset = client.object(f"repos/{client.repository}/rulesets/{ruleset_id}")
        if ruleset is None:  # pragma: no cover - object call does not allow 404
            raise GitHubAuditError("GitHub ruleset disappeared during the audit")
        rulesets.append(ruleset)

    return GitHubSnapshot(
        repository=repository,
        actions_permissions=actions,
        selected_actions=selected,
        workflow_permissions=workflow,
        vulnerability_alerts=client.enabled_endpoint(
            f"repos/{client.repository}/vulnerability-alerts"
        ),
        automated_security_fixes=client.enabled_endpoint(
            f"repos/{client.repository}/automated-security-fixes"
        ),
        private_vulnerability_reporting=private_reporting,
        immutable_releases=immutable,
        release_environment=environment,
        environment_policies=environment_policies,
        environment_variables=environment_variables,
        environment_secrets=environment_secrets,
        rulesets=rulesets,
    )


def verify_source_commit(
    client: GitHubClient, source_revision: str, default_branch: Any
) -> None:
    """Require an existing verified source commit reachable from protected main."""
    commit = client.object(f"repos/{client.repository}/commits/{source_revision}")
    commit_data = commit.get("commit") if isinstance(commit, dict) else None
    verification = (
        commit_data.get("verification") if isinstance(commit_data, dict) else None
    )
    if (
        not isinstance(commit, dict)
        or commit.get("sha") != source_revision
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
    ):
        raise GitHubAuditError(
            "source revision must identify an existing GitHub-verified repository commit"
        )
    if default_branch != "main":
        raise GitHubAuditError("source revision cannot be bound without default branch main")
    comparison = client.object(
        f"repos/{client.repository}/compare/{source_revision}...main"
    )
    if (
        not isinstance(comparison, dict)
        or comparison.get("status") not in {"ahead", "identical"}
    ):
        raise GitHubAuditError(
            "source revision must be reachable from the protected main branch"
        )


def _ref_ruleset(ruleset: dict[str, Any], target: str, include: str) -> bool:
    if ruleset.get("target") != target or ruleset.get("enforcement") != "active":
        return False
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    includes = ref_name.get("include")
    excludes = ref_name.get("exclude")
    return (
        isinstance(includes, list)
        and include in includes
        and isinstance(excludes, list)
        and not excludes
        and ruleset.get("bypass_actors") == []
    )


def _rules(ruleset: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_rules = ruleset.get("rules")
    if not isinstance(raw_rules, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for rule in raw_rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            return {}
        if rule["type"] in result:
            return {}
        result[rule["type"]] = rule
    return result


def _branch_ruleset_passes(ruleset: dict[str, Any]) -> bool:
    if not (
        _ref_ruleset(ruleset, "branch", "~DEFAULT_BRANCH")
        or _ref_ruleset(ruleset, "branch", "refs/heads/main")
    ):
        return False
    rules = _rules(ruleset)
    if not REQUIRED_BRANCH_RULES.issubset(rules):
        return False
    pull_request = rules["pull_request"].get("parameters")
    if not isinstance(pull_request, dict):
        return False
    review_count = pull_request.get("required_approving_review_count")
    if (
        isinstance(review_count, bool)
        or not isinstance(review_count, int)
        or review_count < 1
        or pull_request.get("dismiss_stale_reviews_on_push") is not True
        or pull_request.get("require_code_owner_review") is not True
        or pull_request.get("require_last_push_approval") is not True
        or pull_request.get("required_review_thread_resolution") is not True
    ):
        return False
    status = rules["required_status_checks"].get("parameters")
    if not isinstance(status, dict):
        return False
    checks = status.get("required_status_checks")
    if not isinstance(checks, list) or any(not isinstance(item, dict) for item in checks):
        return False
    contexts = {
        item.get("context") for item in checks if isinstance(item.get("context"), str)
    }
    return (
        status.get("strict_required_status_checks_policy") is True
        and status.get("do_not_enforce_on_create") is False
        and EXPECTED_STATUS_CHECKS.issubset(contexts)
    )


def _tag_ruleset_passes(ruleset: dict[str, Any]) -> bool:
    if not _ref_ruleset(ruleset, "tag", "refs/tags/v*"):
        return False
    rules = _rules(ruleset)
    return {"deletion", "update"}.issubset(rules)


def _names(items: list[dict[str, Any]]) -> set[str] | None:
    result: set[str] = set()
    for item in items:
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or name in result:
            return None
        result.add(name)
    return result


def _reviewer_rule_passes(rule: dict[str, Any]) -> bool:
    reviewers = rule.get("reviewers")
    if rule.get("prevent_self_review") is not True or not isinstance(reviewers, list):
        return False
    if not reviewers:
        return False
    for entry in reviewers:
        reviewer = entry.get("reviewer") if isinstance(entry, dict) else None
        reviewer_id = reviewer.get("id") if isinstance(reviewer, dict) else None
        if (
            not isinstance(entry, dict)
            or entry.get("type") not in {"User", "Team"}
            or isinstance(reviewer_id, bool)
            or not isinstance(reviewer_id, int)
            or reviewer_id <= 0
        ):
            return False
    return True


def evaluate_snapshot(snapshot: GitHubSnapshot) -> list[ControlResult]:
    repository_id = snapshot.repository.get("id")
    repository_ok = (
        isinstance(snapshot.repository.get("full_name"), str)
        and REPOSITORY_RE.fullmatch(snapshot.repository["full_name"]) is not None
        and isinstance(repository_id, int)
        and not isinstance(repository_id, bool)
        and repository_id > 0
        and isinstance(snapshot.repository.get("node_id"), str)
        and bool(snapshot.repository["node_id"].strip())
        and snapshot.repository.get("default_branch") == "main"
        and snapshot.repository.get("archived") is False
        and snapshot.repository.get("disabled") is False
    )
    security = snapshot.repository.get("security_and_analysis")
    security_ok = isinstance(security, dict) and all(
        isinstance(security.get(name), dict)
        and security[name].get("status") == "enabled"
        for name in (
            "advanced_security",
            "secret_scanning",
            "secret_scanning_push_protection",
            "secret_scanning_validity_checks",
        )
    )
    actions_ok = (
        snapshot.actions_permissions.get("enabled") is True
        and snapshot.actions_permissions.get("allowed_actions") == "selected"
        and snapshot.actions_permissions.get("sha_pinning_required") is True
    )
    patterns = snapshot.selected_actions.get("patterns_allowed")
    patterns_ok = (
        snapshot.selected_actions.get("github_owned_allowed") is False
        and snapshot.selected_actions.get("verified_allowed") is False
        and isinstance(patterns, list)
        and all(isinstance(item, str) for item in patterns)
        and len(patterns) == len(set(patterns))
        and set(patterns) == EXPECTED_ACTION_PATTERNS
    )
    workflow_ok = (
        snapshot.workflow_permissions.get("default_workflow_permissions") == "read"
        and snapshot.workflow_permissions.get("can_approve_pull_request_reviews") is False
    )
    immutable_ok = (
        snapshot.immutable_releases is not None
        and snapshot.immutable_releases.get("enabled") is True
        and isinstance(snapshot.immutable_releases.get("enforced_by_owner"), bool)
    )
    private_reporting_ok = (
        snapshot.private_vulnerability_reporting is not None
        and snapshot.private_vulnerability_reporting.get("enabled") is True
    )

    environment = snapshot.release_environment
    required_reviewers = []
    deployment_policy: Any = None
    if environment is not None:
        protection_rules = environment.get("protection_rules")
        if isinstance(protection_rules, list):
            required_reviewers = [
                rule
                for rule in protection_rules
                if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
            ]
        deployment_policy = environment.get("deployment_branch_policy")
    reviewers_ok = any(_reviewer_rule_passes(rule) for rule in required_reviewers)
    custom_policy_ok = (
        isinstance(deployment_policy, dict)
        and deployment_policy.get("protected_branches") is False
        and deployment_policy.get("custom_branch_policies") is True
        and len(snapshot.environment_policies) == 1
        and snapshot.environment_policies[0].get("name") == "v*"
        # GitHub's documented list/get response currently omits the policy type.
        # Reject an explicit non-tag value, but accept omission and require the
        # release workflow's successful tag deployment as runtime proof.
        and snapshot.environment_policies[0].get("type") in {None, "tag"}
    )
    variable_names = _names(snapshot.environment_variables)
    secret_names = _names(snapshot.environment_secrets)
    variables_ok = (
        variable_names is not None
        and REQUIRED_ENVIRONMENT_VARIABLES.issubset(variable_names)
    )
    secrets_ok = (
        secret_names is not None
        and frozenset(secret_names) == REQUIRED_ENVIRONMENT_SECRETS
    )
    environment_ok = (
        environment is not None
        and environment.get("name") == "release"
        and reviewers_ok
        and custom_policy_ok
        and variables_ok
        and secrets_ok
    )

    branch_ok = any(_branch_ruleset_passes(ruleset) for ruleset in snapshot.rulesets)
    tag_ok = any(_tag_ruleset_passes(ruleset) for ruleset in snapshot.rulesets)
    return [
        ControlResult("repository", repository_ok, "active repository with default branch main"),
        ControlResult(
            "secret-scanning",
            security_ok,
            "advanced security, secret scanning, push protection, and validity checks",
        ),
        ControlResult(
            "actions-policy", actions_ok, "selected Actions only with full-SHA enforcement"
        ),
        ControlResult(
            "actions-allowlist", patterns_ok, "exact reviewed action allowlist"
        ),
        ControlResult(
            "workflow-token", workflow_ok, "read-only default token without PR approval"
        ),
        ControlResult(
            "vulnerability-alerts", snapshot.vulnerability_alerts, "dependency alerts enabled"
        ),
        ControlResult(
            "dependabot-security-updates",
            snapshot.automated_security_fixes,
            "automatic security fixes enabled",
        ),
        ControlResult(
            "private-vulnerability-reporting",
            private_reporting_ok,
            "private reporting enabled",
        ),
        ControlResult("immutable-releases", immutable_ok, "future releases are immutable"),
        ControlResult(
            "release-environment",
            environment_ok,
            "reviewer, self-review prevention, v* policy, variables, and sole secret",
        ),
        ControlResult(
            "main-ruleset",
            branch_ok,
            "active no-bypass ruleset with reviews, signatures, history, and all checks",
        ),
        ControlResult(
            "release-tag-ruleset",
            tag_ok,
            "active no-bypass v* ruleset blocks update and deletion",
        ),
    ]


def build_report(
    repository: str,
    source_revision: str,
    snapshot: GitHubSnapshot,
    results: list[ControlResult],
    *,
    audited_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a source-bound, repository-identity-bound audit certificate."""
    canonical_repository = snapshot.repository.get("full_name")
    repository_id = snapshot.repository.get("id")
    repository_node_id = snapshot.repository.get("node_id")
    if (
        not isinstance(canonical_repository, str)
        or REPOSITORY_RE.fullmatch(canonical_repository) is None
        or canonical_repository.casefold() != repository.casefold()
        or isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or repository_id <= 0
        or not isinstance(repository_node_id, str)
        or not repository_node_id.strip()
    ):
        raise GitHubAuditError(
            "the authoritative repository identity does not match the requested repository"
        )
    if SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise GitHubAuditError("source revision must be a lowercase 40-character commit SHA")
    observed = audited_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise GitHubAuditError("audit timestamp must include a timezone")
    observed_utc = observed.astimezone(timezone.utc)
    return {
        "schema_version": AUDIT_REPORT_SCHEMA_VERSION,
        "api_version": API_VERSION,
        "audited_at": observed_utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "repository": canonical_repository,
        "repository_id": repository_id,
        "repository_node_id": repository_node_id,
        "source_revision": source_revision,
        "passed": all(result.passed for result in results),
        "controls": [asdict(result) for result in results],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--source-revision", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = args.repository or ""
    parts = repository.split("/", maxsplit=1)
    if not REPOSITORY_RE.fullmatch(repository) or any(part in {".", ".."} for part in parts):
        print("GitHub production-control audit error: invalid owner/repository slug", file=sys.stderr)
        return 2
    source_revision = args.source_revision or ""
    if source_revision and SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        print(
            "GitHub production-control audit error: source revision must be a lowercase "
            "40-character commit SHA",
            file=sys.stderr,
        )
        return 2
    if args.as_json and not source_revision:
        print(
            "GitHub production-control audit error: --source-revision or GITHUB_SHA is "
            "required for JSON evidence",
            file=sys.stderr,
        )
        return 2
    if shutil.which("gh") is None:
        print("GitHub production-control audit error: GitHub CLI is unavailable", file=sys.stderr)
        return 2
    try:
        client = GitHubClient(repository)
        snapshot = collect_snapshot(client)
        if source_revision:
            verify_source_commit(
                client, source_revision, snapshot.repository.get("default_branch")
            )
        results = evaluate_snapshot(snapshot)
        report = (
            build_report(repository, source_revision, snapshot, results)
            if args.as_json
            else None
        )
    except GitHubAuditError as exc:
        print(f"GitHub production-control audit error: {exc}", file=sys.stderr)
        return 2

    passed = all(result.passed for result in results)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in results:
            print(f"{'PASS' if result.passed else 'FAIL'} {result.name}: {result.detail}")
        print(
            f"GitHub production controls: passed={sum(item.passed for item in results)}/"
            f"{len(results)} repository={repository}"
        )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
