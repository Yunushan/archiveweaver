#!/usr/bin/env python3
"""Validate the controller-neutral premium operating contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by the controller bootstrap
    raise SystemExit("PyYAML is required to validate the controller contract") from exc


CONTRACT_PATH = Path(__file__).resolve().parents[1] / "deploy" / "ansible" / "controller" / "workflow.yml"
HEX_DIGEST = r"[0-9a-f]{64}"
TEMPLATE_DIGEST = "sha256:REPLACE_WITH_64_HEX_DIGEST"
REQUIRED_WORKFLOW_ORDER = [
    "source-integrity",
    "catalog-and-tests",
    "ansible-quality",
    "staging-preview",
    "product-certification",
    "failure-domain-drill",
    "backup-and-restore-gate",
    "readiness",
    "production-approval",
    "production-apply",
    "production-post-apply-verify",
    "production-verify",
    "production-repair-approval",
    "production-repair",
    "production-rollback-approval",
    "production-rollback",
]
REQUIRED_WORKFLOW_DEPENDENCIES = {
    "source-integrity": [],
    "catalog-and-tests": ["source-integrity"],
    "ansible-quality": ["catalog-and-tests"],
    "staging-preview": ["ansible-quality"],
    "product-certification": ["staging-preview"],
    "failure-domain-drill": ["product-certification"],
    "backup-and-restore-gate": ["failure-domain-drill"],
    "readiness": ["backup-and-restore-gate"],
    "production-approval": ["readiness"],
    "production-apply": ["production-approval"],
    "production-post-apply-verify": ["production-apply"],
    "production-verify": ["readiness"],
    "production-repair-approval": ["readiness"],
    "production-repair": ["production-repair-approval"],
    "production-rollback-approval": ["readiness"],
    "production-rollback": ["production-rollback-approval"],
}
PRODUCTION_WORKFLOWS = {
    "production-apply",
    "production-post-apply-verify",
    "production-verify",
    "production-repair",
    "production-rollback",
}
SOURCE_GATED_WORKFLOWS = PRODUCTION_WORKFLOWS | {
    "product-certification",
    "failure-domain-drill",
    "backup-and-restore-gate",
    "readiness",
}
SOURCE_ENVIRONMENT = [
    "ARCHIVEWEAVER_IMMUTABLE_REF",
    "ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS",
]
OPERATIONAL_ENVIRONMENT = SOURCE_ENVIRONMENT + ["ARCHIVEWEAVER_READINESS_MANIFEST_SHA256"]
WORKFLOW_BINDING_KEYS = {
    "production-apply": "production_apply",
    "production-post-apply-verify": "production_verification",
    "production-verify": "production_verification",
    "production-repair": "production_repair",
    "production-rollback": "production_rollback",
}
REQUIRED_RBAC_KEYS = {
    "project_readers",
    "staging_runner",
    "production_runner",
    "production_approvers",
    "evidence_readers",
}
REQUIRED_RUNTIME_BINDINGS = {
    "production_verification": {
        "archiveweaver_release",
        "archiveweaver_change_id",
        "archiveweaver_operator",
        "archiveweaver_fixture_set",
        "archiveweaver_evidence_environment",
        "archiveweaver_evidence_publish_enabled",
        "archiveweaver_evidence_publish_command",
        "archiveweaver_evidence_verify_command",
        "archiveweaver_evidence_publish_command_sha256",
        "archiveweaver_evidence_verify_command_sha256",
        "archiveweaver_evidence_retention_days",
        "archiveweaver_evidence_immutable",
        "archiveweaver_evidence_access_logged",
        "archiveweaver_topology_design_approved",
        "archiveweaver_single_node_production_approved",
        "archiveweaver_provider_bundle_sha256",
        "archiveweaver_product_stack_sha256",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
        "archiveweaver_health_url",
        "archiveweaver_execution_environment_digest",
    },
    "production_apply": {
        "archiveweaver_release",
        "archiveweaver_change_id",
        "archiveweaver_approval_ticket",
        "archiveweaver_backup_verified",
        "archiveweaver_release_manifest_verified",
        "archiveweaver_product_stack_ready",
        "archiveweaver_topology_design_approved",
        "archiveweaver_single_node_production_approved",
        "archiveweaver_provider_bundle_sha256",
        "archiveweaver_product_stack_sha256",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
        "archiveweaver_health_url",
        "archiveweaver_observe_enabled",
        "archiveweaver_check_command",
        "archiveweaver_check_command_sha256",
        "archiveweaver_check_interval",
        "archiveweaver_execution_environment_digest",
    },
    "production_repair": {
        "archiveweaver_release",
        "archiveweaver_change_id",
        "archiveweaver_approval_ticket",
        "archiveweaver_backup_verified",
        "archiveweaver_release_manifest_verified",
        "archiveweaver_product_stack_ready",
        "archiveweaver_operator",
        "archiveweaver_fixture_set",
        "archiveweaver_evidence_publish_enabled",
        "archiveweaver_evidence_publish_command",
        "archiveweaver_evidence_verify_command",
        "archiveweaver_evidence_publish_command_sha256",
        "archiveweaver_evidence_verify_command_sha256",
        "archiveweaver_evidence_retention_days",
        "archiveweaver_evidence_immutable",
        "archiveweaver_evidence_access_logged",
        "archiveweaver_topology_design_approved",
        "archiveweaver_single_node_production_approved",
        "archiveweaver_provider_bundle_sha256",
        "archiveweaver_product_stack_sha256",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
        "archiveweaver_health_url",
        "archiveweaver_execution_environment_digest",
    },
    "production_rollback": {
        "archiveweaver_release",
        "archiveweaver_change_id",
        "archiveweaver_rollback_change_id",
        "archiveweaver_rollback_environment",
        "archiveweaver_rollback_release",
        "archiveweaver_rollback_artifact_digest",
        "archiveweaver_rollback_command",
        "archiveweaver_rollback_approval_ticket",
        "archiveweaver_rollback_backup_verified",
        "archiveweaver_rollback_verify_command",
        "archiveweaver_rollback_command_sha256",
        "archiveweaver_rollback_verify_command_sha256",
        "archiveweaver_rollback_release_manifest_verified",
        "archiveweaver_rollback_product_stack_ready",
        "archiveweaver_operator",
        "archiveweaver_fixture_set",
        "archiveweaver_evidence_environment",
        "archiveweaver_evidence_publish_enabled",
        "archiveweaver_evidence_publish_command",
        "archiveweaver_evidence_verify_command",
        "archiveweaver_evidence_publish_command_sha256",
        "archiveweaver_evidence_verify_command_sha256",
        "archiveweaver_evidence_retention_days",
        "archiveweaver_evidence_immutable",
        "archiveweaver_evidence_access_logged",
        "archiveweaver_topology_design_approved",
        "archiveweaver_single_node_production_approved",
        "archiveweaver_provider_bundle_sha256",
        "archiveweaver_product_stack_sha256",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
        "archiveweaver_health_url",
        "archiveweaver_execution_environment_digest",
    },
    "readiness": {
        "ARCHIVEWEAVER_IMMUTABLE_REF",
        "ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS",
        "ARCHIVEWEAVER_READINESS_MANIFEST_SHA256",
    },
}
REQUIRED_NONPRODUCTION_EXTRA_VARS = {
    "product-certification": {
        "archiveweaver_release",
        "archiveweaver_certification_change_id",
        "archiveweaver_certification_operator",
        "archiveweaver_certification_fixture_set",
        "archiveweaver_certification_tests",
        "archiveweaver_evidence_environment",
        "archiveweaver_evidence_publish_enabled",
        "archiveweaver_evidence_publish_command",
        "archiveweaver_evidence_verify_command",
        "archiveweaver_evidence_publish_command_sha256",
        "archiveweaver_evidence_verify_command_sha256",
        "archiveweaver_evidence_retention_days",
        "archiveweaver_evidence_immutable",
        "archiveweaver_evidence_access_logged",
        "archiveweaver_execution_environment_digest",
    },
    "failure-domain-drill": {
        "archiveweaver_release",
        "archiveweaver_failure_change_id",
        "archiveweaver_operator",
        "archiveweaver_fixture_set",
        "archiveweaver_failure_tests",
        "archiveweaver_evidence_environment",
        "archiveweaver_evidence_publish_enabled",
        "archiveweaver_evidence_publish_command",
        "archiveweaver_evidence_verify_command",
        "archiveweaver_evidence_publish_command_sha256",
        "archiveweaver_evidence_verify_command_sha256",
        "archiveweaver_evidence_retention_days",
        "archiveweaver_evidence_immutable",
        "archiveweaver_evidence_access_logged",
        "archiveweaver_execution_environment_digest",
    },
    "backup-and-restore-gate": {
        "archiveweaver_release",
        "archiveweaver_restore_change_id",
        "archiveweaver_operator",
        "archiveweaver_fixture_set",
        "archiveweaver_restore_source",
        "archiveweaver_restore_command",
        "archiveweaver_fixity_command",
        "archiveweaver_restore_command_sha256",
        "archiveweaver_fixity_command_sha256",
        "archiveweaver_evidence_environment",
        "archiveweaver_evidence_publish_enabled",
        "archiveweaver_evidence_publish_command",
        "archiveweaver_evidence_verify_command",
        "archiveweaver_evidence_publish_command_sha256",
        "archiveweaver_evidence_verify_command_sha256",
        "archiveweaver_evidence_retention_days",
        "archiveweaver_evidence_immutable",
        "archiveweaver_evidence_access_logged",
        "archiveweaver_execution_environment_digest",
    },
}
REQUIRED_STAGING_PREVIEW_EXTRA_VARS = {
    "archiveweaver_solution_id",
    "archiveweaver_release",
    "archiveweaver_os_id",
    "archiveweaver_runtime",
    "archiveweaver_change_id",
    "archiveweaver_kustomize_path",
    "archiveweaver_kustomize_bundle_sha256",
    "archiveweaver_kubeconfig",
    "archiveweaver_health_url",
    "archiveweaver_execution_environment_digest",
}
REQUIRED_STAGING_PREVIEW_EXTRA_VARS_BY_RUNTIME = {
    "raw": {
        "archiveweaver_exec_start",
        "archiveweaver_provider_bundle_sha256",
    },
    "podman-quadlet": {
        "archiveweaver_image",
        "archiveweaver_provider_bundle_sha256",
    },
    "docker": {
        "archiveweaver_compose_path",
        "archiveweaver_product_stack_sha256",
    },
    "docker-swarm": {
        "archiveweaver_compose_path",
        "archiveweaver_product_stack_sha256",
    },
    "k3s": {
        "archiveweaver_kustomize_path",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
    },
    "rke2": {
        "archiveweaver_kustomize_path",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
    },
    "k0s": {
        "archiveweaver_kustomize_path",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
    },
    "microk8s": {
        "archiveweaver_kustomize_path",
        "archiveweaver_kustomize_bundle_sha256",
        "archiveweaver_kubeconfig",
    },
}
UNSUPPORTED_STAGING_PREVIEW_RUNTIMES = {"pacemaker"}


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate YAML mapping keys instead of silently choosing one."""


def _construct_unique_mapping(loader: UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _mapping(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path} must be a mapping")
        return {}
    return value


def _require_mapping_keys(value: dict[str, Any], keys: set[str], path: str, errors: list[str]) -> None:
    missing = sorted(key for key in keys if key not in value)
    errors.extend(f"{path}.{key} is required" for key in missing)


def _require_list_contains(value: Any, required: set[str], path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{path} must be a list of strings")
        return
    missing = sorted(required - set(value))
    errors.extend(f"{path} is missing required binding {item}" for item in missing)


def _workflow_map(contract: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    raw = contract.get("workflow")
    if not isinstance(raw, list):
        errors.append("workflow must be a list")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(f"workflow[{index}] must be a mapping")
            continue
        workflow_id = item.get("id")
        if not isinstance(workflow_id, str) or not workflow_id:
            errors.append(f"workflow[{index}].id must be a non-empty string")
            continue
        if workflow_id in result:
            errors.append(f"workflow contains duplicate id {workflow_id}")
        else:
            result[workflow_id] = item
    actual_order = list(result)
    if actual_order != REQUIRED_WORKFLOW_ORDER:
        errors.append(
            "workflow order must be "
            + " -> ".join(REQUIRED_WORKFLOW_ORDER)
            + f"; got {' -> '.join(actual_order)}"
        )
    return result


def _validate_workflow_dependencies(
    workflows: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    workflow_order = {workflow_id: index for index, workflow_id in enumerate(REQUIRED_WORKFLOW_ORDER)}
    for workflow_id, required in REQUIRED_WORKFLOW_DEPENDENCIES.items():
        item = workflows.get(workflow_id)
        if item is None:
            continue
        actual = item.get("depends_on")
        if actual != required:
            errors.append(
                f"workflow.{workflow_id}.depends_on must be "
                + ("[]" if not required else "[" + ", ".join(required) + "]")
            )
            continue
        for dependency in actual:
            if dependency not in workflow_order:
                errors.append(f"workflow.{workflow_id}.depends_on references unknown workflow {dependency}")
            elif workflow_order[dependency] >= workflow_order[workflow_id]:
                errors.append(f"workflow.{workflow_id}.depends_on must reference an earlier workflow")


def _required_extra_vars(
    workflows: dict[str, dict[str, Any]],
    workflow_id: str,
    required: set[str],
    errors: list[str],
) -> None:
    item = workflows.get(workflow_id)
    if item is None:
        return
    _require_list_contains(item.get("required_extra_vars"), required, f"workflow.{workflow_id}.required_extra_vars", errors)


def _required_extra_vars_by_runtime(
    workflows: dict[str, dict[str, Any]],
    workflow_id: str,
    required_by_runtime: dict[str, set[str]],
    unsupported_runtimes: set[str],
    errors: list[str],
) -> None:
    item = workflows.get(workflow_id)
    if item is None:
        return
    raw = item.get("required_extra_vars_by_runtime")
    if not isinstance(raw, dict):
        errors.append(f"workflow.{workflow_id}.required_extra_vars_by_runtime must be a mapping")
        return
    for runtime, required in required_by_runtime.items():
        _require_list_contains(
            raw.get(runtime),
            required,
            f"workflow.{workflow_id}.required_extra_vars_by_runtime.{runtime}",
            errors,
        )
    actual_unsupported = raw.get("unsupported_runtimes")
    if actual_unsupported is not None:
        if not isinstance(actual_unsupported, list) or not all(isinstance(value, str) for value in actual_unsupported):
            errors.append(f"workflow.{workflow_id}.required_extra_vars_by_runtime.unsupported_runtimes must be a list of strings")
        elif set(actual_unsupported) != unsupported_runtimes:
            errors.append(
                f"workflow.{workflow_id}.required_extra_vars_by_runtime.unsupported_runtimes must be "
                + ", ".join(sorted(unsupported_runtimes))
            )
    else:
        errors.append(f"workflow.{workflow_id}.required_extra_vars_by_runtime.unsupported_runtimes must be declared")
    allowed = set(required_by_runtime) | {"unsupported_runtimes"}
    extra = sorted(set(raw) - allowed)
    errors.extend(
        f"workflow.{workflow_id}.required_extra_vars_by_runtime contains unknown runtime {runtime}"
        for runtime in extra
    )


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            keys.append(str(key).lower())
            keys.extend(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.extend(_walk_keys(child))
    return keys


def validate(contract: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(contract, dict):
        return ["controller contract must contain a YAML mapping"]

    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if contract.get("kind") != "controller-workflow-contract":
        errors.append("kind must be controller-workflow-contract")
    if not isinstance(contract.get("name"), str) or not contract["name"]:
        errors.append("name must be a non-empty string")

    project = _mapping(contract.get("project"), "project", errors)
    for key, expected in (
        ("content_signature_required", True),
        ("immutable_ref_env", "ARCHIVEWEAVER_IMMUTABLE_REF"),
        ("trusted_signer_env", "ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS"),
        ("readiness_manifest_digest_env", "ARCHIVEWEAVER_READINESS_MANIFEST_SHA256"),
        ("source_verification", "signed-commit-and-clean-checkout"),
    ):
        if project.get(key) != expected:
            errors.append(f"project.{key} must be {expected!r}")

    execution_environment = _mapping(contract.get("execution_environment"), "execution_environment", errors)
    image = execution_environment.get("image")
    digest = execution_environment.get("digest")
    if not isinstance(image, str) or "@sha256:" not in image:
        errors.append("execution_environment.image must be an OCI digest reference")
    elif not (re.search(r"@sha256:" + HEX_DIGEST + r"$", image) or image.endswith("@sha256:REPLACE_WITH_64_HEX_DIGEST")):
        errors.append("execution_environment.image must end in a full SHA-256 digest")
    if not isinstance(digest, str) or not (re.fullmatch(r"sha256:" + HEX_DIGEST, digest) or digest == TEMPLATE_DIGEST):
        errors.append("execution_environment.digest must be a SHA-256 digest or the explicit template binding")
    if isinstance(image, str) and isinstance(digest, str) and "@sha256:" in image and not image.endswith("REPLACE_WITH_64_HEX_DIGEST") and digest != "sha256:" + image.rsplit("@sha256:", 1)[1]:
        errors.append("execution_environment.digest must match execution_environment.image")
    for key in ("controller_identity_env", "ansible_core", "ansible_lint"):
        if key not in execution_environment:
            errors.append(f"execution_environment.{key} is required")
    if execution_environment.get("controller_identity_env") != "ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST":
        errors.append("execution_environment.controller_identity_env is not the trusted digest binding")
    for key in ("ansible_core", "ansible_lint"):
        if key in execution_environment and (not isinstance(execution_environment[key], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", execution_environment[key])):
            errors.append(f"execution_environment.{key} must be pinned to a semantic version")

    rbac = _mapping(contract.get("rbac"), "rbac", errors)
    _require_mapping_keys(rbac, REQUIRED_RBAC_KEYS, "rbac", errors)
    concurrency = _mapping(contract.get("concurrency"), "concurrency", errors)
    if concurrency.get("production_lock") != "archiveweaver-production":
        errors.append("concurrency.production_lock must be archiveweaver-production")
    if concurrency.get("max_concurrent_production_workflows") != 1:
        errors.append("concurrency.max_concurrent_production_workflows must be 1")
    if concurrency.get("policy") != "queue":
        errors.append("concurrency.policy must be queue")

    workflows = _workflow_map(contract, errors)
    _validate_workflow_dependencies(workflows, errors)
    source = workflows.get("source-integrity", {})
    source_command = source.get("command", "")
    if not isinstance(source_command, str) or "verify-source-identity.sh" not in source_command:
        errors.append("source-integrity must invoke verify-source-identity.sh")
    if source.get("required_environment") != SOURCE_ENVIRONMENT:
        errors.append("source-integrity.required_environment must require immutable ref and trusted signer bindings")
    if source.get("on_failure") != "stop":
        errors.append("source-integrity.on_failure must be stop")
    for workflow_id in SOURCE_GATED_WORKFLOWS:
        _require_list_contains(
            workflows.get(workflow_id, {}).get("required_environment"),
            set(OPERATIONAL_ENVIRONMENT),
            f"workflow.{workflow_id}.required_environment",
            errors,
        )
        if workflows.get(workflow_id, {}).get("on_failure") != "stop":
            errors.append(f"workflow.{workflow_id}.on_failure must be stop")
    if workflows.get("staging-preview", {}).get("on_failure") != "stop":
        errors.append("workflow.staging-preview.on_failure must be stop")
    for workflow_id in ("catalog-and-tests", "ansible-quality", "readiness"):
        if workflows.get(workflow_id, {}).get("on_failure") != "stop":
            errors.append(f"workflow.{workflow_id}.on_failure must be stop")
    if "validate-ansible.sh" not in str(workflows.get("ansible-quality", {}).get("commands", "")):
        errors.append("ansible-quality must run validate-ansible.sh")
    readiness = workflows.get("readiness", {})
    readiness_commands = readiness.get("commands")
    if not isinstance(readiness_commands, list) or not any(
        isinstance(command, str) and "verify-readiness-manifest.py" in command
        for command in readiness_commands
    ):
        errors.append("readiness must verify the protected readiness manifest digest")
    if not isinstance(readiness_commands, list) or not any(
        isinstance(command, str) and "archiveweaver readiness" in command
        for command in readiness_commands
    ):
        errors.append("readiness must run the readiness gate")

    for workflow_id in PRODUCTION_WORKFLOWS:
        item = workflows.get(workflow_id, {})
        if item.get("resource_lock") != "archiveweaver-production":
            errors.append(f"workflow.{workflow_id}.resource_lock must be archiveweaver-production")
        if item.get("serial") != 1:
            errors.append(f"workflow.{workflow_id}.serial must be 1")
        if item.get("any_errors_fatal") is not True:
            errors.append(f"workflow.{workflow_id}.any_errors_fatal must be true")
        if item.get("on_failure") != "stop":
            errors.append(f"workflow.{workflow_id}.on_failure must be stop")
    for workflow_id in ("production-apply", "production-repair", "production-rollback"):
        if workflows.get(workflow_id, {}).get("credential_binding") != "production-change-account":
            errors.append(f"workflow.{workflow_id}.credential_binding must be production-change-account")
    for workflow_id in ("production-post-apply-verify", "production-verify"):
        if workflows.get(workflow_id, {}).get("credential_binding") != "production-read-only":
            errors.append(f"workflow.{workflow_id}.credential_binding must be production-read-only")
    for workflow_id in ("production-apply", "production-repair", "production-rollback"):
        if workflows.get(workflow_id, {}).get("requires_approval") is not True:
            errors.append(f"workflow.{workflow_id}.requires_approval must be true")
    for workflow_id, credential in (
        ("staging-preview", "staging-read-only"),
        ("product-certification", "staging-certification-account"),
        ("failure-domain-drill", "staging-change-account"),
        ("backup-and-restore-gate", "preservation-restore-account"),
    ):
        if workflows.get(workflow_id, {}).get("credential_binding") != credential:
            errors.append(f"workflow.{workflow_id}.credential_binding must be {credential}")
    for workflow_id in REQUIRED_NONPRODUCTION_EXTRA_VARS:
        if workflows.get(workflow_id, {}).get("requires_approval") is not True:
            errors.append(f"workflow.{workflow_id}.requires_approval must be true")
    for workflow_id, approval_node in (
        ("production-apply", "production-approval"),
        ("production-repair", "production-repair-approval"),
        ("production-rollback", "production-rollback-approval"),
    ):
        if workflows.get(workflow_id, {}).get("approval_node") != approval_node:
            errors.append(f"workflow.{workflow_id}.approval_node must be {approval_node}")
        approval = workflows.get(approval_node, {})
        if approval.get("type") != "manual-approval":
            errors.append(f"workflow.{approval_node} must be a manual-approval node")
        if approval.get("required_group") != "archive-platform-approvers":
            errors.append(f"workflow.{approval_node}.required_group must be archive-platform-approvers")

    runtime_bindings = contract.get("required_runtime_bindings")
    runtime_bindings = runtime_bindings if isinstance(runtime_bindings, dict) else {}
    _require_list_contains(
        runtime_bindings.get("source_integrity"),
        set(SOURCE_ENVIRONMENT),
        "required_runtime_bindings.source_integrity",
        errors,
    )
    _require_list_contains(
        runtime_bindings.get("readiness"),
        set(OPERATIONAL_ENVIRONMENT),
        "required_runtime_bindings.readiness",
        errors,
    )
    for workflow_id, required in REQUIRED_RUNTIME_BINDINGS.items():
        _require_list_contains(
            runtime_bindings.get(workflow_id),
            required,
            f"required_runtime_bindings.{workflow_id}",
            errors,
        )
    for workflow_id in PRODUCTION_WORKFLOWS:
        _required_extra_vars(
            workflows,
            workflow_id,
            REQUIRED_RUNTIME_BINDINGS[WORKFLOW_BINDING_KEYS[workflow_id]],
            errors,
        )
    for workflow_id, required in REQUIRED_NONPRODUCTION_EXTRA_VARS.items():
        _required_extra_vars(workflows, workflow_id, required, errors)
    _required_extra_vars(
        workflows,
        "staging-preview",
        REQUIRED_STAGING_PREVIEW_EXTRA_VARS,
        errors,
    )
    _required_extra_vars_by_runtime(
        workflows,
        "staging-preview",
        REQUIRED_STAGING_PREVIEW_EXTRA_VARS_BY_RUNTIME,
        UNSUPPORTED_STAGING_PREVIEW_RUNTIMES,
        errors,
    )
    for workflow_id, binding_name in (
        ("product-certification", "product_certification"),
        ("failure-domain-drill", "restore_and_failure_drills"),
        ("backup-and-restore-gate", "restore_and_failure_drills"),
    ):
        _require_list_contains(
            runtime_bindings.get(binding_name),
            REQUIRED_NONPRODUCTION_EXTRA_VARS[workflow_id],
            f"required_runtime_bindings.{binding_name}",
            errors,
        )

    schedules = contract.get("schedules")
    if not isinstance(schedules, list):
        errors.append("schedules must be a list")
    else:
        schedule_map = {item.get("id"): item for item in schedules if isinstance(item, dict)}
        for schedule_id, workflow_id, interval in (
            ("hourly-verify", "production-verify", "1h"),
            ("weekly-restore-drill", "backup-and-restore-gate", "7d"),
            ("monthly-failure-domain-drill", "failure-domain-drill", "30d"),
        ):
            item = schedule_map.get(schedule_id)
            if not isinstance(item, dict) or item.get("workflow") != workflow_id or item.get("interval") != interval:
                errors.append(f"schedule {schedule_id} must target {workflow_id} at {interval}")

    secret_keys = {"password", "passwd", "secret", "token", "private_key", "client_secret"}
    errors.extend(f"secret-bearing key {key!r} is not allowed in controller contract" for key in sorted(set(_walk_keys(contract)) & secret_keys))
    return errors


def main() -> int:
    try:
        contract = yaml.load(CONTRACT_PATH.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        print(f"controller contract invalid: {exc}", file=sys.stderr)
        return 2
    errors = validate(contract)
    if errors:
        for error in errors:
            print(f"controller contract invalid: {error}", file=sys.stderr)
        return 2
    print(f"controller contract valid: {CONTRACT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
