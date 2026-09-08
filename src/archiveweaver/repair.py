from __future__ import annotations

import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .catalog import Catalog


def _safe_relative_controller_path(value: str) -> bool:
    if not isinstance(value, str):
        return False
    candidate = Path(value)
    return bool(
        value.strip()
        and not candidate.is_absolute()
        and not candidate.anchor
        and not candidate.drive
        and ".." not in candidate.parts
        and not re.search(r'["\s\r\n\x00]', value)
        and not re.match(r"^[A-Za-z]:[\\/]", value)
    )


def _safe_absolute_controller_path(value: str) -> bool:
    if not isinstance(value, str):
        return False
    candidate = Path(value)
    return bool(
        value.strip()
        and candidate.is_absolute()
        and not re.search(r'["\s\r\n\x00]', value)
        and ".." not in candidate.parts
    )


def _resolve_readiness_manifest_path(value: str, ansible_root: Path) -> str:
    """Resolve the readiness manifest into the checked-in Ansible bundle."""
    raw = Path(value)
    if raw.is_absolute():
        candidate = raw.resolve()
    else:
        parts = raw.parts
        if len(parts) >= 2 and parts[0].lower() == "deploy" and parts[1].lower() == "ansible":
            candidate = (ansible_root / Path(*parts[2:])).resolve()
        else:
            candidate = (Path.cwd() / raw).resolve()
            try:
                candidate.relative_to(ansible_root)
            except ValueError:
                candidate = (ansible_root / raw).resolve()
    try:
        candidate.relative_to(ansible_root)
    except ValueError as exc:
        raise ValueError("--readiness-manifest must resolve inside the Ansible playbook directory") from exc
    return str(candidate)


def _safe_identity(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and not re.search(r'["\s=\r\n\x00]', value)
        and not re.search(r'(?i)(?:replace|todo|tbd|latest)', value)
    )


@dataclass
class RepairAction:
    name: str
    command: list[str]
    risk: str
    reason: str
    requires_explicit_apply: bool = True
    environment: dict[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        if self.environment is None:
            value.pop("environment", None)
        return value


def build_repair_plan(
    catalog: Catalog,
    solution_id: str,
    mode: str,
    *,
    service: str | None = None,
    compose_file: str = "docker-compose.yml",
    playbook: str = "deploy/ansible/repair.yml",
    inventory: str = "deploy/ansible/inventory/production/hosts.yml",
    readiness_manifest: str | None = None,
    namespace: str = "archiveweaver",
    deployment: str | None = None,
    unit: str | None = None,
    resource: str | None = None,
    allow_fencing_actions: bool = False,
    underlying_mode: str | None = None,
    operator: str | None = None,
    fixture_set: str | None = None,
    execution_environment_digest: str | None = None,
) -> dict[str, Any]:
    solution = catalog.solution(solution_id)
    catalog.runtime(mode)
    selected_underlying_mode = underlying_mode
    if mode == "ansible":
        selected_underlying_mode = underlying_mode or "raw"
        if selected_underlying_mode == "ansible":
            raise ValueError("Ansible cannot be its own underlying runtime")
        catalog.runtime(selected_underlying_mode)
    elif underlying_mode is not None:
        raise ValueError("--underlying-mode is only valid when --mode ansible is selected")
    elif readiness_manifest is not None:
        raise ValueError("--readiness-manifest is only valid when --mode ansible is selected")
    target_service = service or (solution["health"]["service_aliases"][0] if solution["health"]["service_aliases"] else solution_id)
    target_deployment = deployment or solution_id
    actions: list[RepairAction] = []

    if mode == "ansible" and selected_underlying_mode == "pacemaker" and not allow_fencing_actions:
        return {
            "solution": solution_id,
            "solution_name": solution["name"],
            "mode": mode,
            "underlying_mode": selected_underlying_mode,
            "status": "blocked",
            "actions": [],
            "blockers": ["Ansible Pacemaker repair is gated. Pass --allow-fencing-actions only after reviewing quorum, STONITH, constraints, and the change ticket."],
        }

    if mode == "raw":
        actions.extend([
            RepairAction("validate-unit", ["systemctl", "status", target_service, "--no-pager"], "read-only", "Capture current state before a restart."),
            RepairAction("restart-service", ["systemctl", "restart", target_service], "service-restart", "Restart the named systemd service after confirming the incident and backup state."),
            RepairAction("verify-unit", ["systemctl", "is-active", target_service], "read-only", "Confirm that systemd reports the service active."),
        ])
    elif mode == "docker":
        actions.extend([
            RepairAction("validate-compose", ["docker", "compose", "-f", compose_file, "config"], "read-only", "Validate the Compose model before changing containers."),
            RepairAction("reconcile-compose", ["docker", "compose", "-f", compose_file, "up", "-d"], "container-reconcile", "Reconcile only the declared Compose workload; unrelated project containers and volumes are left untouched."),
            RepairAction("verify-compose", ["docker", "compose", "-f", compose_file, "ps"], "read-only", "Capture post-reconcile container state."),
        ])
    elif mode == "podman-quadlet":
        target_unit = unit or f"{solution_id}.service"
        actions.extend([
            RepairAction("reload-quadlets", ["systemctl", "daemon-reload"], "unit-reload", "Regenerate systemd units from Quadlet definitions."),
            RepairAction("restart-quadlet", ["systemctl", "restart", target_unit], "service-restart", "Restart the named Quadlet service."),
            RepairAction("verify-quadlet", ["systemctl", "is-active", target_unit], "read-only", "Confirm that the Quadlet service is active."),
        ])
    elif mode == "pacemaker":
        if not allow_fencing_actions:
            return {
                "solution": solution_id,
                "solution_name": solution["name"],
                "mode": mode,
                "status": "blocked",
                "actions": [],
                "blockers": ["Pacemaker repair is gated. Pass --allow-fencing-actions only after reviewing quorum, STONITH, constraints, and the change ticket."],
            }
        target_resource = resource or target_service
        actions.extend([
            RepairAction("cluster-status", ["pcs", "status", "--full"], "read-only", "Verify cluster membership and resource state."),
            RepairAction("resource-cleanup", ["pcs", "resource", "cleanup", target_resource], "cluster-recovery", "Clear a failed resource operation so Pacemaker can retry according to constraints."),
            RepairAction("cluster-status-after", ["pcs", "status", "--full"], "read-only", "Verify recovery and fencing state."),
        ])
    elif mode == "docker-swarm":
        actions.extend([
            RepairAction("validate-stack", ["docker", "stack", "config", "-c", compose_file], "read-only", "Validate the Swarm stack model."),
            RepairAction("redeploy-stack", ["docker", "stack", "deploy", "--compose-file", compose_file, solution_id], "orchestrator-reconcile", "Reconcile services without deleting named volumes."),
            RepairAction("verify-stack", ["docker", "stack", "services", solution_id], "read-only", "Capture desired and running replicas."),
        ])
    elif mode == "ansible":
        # Resolve this path into the Ansible bundle so the generated action is
        # independent of the caller's current working directory. The Ansible
        # preflight repeats the same boundary check on the controller.
        manifest_path = readiness_manifest or "deploy/ansible/release-manifest.json"
        if not (_safe_relative_controller_path(manifest_path) or _safe_absolute_controller_path(manifest_path)):
            raise ValueError("--readiness-manifest must be a safe controller path without traversal or whitespace")
        ansible_root = Path(playbook).resolve().parent
        manifest_path = _resolve_readiness_manifest_path(manifest_path, ansible_root)
        provider_args = [
            "-e",
            f"archiveweaver_runtime={selected_underlying_mode}",
            "-e",
            f"archiveweaver_readiness_manifest_path={manifest_path}",
        ]
        for key, value in (("archiveweaver_operator", operator), ("archiveweaver_fixture_set", fixture_set)):
            if value is not None:
                if not _safe_identity(value):
                    raise ValueError(f"{key} must be a non-placeholder identity without whitespace or '='")
                provider_args.extend(["-e", f"{key}={value}"])
        if execution_environment_digest is not None:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", execution_environment_digest):
                raise ValueError("archiveweaver_execution_environment_digest must be a SHA-256 digest")
            provider_args.extend(["-e", f"archiveweaver_execution_environment_digest={execution_environment_digest}"])
        controller_environment = {
            "ANSIBLE_CONFIG": str(ansible_root / "ansible.cfg"),
            "ANSIBLE_ROLES_PATH": str(ansible_root / "roles"),
        }
        actions.extend([
            RepairAction("validate-playbook", ["ansible-playbook", "-i", inventory, playbook, "--syntax-check"], "read-only", "Validate the reviewed Ansible repair playbook before contacting managed nodes.", environment=controller_environment),
            RepairAction("plan-repair", ["ansible-playbook", "-i", inventory, playbook, "--check", "--diff", "-e", f"archiveweaver_solution_id={solution_id}", *provider_args], "read-only", "Produce an Ansible check-mode diff; no remote changes are allowed in this action.", environment=controller_environment),
            RepairAction("apply-repair", ["ansible-playbook", "-i", inventory, playbook, "-e", f"archiveweaver_solution_id={solution_id}", "-e", "archiveweaver_repair_apply=true", *provider_args], "orchestrator-restart", "Run the explicitly approved Ansible repair playbook. The playbook itself has a separate apply gate.", environment=controller_environment),
            RepairAction("verify-repair", ["ansible-playbook", "-i", inventory, playbook, "--tags", "verify,evidence", "-e", f"archiveweaver_solution_id={solution_id}", *provider_args], "read-only", "Collect post-repair service, endpoint, storage, and sealed evidence results.", environment=controller_environment),
        ])
    else:
        actions.extend([
            RepairAction("verify-cluster", ["kubectl", "get", "nodes", "-o", "wide"], "read-only", "Check control-plane and worker readiness."),
            RepairAction("rollout-restart", ["kubectl", "-n", namespace, "rollout", "restart", f"deployment/{target_deployment}"], "orchestrator-restart", "Perform a rolling restart of the named deployment."),
            RepairAction("verify-rollout", ["kubectl", "-n", namespace, "rollout", "status", f"deployment/{target_deployment}"], "read-only", "Wait for the rollout to complete."),
        ])

    return {
        "solution": solution_id,
        "solution_name": solution["name"],
        "mode": mode,
        "underlying_mode": selected_underlying_mode if mode == "ansible" else None,
        "status": "ready",
        "actions": [action.as_dict() for action in actions],
        "safety": [
            "The default output is a plan. Nothing runs until the caller passes --apply.",
            "No action removes volumes, deletes files, bypasses authentication, or disables fencing.",
            "Review backup, fixity, quorum, and application logs before applying a recovery action.",
        ],
    }


def apply_repair(plan: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    if plan.get("status") != "ready":
        return {"status": "blocked", "results": [], "blockers": plan.get("blockers", ["repair plan is not ready"])}
    results: list[dict[str, Any]] = []
    for item in plan["actions"]:
        command = item["command"]
        if dry_run:
            results.append({"name": item["name"], "status": "planned", "command": command})
            continue
        try:
            run_options: dict[str, Any] = {
                "check": False,
                "capture_output": True,
                "text": True,
                "timeout": 120,
            }
            if isinstance(item.get("environment"), dict):
                environment = os.environ.copy()
                environment.update({str(key): str(value) for key, value in item["environment"].items()})
                run_options["env"] = environment
            completed = subprocess.run(command, **run_options)
            results.append({
                "name": item["name"],
                "status": "pass" if completed.returncode == 0 else "fail",
                "returncode": completed.returncode,
                "output_redacted": True,
                "command": command,
            })
            if completed.returncode != 0:
                break
        except (OSError, subprocess.TimeoutExpired):
            results.append({"name": item["name"], "status": "fail", "output_redacted": True, "command": command})
            break
    failures = [result for result in results if result["status"] == "fail"]
    return {"status": "fail" if failures else ("planned" if dry_run else "pass"), "results": results, "safety": plan.get("safety", [])}

