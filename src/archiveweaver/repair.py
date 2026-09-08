from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from typing import Any

from .catalog import Catalog


@dataclass
class RepairAction:
    name: str
    command: list[str]
    risk: str
    reason: str
    requires_explicit_apply: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_repair_plan(
    catalog: Catalog,
    solution_id: str,
    mode: str,
    *,
    service: str | None = None,
    compose_file: str = "docker-compose.yml",
    namespace: str = "archiveweaver",
    deployment: str | None = None,
    unit: str | None = None,
    resource: str | None = None,
    allow_fencing_actions: bool = False,
) -> dict[str, Any]:
    solution = catalog.solution(solution_id)
    catalog.runtime(mode)
    target_service = service or (solution["health"]["service_aliases"][0] if solution["health"]["service_aliases"] else solution_id)
    target_deployment = deployment or solution_id
    actions: list[RepairAction] = []

    if mode == "raw":
        actions.extend([
            RepairAction("validate-unit", ["systemctl", "status", target_service, "--no-pager"], "read-only", "Capture current state before a restart."),
            RepairAction("restart-service", ["systemctl", "restart", target_service], "service-restart", "Restart the named systemd service after confirming the incident and backup state."),
            RepairAction("verify-unit", ["systemctl", "is-active", target_service], "read-only", "Confirm that systemd reports the service active."),
        ])
    elif mode == "docker":
        actions.extend([
            RepairAction("validate-compose", ["docker", "compose", "-f", compose_file, "config"], "read-only", "Validate the Compose model before changing containers."),
            RepairAction("reconcile-compose", ["docker", "compose", "-f", compose_file, "up", "-d", "--remove-orphans"], "container-reconcile", "Recreate only the declared Compose workload; volumes are not deleted."),
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
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
            results.append({"name": item["name"], "status": "pass" if completed.returncode == 0 else "fail", "returncode": completed.returncode, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip(), "command": command})
            if completed.returncode != 0:
                break
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"name": item["name"], "status": "fail", "error": str(exc), "command": command})
            break
    failures = [result for result in results if result["status"] == "fail"]
    return {"status": "fail" if failures else ("planned" if dry_run else "pass"), "results": results, "safety": plan.get("safety", [])}

