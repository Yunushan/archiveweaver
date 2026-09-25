from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
from importlib.metadata import PackageNotFoundError, distribution
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .catalog import Catalog
from .path_utils import has_symlink_component
from .provider_digest import digest_file


_SAFE_TARGET_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
_SAFE_KUBERNETES_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$")
_KUBERNETES_MODES = frozenset({"k3s", "rke2", "k0s", "microk8s"})
_PLAN_AUTHORITY = object()
_PLAN_SEAL_KEY = secrets.token_bytes(32)


def _canonical_plan_bytes(value: dict[str, Any]) -> bytes:
    """Serialize a generated plan with one deterministic, finite meaning."""
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("repair plan contains unsupported values") from exc


class _SealedRepairPlan(dict[str, Any]):
    """A generated plan whose nested content cannot be changed before apply."""

    def __init__(self, value: dict[str, Any], authority: object) -> None:
        if authority is not _PLAN_AUTHORITY:
            raise ValueError("repair plans can only be sealed by the plan builder")
        super().__init__(value)
        self._seal = hmac.new(
            _PLAN_SEAL_KEY,
            _canonical_plan_bytes(value),
            hashlib.sha256,
        ).digest()

    def verified_snapshot(self) -> dict[str, Any] | None:
        """Copy and authenticate the exact plan that execution will consume."""
        try:
            snapshot = copy.deepcopy(dict(self))
            actual = hmac.new(
                _PLAN_SEAL_KEY,
                _canonical_plan_bytes(snapshot),
                hashlib.sha256,
            ).digest()
        except (RecursionError, TypeError, ValueError):
            return None
        return snapshot if hmac.compare_digest(actual, self._seal) else None


def _seal_repair_plan(value: dict[str, Any]) -> dict[str, Any]:
    return _SealedRepairPlan(value, _PLAN_AUTHORITY)


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


def _usable_ansible_root(candidate: Path) -> bool:
    """Accept only a complete Ansible bundle with no symlinked trust boundary."""
    config = candidate / "ansible.cfg"
    roles = candidate / "roles"
    repair_playbook = candidate / "repair.yml"
    return bool(
        candidate.is_dir()
        and not has_symlink_component(candidate)
        and config.is_file()
        and not config.is_symlink()
        and roles.is_dir()
        and not roles.is_symlink()
        and repair_playbook.is_file()
        and not repair_playbook.is_symlink()
    )


def _find_ansible_root() -> Path:
    """Locate the bundle shipped with this source tree or distribution."""
    package_root = Path(__file__).resolve().parents[2]
    candidate = package_root / "deploy" / "ansible"
    if _usable_ansible_root(candidate):
        return candidate
    try:
        installed = distribution("archiveweaver")
    except PackageNotFoundError:
        installed = None
    if installed is not None:
        for installed_file in installed.files or ():
            normalized = installed_file.as_posix()
            if not normalized.endswith(
                "share/archiveweaver/deploy/ansible/ansible.cfg"
            ):
                continue
            candidate = Path(str(installed.locate_file(installed_file))).parent
            if _usable_ansible_root(candidate):
                return candidate.resolve()
    raise ValueError("could not locate the repository Ansible bundle")


def _resolve_readiness_manifest_path(
    value: str,
    ansible_root: Path,
    *,
    repository_root: Path | None = None,
) -> str:
    """Resolve the readiness manifest into the checked-in Ansible bundle."""
    candidate = _resolve_ansible_bundle_path(
        value,
        ansible_root,
        "--readiness-manifest",
        repository_root=repository_root,
    )
    try:
        candidate.relative_to(ansible_root)
    except ValueError as exc:
        raise ValueError("--readiness-manifest must resolve inside the Ansible playbook directory") from exc
    return str(candidate)


def _resolve_ansible_bundle_path(
    value: str,
    ansible_root: Path,
    label: str,
    *,
    repository_root: Path | None = None,
) -> Path:
    """Resolve a controller input below the reviewed Ansible bundle."""
    if not (_safe_relative_controller_path(value) or _safe_absolute_controller_path(value)):
        raise ValueError(f"{label} must be a safe controller path without traversal or whitespace")
    if has_symlink_component(ansible_root):
        raise ValueError(f"{label} cannot be checked below a symlinked Ansible bundle")
    raw = Path(value)
    if raw.is_absolute():
        unresolved = raw
    else:
        repository_root = repository_root or ansible_root.parent.parent
        repository_relative = raw.parts[:2] == ("deploy", "ansible")
        if repository_relative:
            unresolved = repository_root / raw
        else:
            cwd = Path(os.path.abspath(os.fspath(Path.cwd())))
            cwd_candidate = cwd / raw
            try:
                cwd_candidate.relative_to(ansible_root)
            except ValueError:
                unresolved = ansible_root / raw
            else:
                unresolved = cwd_candidate
    if has_symlink_component(unresolved):
        raise ValueError(f"{label} must not resolve through a symlink")
    candidate = unresolved.resolve()
    try:
        relative = candidate.relative_to(ansible_root)
    except ValueError as exc:
        raise ValueError(f"{label} must resolve inside the Ansible playbook directory") from exc
    current = ansible_root
    try:
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(f"{label} must not resolve through a symlink")
    except OSError as exc:
        raise ValueError(f"{label} could not be inspected safely") from exc
    return candidate


def _safe_identity(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and not re.search(r'["\s=\r\n\x00]', value)
        and not re.search(r'(?i)(?:replace|todo|tbd|latest)', value)
    )


def _require_safe_target_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_TARGET_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{label} must be a non-empty command-safe identifier")
    return value


def _require_safe_kubernetes_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_KUBERNETES_NAME_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase Kubernetes name of at most 63 characters")
    return value


def _require_kubernetes_context(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 253
        or value != value.strip()
        or value.startswith("-")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("--context must name one explicit Kubernetes context")
    return value


def _require_kubeconfig(value: str | None) -> tuple[str, str]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("--kubeconfig must name an absolute regular file")
    path = Path(value)
    if not path.is_absolute() or has_symlink_component(path) or not path.is_file():
        raise ValueError("--kubeconfig must name an absolute regular non-symlink file")
    try:
        return str(path.resolve(strict=True)), digest_file(path)
    except (OSError, ValueError) as exc:
        raise ValueError("--kubeconfig could not be measured safely") from exc


def _require_safe_path_argument(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value.startswith("-")
        or re.search(r"[\x00\r\n]", value)
    ):
        raise ValueError(f"{label} must be a non-empty path without control characters or option syntax")
    return value


@dataclass
class RepairAction:
    name: str
    command: list[str]
    risk: str
    reason: str
    requires_explicit_apply: bool = True
    environment: dict[str, str] | None = None
    timeout_seconds: int = 120

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
    kubeconfig: str | None = None,
    context: str | None = None,
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
    if mode in _KUBERNETES_MODES:
        selected_context = _require_kubernetes_context(context)
        selected_kubeconfig, kubeconfig_digest = _require_kubeconfig(kubeconfig)
    else:
        if kubeconfig is not None or context is not None:
            raise ValueError("--kubeconfig and --context require a Kubernetes repair mode")
        selected_context = None
        selected_kubeconfig = None
        kubeconfig_digest = None
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
        _require_safe_target_identifier(target_service, "--service")
        actions.extend([
            RepairAction("validate-unit", ["systemctl", "status", target_service, "--no-pager"], "read-only", "Capture current state before a restart."),
            RepairAction("restart-service", ["systemctl", "restart", target_service], "service-restart", "Restart the named systemd service after confirming the incident and backup state."),
            RepairAction("verify-unit", ["systemctl", "is-active", target_service], "read-only", "Confirm that systemd reports the service active."),
        ])
    elif mode == "docker":
        _require_safe_target_identifier(target_service, "--service")
        _require_safe_path_argument(compose_file, "--compose-file")
        actions.extend([
            RepairAction("validate-compose", ["docker", "compose", "-f", compose_file, "config"], "read-only", "Validate the Compose model before changing containers."),
            RepairAction("reconcile-compose", ["docker", "compose", "-f", compose_file, "up", "-d"], "container-reconcile", "Reconcile only the declared Compose workload; unrelated project containers and volumes are left untouched."),
            RepairAction("verify-compose", ["docker", "compose", "-f", compose_file, "ps"], "read-only", "Capture post-reconcile container state."),
        ])
    elif mode == "podman-quadlet":
        target_unit = unit or f"{solution_id}.service"
        _require_safe_target_identifier(target_unit, "--unit")
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
        _require_safe_target_identifier(target_resource, "--resource")
        actions.extend([
            RepairAction("cluster-status", ["pcs", "status", "--full"], "read-only", "Verify cluster membership and resource state."),
            RepairAction("resource-cleanup", ["pcs", "resource", "cleanup", target_resource], "cluster-recovery", "Clear a failed resource operation so Pacemaker can retry according to constraints."),
            RepairAction("cluster-status-after", ["pcs", "status", "--full"], "read-only", "Verify recovery and fencing state."),
        ])
    elif mode == "docker-swarm":
        _require_safe_path_argument(compose_file, "--compose-file")
        actions.extend([
            RepairAction("validate-stack", ["docker", "stack", "config", "-c", compose_file], "read-only", "Validate the Swarm stack model."),
            RepairAction("redeploy-stack", ["docker", "stack", "deploy", "--compose-file", compose_file, solution_id], "orchestrator-reconcile", "Reconcile services without deleting named volumes."),
            RepairAction("verify-stack", ["docker", "stack", "services", solution_id], "read-only", "Capture desired and running replicas."),
        ])
    elif mode == "ansible":
        # Resolve this path into the Ansible bundle so the generated action is
        # independent of the caller's current working directory. The Ansible
        # preflight repeats the same boundary check on the controller.
        ansible_root = _find_ansible_root()
        repository_root = ansible_root.parent.parent
        playbook_path = _resolve_ansible_bundle_path(
            playbook,
            ansible_root,
            "--playbook",
            repository_root=repository_root,
        )
        if playbook_path.name != "repair.yml":
            raise ValueError("--playbook must resolve to the approved Ansible repair.yml")
        runner_path = repository_root / "scripts" / "run-ansible-operational.sh"
        if has_symlink_component(runner_path) or runner_path.is_symlink() or not runner_path.is_file():
            raise ValueError("the approved Ansible operational runner is missing or unsafe")
        inventory_path = _resolve_ansible_bundle_path(
            inventory,
            ansible_root,
            "--inventory",
            repository_root=repository_root,
        )
        manifest_path = readiness_manifest or "deploy/ansible/release-manifest.json"
        manifest_path = _resolve_readiness_manifest_path(
            manifest_path,
            ansible_root,
            repository_root=repository_root,
        )
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
        runner_command = ["bash", str(runner_path), "repair.yml", "-i", str(inventory_path)]
        actions.extend([
            RepairAction("validate-playbook", [*runner_command, "--syntax-check"], "read-only", "Validate the approved Ansible repair playbook before contacting managed nodes.", environment=controller_environment),
            RepairAction("plan-repair", [*runner_command, "--check", "--diff", "-e", f"archiveweaver_solution_id={solution_id}", "-e", "archiveweaver_repair_apply=true", *provider_args], "read-only", "Preview repair task selection and check-mode-supported changes; production source, release, and evidence gates run again at apply.", environment=controller_environment, timeout_seconds=1800),
            RepairAction("apply-repair", [*runner_command, "-e", f"archiveweaver_solution_id={solution_id}", "-e", "archiveweaver_repair_apply=true", *provider_args], "orchestrator-restart", "Run the explicitly approved Ansible repair playbook. The playbook itself has a separate apply gate.", environment=controller_environment, timeout_seconds=1800),
            RepairAction("verify-repair", [*runner_command, "-e", f"archiveweaver_solution_id={solution_id}", *provider_args], "read-only", "Collect post-repair service, endpoint, storage, and sealed evidence results through an unfiltered play.", environment=controller_environment, timeout_seconds=1800),
        ])
    else:
        _require_safe_kubernetes_name(namespace, "--namespace")
        _require_safe_kubernetes_name(target_deployment, "--deployment")
        if selected_kubeconfig is None or selected_context is None:
            raise ValueError("Kubernetes repair requires an explicit kubeconfig and context")
        kubectl = ["kubectl", "--kubeconfig", selected_kubeconfig, "--context", selected_context, "--request-timeout=30s"]
        actions.extend([
            RepairAction("verify-cluster", [*kubectl, "get", "nodes", "-o", "wide"], "read-only", "Check control-plane and worker readiness in the bound cluster."),
            RepairAction("rollout-restart", [*kubectl, "-n", namespace, "rollout", "restart", f"deployment/{target_deployment}"], "orchestrator-restart", "Perform a rolling restart of the named deployment in the bound cluster."),
            RepairAction("verify-rollout", [*kubectl, "-n", namespace, "rollout", "status", f"deployment/{target_deployment}", "--timeout=300s"], "read-only", "Wait up to five minutes for the rollout to complete.", timeout_seconds=600),
        ])

    plan_value: dict[str, Any] = {
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
    if selected_kubeconfig is not None:
        plan_value["kubeconfig"] = selected_kubeconfig
        plan_value["kubeconfig_digest"] = kubeconfig_digest
        plan_value["context"] = selected_context
    return _seal_repair_plan(plan_value)


def apply_repair(plan: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    if plan.get("status") != "ready":
        return {"status": "blocked", "results": [], "blockers": plan.get("blockers", ["repair plan is not ready"])}
    if not isinstance(plan, _SealedRepairPlan):
        return {
            "status": "blocked",
            "results": [],
            "blockers": ["repair plan was not produced by the trusted plan builder"],
        }
    execution_plan = plan.verified_snapshot()
    if execution_plan is None:
        return {
            "status": "blocked",
            "results": [],
            "blockers": ["repair plan changed after it was reviewed"],
        }
    results: list[dict[str, Any]] = []
    for item in execution_plan["actions"]:
        command = item["command"]
        if dry_run:
            results.append({"name": item["name"], "status": "planned", "command": command})
            continue
        if execution_plan.get("mode") in _KUBERNETES_MODES:
            try:
                observed_digest = digest_file(Path(execution_plan["kubeconfig"]))
            except (OSError, ValueError):
                observed_digest = None
            if observed_digest != execution_plan.get("kubeconfig_digest"):
                results.append({"name": item["name"], "status": "fail", "error": "bound kubeconfig changed or became unsafe", "output_redacted": True, "command": command})
                break
        try:
            run_options: dict[str, Any] = {
                "check": False,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "timeout": item["timeout_seconds"],
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
        except subprocess.TimeoutExpired:
            results.append({"name": item["name"], "status": "fail", "error": "timed out; a remote operation may still be running", "output_redacted": True, "command": command})
            break
        except OSError:
            results.append({"name": item["name"], "status": "fail", "error": "could not start repair command", "output_redacted": True, "command": command})
            break
    failures = [result for result in results if result["status"] == "fail"]
    return {"status": "fail" if failures else ("planned" if dry_run else "pass"), "results": results, "safety": execution_plan.get("safety", [])}
