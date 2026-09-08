from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .catalog import Catalog


@dataclass
class Plan:
    solution: str
    solution_name: str
    mode: str
    mode_name: str
    nodes: str
    os: str
    os_name: str
    status: str
    support_level: str
    topology_level: str
    blockers: list[str]
    warnings: list[str]
    prerequisites: list[str]
    steps: list[str]
    commands: list[str]
    data_safety: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def node_bucket(value: str | int) -> str:
    text = str(value).strip().lower()
    if text in {"3+", "3plus", "3-plus", "n"}:
        return "3+"
    try:
        count = int(text)
    except ValueError as exc:
        raise ValueError("nodes must be 1, 2, 3, or 3+") from exc
    if count < 1:
        raise ValueError("nodes must be at least 1")
    if count == 1:
        return "1"
    if count == 2:
        return "2"
    if count == 3:
        return "3"
    return "3+"


def _base_commands(mode: str, solution_id: str, nodes: str, namespace: str) -> list[str]:
    if mode == "raw":
        return [
            "sudo ./scripts/install-host-prerequisites.sh --check-only",
            f"sudo ./scripts/install-solution.sh --solution {solution_id} --nodes {nodes} --plan-only",
            "sudo systemctl daemon-reload",
        ]
    if mode == "docker":
        return [
            "docker compose config",
            f"docker compose --project-name {solution_id} up -d",
            f"docker compose --project-name {solution_id} ps",
        ]
    if mode == "podman-quadlet":
        return [
            "sudo install -d -m 0755 /etc/containers/systemd",
            "sudo cp deploy/podman/quadlets/*.container deploy/podman/quadlets/*.network /etc/containers/systemd/",
            "sudo systemctl daemon-reload",
            f"sudo systemctl enable --now {solution_id}.service",
        ]
    if mode == "pacemaker":
        return [
            "sudo pcs status --full",
            "sudo pcs quorum status",
            "sudo pcs stonith status",
            "sudo pcs resource config",
        ]
    if mode == "docker-swarm":
        return [
            "docker info --format '{{.Swarm.LocalNodeState}}'",
            "docker stack config -c deploy/docker-swarm/stack.yml",
            f"docker stack deploy --compose-file deploy/docker-swarm/stack.yml {solution_id}",
        ]
    return [
        f"kubectl --context <{mode}-context> get nodes",
        f"kubectl --context <{mode}-context> -n {namespace} apply -k deploy/kubernetes/overlays/{mode}",
        f"kubectl --context <{mode}-context> -n {namespace} rollout status deployment/{solution_id}",
    ]


def build_plan(
    catalog: Catalog,
    solution_id: str,
    mode: str,
    nodes: str | int,
    os_id: str,
    *,
    namespace: str = "archiveweaver",
    stonith: bool = False,
    qdevice: bool = False,
    external_datastore: bool = False,
    allow_conditional: bool = False,
) -> Plan:
    solution = catalog.solution(solution_id)
    runtime = catalog.runtime(mode)
    operating_system = catalog.operating_system(os_id)
    bucket = node_bucket(nodes)
    support_level = solution["mode_support"][mode]
    topology_level = runtime["topology"][bucket]
    blockers: list[str] = []
    warnings: list[str] = []

    if support_level == "not-recommended":
        blockers.append("The solution marks this deployment mode as not-recommended.")
    if support_level == "conditional" and not allow_conditional:
        blockers.append("This product/mode is conditional; rerun with --allow-conditional after a design review.")
    if topology_level == "not-recommended" and not allow_conditional:
        blockers.append(f"The {runtime['name']} topology policy marks {bucket} nodes as not-recommended.")
    if topology_level == "supported-with-stonith" and not stonith:
        blockers.append("Pacemaker two-node plans require --stonith; STONITH fencing cannot be optional in production.")
    if mode == "pacemaker" and bucket == "2" and not qdevice:
        warnings.append("A quorum device or third witness is strongly recommended for a two-node Pacemaker cluster.")
    if mode in {"k3s", "rke2", "k0s", "microk8s", "docker-swarm"} and bucket in {"2", "3+"}:
        if bucket == "2" and not external_datastore:
            blockers.append("Two-node consensus is not a resilient baseline; use three control/manager nodes or an external quorum-capable datastore.")
        if bucket == "3+":
            warnings.append("Keep the application database, object storage, and search cluster outside the scheduler's local ephemeral storage.")
    if operating_system["tier"] == "legacy-conditional":
        warnings.append("This OS is a legacy-conditional baseline; pin dependencies and run the full integration test before production.")
    if operating_system["tier"] == "forward-validate":
        warnings.append("This OS is included for forward validation; do not promote it to production without an application release test.")
    if mode in {"k3s", "rke2", "k0s", "microk8s"} and bucket == "1":
        warnings.append("A single control plane is suitable for development or edge use, not failure-tolerant production HA.")
    if mode == "docker" and bucket in {"2", "3", "3+"}:
        warnings.append("Docker Compose does not schedule across hosts; use a shared deployment pipeline, Swarm, or Kubernetes for multi-host placement.")
    if mode == "pacemaker":
        warnings.append("Pacemaker should manage a complete resource group (VIP, web process, and state dependency) with tested fencing and recovery constraints.")
    if mode == "podman-quadlet" and bucket != "1":
        warnings.append("Quadlet is single-host lifecycle management; use Pacemaker for active/passive failover and externalize state.")
    if mode in {"k3s", "rke2", "k0s", "microk8s"}:
        warnings.append("Use CSI-backed persistent volumes, PodDisruptionBudgets, anti-affinity, ingress health checks, and tested backup/restore.")

    prerequisites = list(runtime["prerequisites"])
    prerequisites.extend([
        f"approved {operating_system['name']} image and pinned kernel/userspace baseline",
        "DNS, NTP, TLS certificates, firewall rules, and least-privilege service identities",
        "tested backup and restore for database, object/file storage, configuration, and fixity metadata",
    ])
    steps = [
        "Capture the release manifest, upstream URLs, checksums, and change ticket.",
        "Validate host OS, CPU architecture, time synchronization, DNS, firewall, and storage mounts.",
        "Provision or validate dependencies before starting the application workload.",
        f"Deploy the {solution['name']} application using the {runtime['name']} adapter.",
        "Run health, dependency, configuration, fixity, and smoke checks.",
        "Record the deployment manifest and backup verification result before accepting traffic.",
    ]
    data_safety = [
        "ArchiveWeaver never deletes application data as part of install, check, or repair.",
        "Repair is plan-only unless --apply is explicitly supplied.",
        "Never bypass STONITH, quorum, TLS verification, or application authentication to make a check green.",
        "Take or verify a restorable backup before migrations, index rebuilds, or failover actions.",
    ]
    status = "blocked" if blockers else ("conditional" if warnings or support_level == "conditional" else "ready")
    return Plan(
        solution=solution_id,
        solution_name=solution["name"],
        mode=mode,
        mode_name=runtime["name"],
        nodes=str(nodes),
        os=os_id,
        os_name=operating_system["name"],
        status=status,
        support_level=support_level,
        topology_level=topology_level,
        blockers=blockers,
        warnings=warnings,
        prerequisites=prerequisites,
        steps=steps,
        commands=_base_commands(mode, solution_id, str(nodes), namespace),
        data_safety=data_safety,
    )
