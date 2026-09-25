"""Validate a reviewed Swarm stack against deployed service and task state."""

from __future__ import annotations

import json
import re
from typing import Any


_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:([0-9a-f]{64})$")
_PLACEHOLDER_RE = re.compile(r"(?:example\.invalid|replace|todo|tbd|latest)", re.IGNORECASE)
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_RUNNING_RE = re.compile(r"^Running(?:\s|$)")


def _digest(image: Any) -> str | None:
    if not isinstance(image, str) or _PLACEHOLDER_RE.search(image):
        return None
    match = _IMAGE_RE.fullmatch(image)
    return match.group(1) if match else None


def swarm_targets(model: Any) -> dict[str, dict[str, Any]]:
    """Extract explicit, positive replicated targets from rendered stack config."""
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise ValueError("the rendered Swarm model must contain services")
    services = model["services"]
    if not services:
        raise ValueError("the rendered Swarm model must contain at least one service")
    targets: dict[str, dict[str, Any]] = {}
    for name, service in services.items():
        if not isinstance(name, str) or not _SERVICE_RE.fullmatch(name):
            raise ValueError("the rendered Swarm model has an invalid service name")
        if not isinstance(service, dict) or _digest(service.get("image")) is None:
            raise ValueError(f"Swarm service {name} must use an immutable image digest")
        deploy = service.get("deploy")
        if not isinstance(deploy, dict) or deploy.get("mode", "replicated") != "replicated":
            raise ValueError(f"Swarm service {name} must declare a replicated deployment")
        replicas = deploy.get("replicas")
        if type(replicas) is not int or replicas <= 0:
            raise ValueError(f"Swarm service {name} must declare positive replicas")
        targets[name] = {"image": service["image"], "replicas": replicas}
    return targets


def swarm_service_spec_matches(
    output: Any, service_name: str, image: str, replicas: int
) -> bool:
    """Require the manager's new service spec to match the reviewed target."""
    expected_digest = _digest(image)
    if expected_digest is None or type(replicas) is not int or replicas <= 0:
        return False
    try:
        services = json.loads(output)
        if not isinstance(services, list) or len(services) != 1:
            return False
        service = services[0]
        spec = service["Spec"]
        update = service.get("UpdateStatus")
        return bool(
            isinstance(spec, dict)
            and spec.get("Name") == service_name
            and spec["Mode"]["Replicated"]["Replicas"] == replicas
            and type(spec["Mode"]["Replicated"]["Replicas"]) is int
            and _digest(spec["TaskTemplate"]["ContainerSpec"]["Image"])
            == expected_digest
            and (update is None or update.get("State") == "completed")
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def swarm_tasks_converged(
    output: Any, service_name: str, image: str, replicas: int
) -> bool:
    """Require every desired replica slot to run the reviewed image digest."""
    if not isinstance(output, str) or type(replicas) is not int or replicas <= 0:
        return False
    lines = output.splitlines()
    if len(lines) != replicas:
        return False
    expected_digest = _digest(image)
    if expected_digest is None:
        return False
    slots: set[int] = set()
    for line in lines:
        try:
            task = json.loads(line)
            match = re.fullmatch(rf"{re.escape(service_name)}\.([1-9][0-9]*)", task["Name"])
            if (
                not isinstance(task, dict)
                or match is None
                or str(task["DesiredState"]).casefold() != "running"
                or not _RUNNING_RE.match(task["CurrentState"])
                or _digest(task["Image"]) != expected_digest
                or task.get("Error")
            ):
                return False
            slots.add(int(match.group(1)))
        except (KeyError, TypeError, ValueError, AttributeError):
            return False
    return slots == set(range(1, replicas + 1))


class FilterModule:
    def filters(self) -> dict[str, Any]:
        return {
            "archiveweaver_swarm_targets": swarm_targets,
            "archiveweaver_swarm_service_spec_matches": swarm_service_spec_matches,
            "archiveweaver_swarm_tasks_converged": swarm_tasks_converged,
        }
