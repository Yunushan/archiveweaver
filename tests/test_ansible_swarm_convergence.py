"""Swarm reconciliation must observe the requested tasks before recording release."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/ansible/filter_plugins"))

from archiveweaver_swarm import (  # noqa: E402
    swarm_service_spec_matches,
    swarm_targets,
    swarm_tasks_converged,
)


IMAGE = "registry.example.org/archive/app@sha256:" + "a" * 64
OLD_IMAGE = "registry.example.org/archive/app@sha256:" + "b" * 64
SERVICE = "paperless-ngx_app"
SWARM_TASKS = ROOT / "deploy/ansible/roles/archiveweaver_provider/tasks/docker-swarm.yml"


def service_spec(*, image: str = IMAGE, replicas: int = 2, state: str = "completed") -> str:
    return json.dumps(
        [
            {
                "Spec": {
                    "Name": SERVICE,
                    "Mode": {"Replicated": {"Replicas": replicas}},
                    "TaskTemplate": {"ContainerSpec": {"Image": image}},
                },
                "UpdateStatus": {"State": state},
            }
        ]
    )


def task(slot: int, *, image: str = IMAGE, state: str = "Running 10 seconds ago") -> dict[str, str]:
    return {
        "Name": f"{SERVICE}.{slot}",
        "DesiredState": "Running",
        "CurrentState": state,
        "Image": image,
        "Error": "",
    }


class SwarmConvergenceTests(unittest.TestCase):
    def test_rendered_model_requires_pinned_positive_replicated_targets(self) -> None:
        model = {"services": {"app": {"image": IMAGE, "deploy": {"replicas": 2}}}}
        self.assertEqual(swarm_targets(model), {"app": {"image": IMAGE, "replicas": 2}})
        for mutation in (
            lambda data: data["services"]["app"]["deploy"].update(replicas=0),
            lambda data: data["services"]["app"]["deploy"].update(replicas=True),
            lambda data: data["services"]["app"]["deploy"].update(mode="global"),
            lambda data: data["services"]["app"].update(image="registry.example.org/app:latest"),
        ):
            with self.subTest(mutation=mutation):
                invalid = copy.deepcopy(model)
                mutation(invalid)
                with self.assertRaises(ValueError):
                    swarm_targets(invalid)
        with self.assertRaises(ValueError):
            swarm_targets({"services": {}})

    def test_service_spec_requires_exact_name_replicas_digest_and_completed_update(self) -> None:
        self.assertTrue(swarm_service_spec_matches(service_spec(), SERVICE, IMAGE, 2))
        self.assertFalse(swarm_service_spec_matches(service_spec(), "other_app", IMAGE, 2))
        self.assertFalse(swarm_service_spec_matches(service_spec(replicas=1), SERVICE, IMAGE, 2))
        self.assertFalse(swarm_service_spec_matches(service_spec(image=OLD_IMAGE), SERVICE, IMAGE, 2))
        self.assertFalse(swarm_service_spec_matches(service_spec(state="paused"), SERVICE, IMAGE, 2))
        self.assertFalse(swarm_service_spec_matches("not-json", SERVICE, IMAGE, 2))

    def test_running_tasks_must_fill_every_slot_with_the_new_digest(self) -> None:
        running = "\n".join(json.dumps(item) for item in (task(1), task(2)))
        self.assertTrue(swarm_tasks_converged(running, SERVICE, IMAGE, 2))
        for rows in (
            [task(1)],
            [task(1), task(1)],
            [task(1), task(2, image=OLD_IMAGE)],
            [task(1), task(2, state="Preparing 2 seconds ago")],
            [task(1), {**task(2), "DesiredState": "Shutdown"}],
            [task(1), {**task(2), "Error": "container failed"}],
        ):
            with self.subTest(rows=rows):
                self.assertFalse(
                    swarm_tasks_converged("\n".join(json.dumps(row) for row in rows), SERVICE, IMAGE, 2)
                )
        self.assertFalse(swarm_tasks_converged("not-json", SERVICE, IMAGE, 1))

    def test_provider_uses_bounded_full_task_inspection_before_success(self) -> None:
        source = SWARM_TASKS.read_text(encoding="utf-8")
        self.assertLess(source.index("Define the reviewed Swarm service targets"), source.index("Deploy the reviewed Swarm stack"))
        self.assertLess(source.index("Deploy the reviewed Swarm stack"), source.index("Wait for every Swarm service to declare the reviewed target"))
        self.assertLess(source.index("Wait for every Swarm service to declare the reviewed target"), source.index("Wait for every reviewed Swarm replica to run the new image"))
        for task_name in (
            "Wait for every Swarm service to declare the reviewed target",
            "Wait for every reviewed Swarm replica to run the new image",
        ):
            block = source.split(f"- name: {task_name}", 1)[1].split("\n- name:", 1)[0]
            self.assertIn("- timeout", block)
            self.assertIn("- --kill-after=5s", block)
            self.assertIn("- 15s", block)
            self.assertIn("retries: 12", block)
            self.assertIn("delay: 10", block)
            self.assertIn("until: >-", block)
            self.assertIn("when: not ansible_check_mode | bool", block)
            self.assertIn("no_log: true", block)
        tasks_block = source.split("- name: Wait for every reviewed Swarm replica to run the new image", 1)[1]
        for argument in ("- service", "- ps", "- --no-trunc", "- --filter", "- desired-state=running", "- --format", "{{ '{{json .}}' }}"):
            self.assertIn(argument, tasks_block)
        self.assertIn("archiveweaver_swarm_tasks_converged", tasks_block)


if __name__ == "__main__":
    unittest.main()
