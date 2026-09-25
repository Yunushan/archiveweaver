"""Guard the direct site.yml apply path against unverified success."""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


SITE = (Path(__file__).resolve().parents[1] / "deploy/ansible/site.yml").read_text(encoding="utf-8")


def folded_expression(source: str, label: str) -> str:
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != label:
            continue
        indent = len(line) - len(line.lstrip())
        parts: list[str] = []
        for continuation in lines[index + 1 :]:
            if not continuation.strip():
                continue
            if len(continuation) - len(continuation.lstrip()) <= indent:
                break
            parts.append(continuation.strip())
        if not parts:
            raise AssertionError(f"empty folded expression: {label}")
        return " ".join(parts).removeprefix("{{ ").removesuffix(" }}")
    raise AssertionError(f"missing folded expression: {label}")


def evaluate_intent(expression: str, *, apply: bool, verify: bool, check: bool) -> bool:
    values = {"archiveweaver_apply": apply, "archiveweaver_run_verification": verify}
    expression = re.sub(
        r"\b(archiveweaver_apply|archiveweaver_run_verification)\s*\|\s*default\(false\)\s*\|\s*bool\b",
        lambda match: repr(values[match.group(1)]),
        expression,
    )
    expression = re.sub(r"\bansible_check_mode\s*\|\s*bool\b", repr(check), expression)

    def evaluate(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return all(evaluate(item) for item in node.values)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            return any(evaluate(item) for item in node.values)
        raise AssertionError(f"unexpected Ansible gate expression: {ast.dump(node)}")

    return evaluate(ast.parse(expression, mode="eval").body)


class DirectApplyVerificationTests(unittest.TestCase):
    def test_applied_run_forces_verification_and_sealing(self) -> None:
        fact = folded_expression(SITE, "archiveweaver_evidence_seal_enabled: >-")
        verify_role = SITE[SITE.index("- name: Verify the applied release and collect service evidence") :]
        verify_when = folded_expression(verify_role, "when: >-")
        evidence_play = SITE[SITE.index("- name: Seal ArchiveWeaver evidence after all managed hosts complete") :]
        evidence_when = folded_expression(evidence_play, "when: >-")
        for expression in (fact, verify_when, evidence_when):
            self.assertFalse(evaluate_intent(expression, apply=False, verify=False, check=False))
            self.assertTrue(evaluate_intent(expression, apply=True, verify=False, check=False))
            self.assertFalse(evaluate_intent(expression, apply=True, verify=False, check=True))
            self.assertTrue(evaluate_intent(expression, apply=False, verify=True, check=False))
        self.assertNotIn("archiveweaver_evidence_seal_enabled", evidence_when)

    def test_provider_handlers_run_before_post_apply_health_probe(self) -> None:
        self.assertLess(SITE.index("- role: archiveweaver_provider"), SITE.index("meta: flush_handlers"))
        self.assertLess(
            SITE.index("meta: flush_handlers"),
            SITE.index("tasks_from: record-release"),
        )
        self.assertLess(
            SITE.index("tasks_from: record-release"),
            SITE.index("- name: Verify the applied release and collect service evidence"),
        )
        self.assertLess(
            SITE.index("- name: Verify the applied release and collect service evidence"),
            SITE.index("- name: Seal ArchiveWeaver evidence after all managed hosts complete"),
        )
        self.assertLess(
            SITE.index("- name: Seal ArchiveWeaver evidence after all managed hosts complete"),
            SITE.index("- role: archiveweaver_observe"),
        )
        flush = SITE[
            SITE.index("- name: Apply pending provider handlers") : SITE.index("- name: Verify the applied release")
        ]
        self.assertIn("not ansible_check_mode | bool", flush)
        self.assertIn("archiveweaver_apply | bool", flush)

    def test_host_scoped_intent_cannot_bypass_controller_gate(self) -> None:
        guard = SITE[
            SITE.index("- name: Require uniform deployment intent across all managed hosts") :
            SITE.index("- name: Preserve the post-play evidence sealing decision")
        ]
        self.assertIn("groups['archiveweaver_nodes'] | default([]) | length > 0", guard)
        self.assertIn("loop: \"{{ groups['archiveweaver_nodes'] | default([]) }}\"", guard)
        self.assertIn("hostvars[item].archiveweaver_apply", guard)
        self.assertIn("hostvars[item].archiveweaver_run_verification", guard)
        self.assertIn("tags: [always, controller]", guard)

    def test_orchestration_controller_deploys_in_first_serial_batch(self) -> None:
        self.assertIn("order: inventory", SITE)
        self.assertIn(
            "groups['archiveweaver_nodes'][0] == groups['archiveweaver_control'][0]",
            SITE,
        )
        self.assertIn(
            "groups['archiveweaver_nodes'][0] == groups['archiveweaver_app'][0]",
            SITE,
        )
        self.assertLess(
            SITE.index("Require the orchestration apply host to be the first serial deployment batch"),
            SITE.index("- role: archiveweaver_provider"),
        )


if __name__ == "__main__":
    unittest.main()
