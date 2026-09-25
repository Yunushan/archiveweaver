"""Regression checks for controller checks that must also run in check mode."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = (ROOT / "deploy/ansible/roles/archiveweaver_controller_preflight/tasks/main.yml").read_text(
    encoding="utf-8"
)


def task(name: str) -> str:
    match = re.search(rf"(?ms)^- name: {re.escape(name)}\n(.*?)(?=^- name: |\Z)", PREFLIGHT)
    if match is None:
        raise AssertionError(f"missing controller preflight task: {name}")
    return match.group(1)


def gate_enabled(fact: str, *, check: bool, staging_preview: bool, environment: str, **intents: bool) -> bool:
    """Evaluate the role's simple boolean gate with the supplied preview inputs."""
    source = task(
        "Determine whether immutable source verification applies"
        if fact == "archiveweaver_controller_preflight_source_gate_active"
        else "Determine whether the final readiness gate applies"
    )
    match = re.search(rf"(?m)^    {re.escape(fact)}: >-\n((?:^      .*\n)+)", source)
    if match is None:
        raise AssertionError(f"missing gate expression: {fact}")
    expression = " ".join(line.strip() for line in match.group(1).splitlines())
    expression = expression.removeprefix("{{ ").removesuffix(" }}")
    values = {
        "ansible_check_mode": check,
        "archiveweaver_staging_preview": staging_preview,
        **intents,
    }
    expression = re.sub(
        r"\b(\w+)\s*\|\s*default\(false\)\s*\|\s*bool\b",
        lambda match: repr(bool(values.get(match.group(1), False))),
        expression,
    )
    expression = re.sub(
        r"\bansible_check_mode\s*\|\s*bool\b",
        repr(check),
        expression,
    )
    expression = expression.replace("archiveweaver_environment", repr(environment))
    expression = expression.replace(
        "archiveweaver_controller_preflight_recovery_drill_active | bool",
        repr(bool(intents.get("archiveweaver_recovery_drill", False))),
    )
    expression = expression.replace(
        "archiveweaver_controller_preflight_bootstrap_active | bool",
        repr(bool(intents.get("archiveweaver_bootstrap_apply", False))),
    )
    expression = expression.replace(
        "archiveweaver_controller_preflight_staging_seed_active | bool",
        repr(bool(intents.get("archiveweaver_staging_seed_apply", False))),
    )
    if re.search(r"\barchiveweaver_\w+\b|\|", expression):
        raise AssertionError(f"unhandled gate expression: {expression}")
    def evaluate(node: ast.AST) -> bool | str:
        if isinstance(node, ast.Constant) and isinstance(node.value, (bool, str)):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return all(bool(evaluate(value)) for value in node.values)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            return any(bool(evaluate(value)) for value in node.values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            return evaluate(node.left) == evaluate(node.comparators[0])
        raise AssertionError(f"unexpected gate expression node: {ast.dump(node)}")

    return bool(evaluate(ast.parse(expression, mode="eval").body))


class ControllerPreviewGateTests(unittest.TestCase):
    def test_repair_check_mode_runs_source_and_readiness_gates(self) -> None:
        options = {
            "check": True,
            "staging_preview": False,
            "environment": "production",
            "archiveweaver_repair_apply": True,
        }
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))

        for name in (
            "Require the controller immutable source reference",
            "Verify the signed immutable source checkout",
            "Require a controller-protected readiness manifest digest",
            "Verify the controller-approved operational readiness manifest",
            "Require an immutable execution-environment digest for applied workflows",
            "Require the controller image identity to match the job binding",
        ):
            self.assertIn("when: archiveweaver_controller_preflight_source_gate_active | bool", task(name))
            self.assertIn("no_log: true", task(name))

        for name in (
            "Require applied workflows to match the signed readiness identity",
        ):
            self.assertIn("when: archiveweaver_controller_preflight_readiness_gate_active | bool", task(name))
            self.assertIn("no_log: true", task(name))
        self.assertIn(
            "archiveweaver_controller_preflight_readiness_gate_active | bool",
            task("Verify the applied workflow readiness manifest"),
        )

    def test_invalid_preview_bindings_fail_the_active_assertions(self) -> None:
        options = {
            "check": True,
            "staging_preview": False,
            "environment": "production",
            "archiveweaver_run_verification": True,
        }
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))

        for name, binding, invalid in (
            ("Require the controller immutable source reference", "ARCHIVEWEAVER_IMMUTABLE_REF", "main"),
            ("Require a controller-protected readiness manifest digest", "ARCHIVEWEAVER_READINESS_MANIFEST_SHA256", "not-a-sha256"),
            ("Require an immutable execution-environment digest for applied workflows", "archiveweaver_execution_environment_digest", "latest"),
        ):
            assertion = task(name)
            match = re.search(rf"{re.escape(binding)}[^\n]* is match\('([^']+)'\)", assertion)
            self.assertIsNotNone(match, name)
            self.assertIsNone(re.fullmatch(match.group(1), invalid), name)
        self.assertIn(
            "archiveweaver_controller_preflight_execution_environment_digest == archiveweaver_execution_environment_digest",
            task("Require the controller image identity to match the job binding"),
        )

    def test_staging_preview_still_precedes_final_readiness(self) -> None:
        options = {
            "check": True,
            "staging_preview": True,
            "environment": "staging",
            "archiveweaver_apply": True,
        }
        self.assertFalse(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertFalse(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))
        options["environment"] = "production"
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))

    def test_staging_recovery_drill_preserves_source_gate_without_final_score(self) -> None:
        options = {
            "check": False,
            "staging_preview": False,
            "environment": "staging",
            "archiveweaver_repair_apply": True,
            "archiveweaver_recovery_drill": True,
        }
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertFalse(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))
        options["archiveweaver_recovery_drill"] = False
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))

    def test_first_apply_requires_source_and_separate_authorization_but_not_final_score(self) -> None:
        options = {
            "check": False,
            "staging_preview": False,
            "environment": "production",
            "archiveweaver_apply": True,
            "archiveweaver_bootstrap_apply": True,
        }
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertFalse(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))
        self.assertIn("verify-bootstrap-authorization.py", task("Verify the separately approved first-apply authorization"))
        self.assertIn("score', 0) | int == 90", task("Require nine independently proven pre-deployment readiness domains"))
        options["archiveweaver_bootstrap_apply"] = False
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))

    def test_first_staging_seed_uses_separate_authorization_and_preseed_floor(self) -> None:
        options = {
            "check": False,
            "staging_preview": False,
            "environment": "staging",
            "archiveweaver_apply": True,
            "archiveweaver_staging_seed_apply": True,
        }
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_source_gate_active", **options))
        self.assertFalse(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))
        self.assertIn("verify-staging-seed-authorization.py", task("Verify the separately approved first staging seed authorization"))
        self.assertIn("['control', 'release', 'governance', 'support']", task("Require four independently proven preseed readiness domains"))
        options["archiveweaver_staging_seed_apply"] = False
        self.assertTrue(gate_enabled("archiveweaver_controller_preflight_readiness_gate_active", **options))

    def test_manifest_verifier_rejects_wrong_approved_digest(self) -> None:
        manifest = ROOT / "deploy/ansible/release-manifest.example.json"
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/verify-readiness-manifest.py"), str(manifest), "0" * 64, "a" * 40],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not match", result.stderr)

    def test_check_mode_override_commands_are_read_only_and_suppress_bytecode(self) -> None:
        for name in (
            "Reject partial inventory limits for operational workflows",
            "Reject tag-filtered operational workflows",
        ):
            self.assertNotIn("not ansible_check_mode", task(name))
        for name in (
            "Check controller path components before any local write",
            "Verify the signed immutable source checkout",
            "Verify the controller-approved operational readiness manifest",
            "Verify the applied workflow readiness manifest",
        ):
            content = task(name)
            self.assertIn("ansible.builtin.command:", content)
            self.assertIn("changed_when: false", content)
            self.assertIn("check_mode: false", content)
            self.assertIn("no_log: true", content)
        for name in (
            "Check controller path components before any local write",
            "Verify the controller-approved operational readiness manifest",
            "Verify the applied workflow readiness manifest",
        ):
            self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', task(name))
        self.assertIn('GIT_OPTIONAL_LOCKS: "0"', task("Verify the signed immutable source checkout"))


if __name__ == "__main__":
    unittest.main()
