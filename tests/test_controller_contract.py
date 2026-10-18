from __future__ import annotations

import contextlib
import importlib.util
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-controller-contract.py"
CONTRACT_FILE = ROOT / "deploy" / "ansible" / "controller" / "workflow.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("validate_controller_contract", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


def base_contract():
    return yaml.safe_load(CONTRACT_FILE.read_text(encoding="utf-8"))


def workflow(contract, workflow_id):
    return next(item for item in contract["workflow"] if item["id"] == workflow_id)


def runner_errors(contract):
    errors: list[str] = []
    workflows = MODULE._workflow_map(contract, errors)
    MODULE._validate_operational_runner(contract, workflows, errors)
    return errors


class ControllerContractUnitTests(unittest.TestCase):
    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            yaml.load("a: 1\na: 2\n", Loader=MODULE.UniqueKeyLoader)
        self.assertEqual(
            yaml.load("a: 1\nb: 2\n", Loader=MODULE.UniqueKeyLoader),
            {"a": 1, "b": 2},
        )

    def test_mapping_helper_rejects_non_mapping(self) -> None:
        errors: list[str] = []
        self.assertEqual(MODULE._mapping(["not", "mapping"], "node", errors), {})
        self.assertIn("node must be a mapping", errors)
        self.assertEqual(MODULE._mapping({"a": 1}, "node", errors), {"a": 1})

    def test_require_list_contains_rejects_non_list(self) -> None:
        errors: list[str] = []
        MODULE._require_list_contains("not-a-list", {"a"}, "node", errors)
        self.assertIn("node must be a list of strings", errors)

    def test_workflow_map_rejects_bad_entries(self) -> None:
        errors: list[str] = []
        self.assertEqual(MODULE._workflow_map({"workflow": "not-a-list"}, errors), {})
        self.assertIn("workflow must be a list", errors)

        errors = []
        MODULE._workflow_map({"workflow": ["not-a-mapping"]}, errors)
        self.assertTrue(any("must be a mapping" in error for error in errors))

        errors = []
        MODULE._workflow_map({"workflow": [{"id": ""}]}, errors)
        self.assertTrue(any("must be a non-empty string" in error for error in errors))

        errors = []
        MODULE._workflow_map({"workflow": [{"id": "a"}, {"id": "a"}]}, errors)
        self.assertTrue(any("duplicate id a" in error for error in errors))

    def test_validate_workflow_dependencies_handles_missing_and_bad(self) -> None:
        errors: list[str] = []
        MODULE._validate_workflow_dependencies({}, errors)
        self.assertEqual(errors, [])

        errors = []
        MODULE._validate_workflow_dependencies(
            {"source-integrity": {"depends_on": ["catalog-and-tests"]}}, errors
        )
        self.assertTrue(any("depends_on must be" in error for error in errors))

        with mock.patch.object(MODULE, "REQUIRED_WORKFLOW_ORDER", ["a", "b"]):
            with mock.patch.object(
                MODULE, "REQUIRED_WORKFLOW_DEPENDENCIES", {"b": ["zzz"]}
            ):
                errors = []
                MODULE._validate_workflow_dependencies(
                    {"b": {"depends_on": ["zzz"]}}, errors
                )
                self.assertTrue(any("unknown workflow" in error for error in errors))

            with mock.patch.object(
                MODULE, "REQUIRED_WORKFLOW_DEPENDENCIES", {"a": ["b"]}
            ):
                errors = []
                MODULE._validate_workflow_dependencies(
                    {"a": {"depends_on": ["b"]}}, errors
                )
                self.assertTrue(any("earlier workflow" in error for error in errors))

    def test_required_extra_var_helpers_handle_missing_workflows(self) -> None:
        errors: list[str] = []
        MODULE._required_extra_vars({}, "absent", {"a"}, errors)
        MODULE._required_extra_vars_by_runtime({}, "absent", {"raw": {"a"}}, {"x"}, errors)
        self.assertEqual(errors, [])

    def test_required_extra_vars_by_runtime_rejects_bad_payloads(self) -> None:
        errors: list[str] = []
        MODULE._required_extra_vars_by_runtime(
            {"staging-preview": {"required_extra_vars_by_runtime": "bad"}},
            "staging-preview",
            {"raw": {"archiveweaver_a"}},
            {"pacemaker"},
            errors,
        )
        self.assertTrue(any("must be a mapping" in error for error in errors))

        errors = []
        MODULE._required_extra_vars_by_runtime(
            {
                "staging-preview": {
                    "required_extra_vars_by_runtime": {
                        "raw": ["archiveweaver_a"],
                        "unsupported_runtimes": "pacemaker",
                    }
                }
            },
            "staging-preview",
            {"raw": {"archiveweaver_a"}},
            {"pacemaker"},
            errors,
        )
        self.assertTrue(any("must be a list of strings" in error for error in errors))

        errors = []
        MODULE._required_extra_vars_by_runtime(
            {
                "staging-preview": {
                    "required_extra_vars_by_runtime": {
                        "raw": ["archiveweaver_a"],
                        "unsupported_runtimes": ["other"],
                    }
                }
            },
            "staging-preview",
            {"raw": {"archiveweaver_a"}},
            {"pacemaker"},
            errors,
        )
        self.assertTrue(any("unsupported_runtimes must be pacemaker" in error for error in errors))

        errors = []
        MODULE._required_extra_vars_by_runtime(
            {
                "staging-preview": {
                    "required_extra_vars_by_runtime": {"raw": ["archiveweaver_a"]}
                }
            },
            "staging-preview",
            {"raw": {"archiveweaver_a"}},
            {"pacemaker"},
            errors,
        )
        self.assertTrue(any("must be declared" in error for error in errors))

        errors = []
        MODULE._required_extra_vars_by_runtime(
            {
                "staging-preview": {
                    "required_extra_vars_by_runtime": {
                        "raw": ["archiveweaver_a"],
                        "bogus": ["archiveweaver_b"],
                        "unsupported_runtimes": ["pacemaker"],
                    }
                }
            },
            "staging-preview",
            {"raw": {"archiveweaver_a"}},
            {"pacemaker"},
            errors,
        )
        self.assertTrue(any("unknown runtime bogus" in error for error in errors))

    def test_validate_runner_extra_var_rejects_bad_payloads(self) -> None:
        for payload in ("@file.yml", "{a: 1}", "[a, b]", "no-equals-sign"):
            errors: list[str] = []
            MODULE._validate_runner_extra_var("w", payload, set(), errors)
            self.assertTrue(any("explicit archiveweaver_" in error for error in errors), payload)

        errors = []
        MODULE._validate_runner_extra_var("w", "other=1", set(), errors)
        self.assertTrue(any("unapproved key" in error for error in errors))

        errors = []
        MODULE._validate_runner_extra_var(
            "w",
            "archiveweaver_a=1, archiveweaver_b=2",
            {"archiveweaver_a", "archiveweaver_b"},
            errors,
        )
        self.assertTrue(any("one binding per option" in error for error in errors))

        errors = []
        MODULE._validate_runner_extra_var("w", "ansible_user=root", set(), errors)
        self.assertTrue(any("protected controller binding" in error for error in errors))

    def test_validate_runner_command_bindings_variants(self) -> None:
        errors: list[str] = []
        MODULE._validate_runner_command_bindings("w", ["-i"], {"inv"}, set(), errors)
        self.assertTrue(any("inventory option is missing" in error for error in errors))

        errors = []
        MODULE._validate_runner_command_bindings("w", ["--inventory=inv"], {"inv"}, set(), errors)
        MODULE._validate_runner_command_bindings("w", ["-iinv"], {"inv"}, set(), errors)
        self.assertEqual(errors, [])

        errors = []
        MODULE._validate_runner_command_bindings("w", ["-e"], {"inv"}, set(), errors)
        self.assertTrue(any("extra-vars option is missing" in error for error in errors))

        errors = []
        MODULE._validate_runner_command_bindings(
            "w",
            ["-i", "inv", "--extra-vars=archiveweaver_apply=true"],
            {"inv"},
            {"archiveweaver_apply"},
            errors,
        )
        MODULE._validate_runner_command_bindings(
            "w",
            ["-i", "inv", "-earchiveweaver_apply=true"],
            {"inv"},
            {"archiveweaver_apply"},
            errors,
        )
        self.assertEqual(errors, [])

    def test_validate_runner_option_shape_variants(self) -> None:
        errors: list[str] = []
        MODULE._validate_runner_option_shape("w", ["-i"], errors)
        self.assertTrue(any("missing its value" in error for error in errors))

        for token in ("--inventory=inv", "-iinv", "-evar=1"):
            errors = []
            MODULE._validate_runner_option_shape("w", [token], errors)
            self.assertEqual(errors, [], token)

        errors = []
        MODULE._validate_runner_option_shape("w", ["unexpected"], errors)
        self.assertTrue(any("unapproved operational argument" in error for error in errors))


class ControllerContractRunnerTests(unittest.TestCase):
    def _with_allowlist(self, content: str, *, exists: bool = True) -> list[str]:
        contract = base_contract()
        errors: list[str] = []
        workflows = MODULE._workflow_map(contract, errors)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowed-extra-vars.txt"
            if exists:
                path.write_text(content, encoding="utf-8")
            with mock.patch.object(MODULE, "EXTRA_VARS_ALLOWLIST_PATH", path):
                MODULE._validate_operational_runner(contract, workflows, errors)
        return errors

    def test_allowlist_read_failure_is_reported(self) -> None:
        errors = self._with_allowlist("", exists=False)
        self.assertTrue(any("cannot be read" in error for error in errors))

    def test_allowlist_must_be_sorted(self) -> None:
        errors = self._with_allowlist("archiveweaver_b\narchiveweaver_a\n")
        self.assertTrue(any("must be sorted" in error for error in errors))

    def test_allowlist_must_not_have_duplicates(self) -> None:
        errors = self._with_allowlist("archiveweaver_a\narchiveweaver_a\n")
        self.assertTrue(any("must not contain duplicates" in error for error in errors))

    def test_allowlist_rejects_invalid_keys(self) -> None:
        errors = self._with_allowlist("not-a-valid-key\n")
        self.assertTrue(any("invalid keys" in error for error in errors))

    def test_allowlist_rejects_protected_keys(self) -> None:
        errors = self._with_allowlist("archiveweaver_serial\n")
        self.assertTrue(any("protected keys" in error for error in errors))

    def test_missing_declared_allowlist_keys_are_reported(self) -> None:
        errors = self._with_allowlist("archiveweaver_apply\n")
        self.assertTrue(any("missing declared keys" in error for error in errors))

    def test_contract_without_runtime_binding_map(self) -> None:
        contract = base_contract()
        contract["required_runtime_bindings"] = "not-a-mapping"
        self.assertTrue(MODULE.validate(contract))

    def test_runner_field_drift_is_reported(self) -> None:
        contract = base_contract()
        runner = contract["operational_runner"]
        runner["path"] = "wrong/path.sh"
        runner["allowed_playbooks"] = []
        runner["allowed_options"] = []
        runner["rejected_options"] = []
        runner["required_inventory"] = False
        runner["allowed_inventories"] = []
        runner["environment_policy"] = {}
        runner["extra_vars"] = {}
        runner["invocation"] = "no runner here"
        errors = runner_errors(contract)
        self.assertTrue(any("operational_runner.path must be" in error for error in errors))
        self.assertTrue(any("allowed_playbooks" in error for error in errors))
        self.assertTrue(any("allowed_options" in error for error in errors))
        self.assertTrue(any("rejected_options" in error for error in errors))
        self.assertTrue(any("required_inventory" in error for error in errors))
        self.assertTrue(any("allowed_inventories" in error for error in errors))
        self.assertTrue(any("environment_policy" in error for error in errors))
        self.assertTrue(any("extra_vars" in error for error in errors))
        self.assertTrue(any("invocation" in error for error in errors))

    def test_runner_file_missing_is_reported(self) -> None:
        contract = base_contract()
        runner = contract["operational_runner"]
        fake = "scripts/_missing_runner_for_test.sh"
        runner["path"] = fake
        runner["invocation"] = fake
        errors: list[str] = []
        workflows = MODULE._workflow_map(contract, errors)
        with mock.patch.object(MODULE, "OPERATIONAL_RUNNER_PATH", fake):
            MODULE._validate_operational_runner(contract, workflows, errors)
        self.assertTrue(any("does not exist" in error for error in errors))

    def test_workflow_command_errors_are_reported(self) -> None:
        contract = base_contract()
        workflow(contract, "production-apply")["working_directory"] = "."
        workflow(contract, "production-verify")["commands"] = "not-a-list"
        workflow(contract, "production-repair")["commands"] = []
        workflow(contract, "production-rollback")["command"] = (
            'bash ../../scripts/run-ansible-operational.sh rollback.yml '
            '-i inventory/production/hosts.yml -e "unterminated'
        )
        preview = workflow(contract, "staging-preview")
        preview["command"] = preview["command"].replace(
            "operational.sh site.yml", "operational.sh unapproved.yml"
        )
        seed = workflow(contract, "staging-seed-apply")
        seed["command"] = seed["command"] + " --limit production"
        errors = MODULE.validate(contract)
        self.assertTrue(any("deploy/ansible directory" in error for error in errors))
        self.assertTrue(any("string command(s)" in error for error in errors))
        self.assertTrue(any("for every playbook command" in error for error in errors))
        self.assertTrue(any("invalid shell command" in error for error in errors))
        self.assertTrue(any("approved playbook(s)" in error for error in errors))
        self.assertTrue(any("rejected operational option" in error for error in errors))


class ControllerContractValidateTests(unittest.TestCase):
    def test_valid_contract_is_accepted(self) -> None:
        self.assertEqual(MODULE.validate(base_contract()), [])

    def test_non_mapping_contract_is_rejected(self) -> None:
        self.assertEqual(
            MODULE.validate(["not", "a", "mapping"]),
            ["controller contract must contain a YAML mapping"],
        )

    def test_identity_and_project_drift_is_reported(self) -> None:
        contract = base_contract()
        contract["schema_version"] = 2
        contract["kind"] = "wrong"
        contract["name"] = ""
        contract["project"]["content_signature_required"] = False
        errors = MODULE.validate(contract)
        self.assertTrue(any("schema_version must be 1" in error for error in errors))
        self.assertTrue(any("kind must be" in error for error in errors))
        self.assertTrue(any("name must be a non-empty string" in error for error in errors))
        self.assertTrue(any("project.content_signature_required" in error for error in errors))

    def test_execution_environment_drift_is_reported(self) -> None:
        cases = (
            {"image": "no-digest"},
            {"image": "repo@sha256:short"},
            {"digest": "not-a-digest"},
            {"image": "repo@sha256:" + "a" * 64, "digest": "sha256:" + "b" * 64},
            {"controller_identity_env": "WRONG"},
            {"ansible_core": "v1"},
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                contract = base_contract()
                contract["execution_environment"].update(mutation)
                errors = MODULE.validate(contract)
                self.assertTrue(errors)
        contract = base_contract()
        del contract["execution_environment"]["ansible_core"]
        self.assertTrue(any("ansible_core is required" in error for error in MODULE.validate(contract)))

    def test_concurrency_drift_is_reported(self) -> None:
        contract = base_contract()
        contract["concurrency"] = {
            "production_lock": "wrong",
            "max_concurrent_production_workflows": 2,
            "policy": "drop",
        }
        errors = MODULE.validate(contract)
        self.assertTrue(any("production_lock" in error for error in errors))
        self.assertTrue(any("max_concurrent_production_workflows" in error for error in errors))
        self.assertTrue(any("concurrency.policy" in error for error in errors))

    def test_source_integrity_drift_is_reported(self) -> None:
        contract = base_contract()
        source = workflow(contract, "source-integrity")
        source["command"] = ""
        source["required_environment"] = []
        source["on_failure"] = "continue"
        errors = MODULE.validate(contract)
        self.assertTrue(any("verify-source-identity.sh" in error for error in errors))
        self.assertTrue(any("source-integrity.required_environment" in error for error in errors))
        self.assertTrue(any("source-integrity.on_failure must be stop" in error for error in errors))

    def test_source_gated_failure_policy_drift_is_reported(self) -> None:
        contract = base_contract()
        workflow(contract, "readiness")["on_failure"] = "continue"
        workflow(contract, "staging-preview")["on_failure"] = "continue"
        errors = MODULE.validate(contract)
        self.assertTrue(any("workflow.readiness.on_failure must be stop" in error for error in errors))
        self.assertTrue(any("workflow.staging-preview.on_failure must be stop" in error for error in errors))

    def test_python_gate_and_readiness_command_drift_is_reported(self) -> None:
        contract = base_contract()
        workflow(contract, "catalog-and-tests")["on_failure"] = "continue"
        workflow(contract, "catalog-and-tests")["environment"] = {"PYTHONPATH": "src"}
        workflow(contract, "ansible-quality")["commands"] = ["echo nothing"]
        workflow(contract, "readiness")["commands"] = []
        errors = MODULE.validate(contract)
        self.assertTrue(any("must disable Python bytecode writes" in error for error in errors))
        self.assertTrue(any("ansible-quality must run validate-ansible.sh" in error for error in errors))
        self.assertTrue(any("manifest digest and source commit" in error for error in errors))
        self.assertTrue(any("readiness gate" in error for error in errors))

    def test_production_workflow_policy_drift_is_reported(self) -> None:
        contract = base_contract()
        verify = workflow(contract, "production-verify")
        verify["resource_lock"] = "wrong"
        verify["serial"] = 2
        verify["any_errors_fatal"] = False
        verify["on_failure"] = "continue"
        verify["credential_binding"] = "wrong"
        apply_node = workflow(contract, "production-apply")
        apply_node["credential_binding"] = "wrong"
        apply_node["requires_approval"] = False
        errors = MODULE.validate(contract)
        self.assertTrue(any("resource_lock must be archiveweaver-production" in error for error in errors))
        self.assertTrue(any("serial must be 1" in error for error in errors))
        self.assertTrue(any("any_errors_fatal must be true" in error for error in errors))
        self.assertTrue(any("must be stop" in error for error in errors))
        self.assertTrue(any("production-read-only" in error for error in errors))
        self.assertTrue(any("production-change-account" in error for error in errors))
        self.assertTrue(any("requires_approval must be true" in error for error in errors))

    def test_credential_and_approval_drift_is_reported(self) -> None:
        contract = base_contract()
        workflow(contract, "staging-preview")["credential_binding"] = "wrong"
        workflow(contract, "staging-seed-apply")["requires_approval"] = False
        drill = workflow(contract, "staging-repair-drill")
        drill["serial"] = 2
        drill["any_errors_fatal"] = False
        approval = workflow(contract, "production-approval")
        approval["type"] = "automatic"
        approval["required_group"] = "wrong-group"
        errors = MODULE.validate(contract)
        self.assertTrue(any("staging-read-only" in error for error in errors))
        self.assertTrue(any("requires_approval must be true" in error for error in errors))
        self.assertTrue(any("must serialize and fail on every host error" in error for error in errors))
        self.assertTrue(any("manual-approval node" in error for error in errors))
        self.assertTrue(any("required_group must be archive-platform-approvers" in error for error in errors))

    def test_on_demand_trigger_and_seed_lock_drift_is_reported(self) -> None:
        contract = base_contract()
        workflow(contract, "production-bootstrap-apply")["trigger"] = "scheduled"
        seed = workflow(contract, "staging-seed-apply")
        seed["trigger"] = "scheduled"
        seed["resource_lock"] = "wrong"
        errors = MODULE.validate(contract)
        self.assertTrue(any("on-demand" in error for error in errors))
        self.assertTrue(any("first staging seed lock" in error for error in errors))

    def test_schedule_drift_is_reported(self) -> None:
        contract = base_contract()
        contract["schedules"] = {}
        self.assertTrue(any("schedules must be a list" in error for error in MODULE.validate(contract)))

        contract = base_contract()
        contract["schedules"] = [{"id": "hourly-verify", "workflow": "wrong", "interval": "2h"}]
        self.assertTrue(any("schedule hourly-verify" in error for error in MODULE.validate(contract)))

    def test_secret_bearing_keys_are_rejected(self) -> None:
        contract = base_contract()
        contract["project"]["password"] = "placeholder"
        errors = MODULE.validate(contract)
        self.assertTrue(any("secret-bearing key" in error for error in errors))


class ControllerContractMainTests(unittest.TestCase):
    def test_main_accepts_the_real_contract(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(MODULE.main(), 0)

    def test_main_reports_unreadable_contract(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(MODULE, "CONTRACT_PATH", ROOT / "missing-controller.yml"):
            with contextlib.redirect_stderr(stderr):
                code = MODULE.main()
        self.assertEqual(code, 2)
        self.assertIn("controller contract invalid", stderr.getvalue())

    def test_main_reports_duplicate_yaml_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text("a: 1\na: 2\n", encoding="utf-8")
            with mock.patch.object(MODULE, "CONTRACT_PATH", path):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(MODULE.main(), 2)

    def test_main_reports_validation_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text("schema_version: 2\n", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(MODULE, "CONTRACT_PATH", path):
                with contextlib.redirect_stderr(stderr):
                    code = MODULE.main()
        self.assertEqual(code, 2)
        self.assertIn("controller contract invalid", stderr.getvalue())

    def test_main_guard_runs_and_exits_zero(self) -> None:
        with mock.patch.object(sys, "argv", ["validate-controller-contract.py"]):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
