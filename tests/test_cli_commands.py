from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from archiveweaver.cli import main


class CLICommandTests(unittest.TestCase):
    def invoke(self, arguments: list[str]) -> tuple[int, str, str]:
        output = io.StringIO()
        error = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            result = main(arguments)
        return result, output.getvalue(), error.getvalue()

    def test_catalog_listing_and_matrix_json_contracts(self) -> None:
        code, output, _ = self.invoke(["list-solutions", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["count"], 30)
        code, output, _ = self.invoke(
            ["matrix", "--solution", "paperless-ngx", "--json"]
        )
        matrix = json.loads(output)["rows"]
        self.assertEqual(code, 0)
        self.assertEqual(len(matrix), 10)
        self.assertTrue(all(row[0] == "paperless-ngx" for row in matrix))

    def test_plan_reports_ready_text_and_blocked_json(self) -> None:
        code, output, _ = self.invoke(
            ["plan", "--solution", "paperless-ngx", "--mode", "raw"]
        )
        self.assertEqual(code, 0)
        self.assertIn("status: ready", output)
        self.assertIn("Execution stages", output)
        code, output, _ = self.invoke(
            [
                "plan",
                "--solution",
                "paperless-ngx",
                "--mode",
                "rke2",
                "--nodes",
                "2",
                "--json",
            ]
        )
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["status"], "blocked")

    def test_check_exit_codes_follow_summary_status(self) -> None:
        for status, expected in (("pass", 0), ("warn", 1), ("fail", 2)):
            report = {"summary": {"status": status}}
            with patch("archiveweaver.cli.run_checks", return_value=report):
                code, output, _ = self.invoke(
                    ["check", "--solution", "paperless-ngx", "--json"]
                )
            self.assertEqual(code, expected)
            self.assertEqual(json.loads(output)["summary"]["status"], status)

    def test_repair_executes_plan_and_propagates_failure(self) -> None:
        plan = {"status": "ready", "actions": []}
        with (
            patch("archiveweaver.cli.build_repair_plan", return_value=plan),
            patch(
                "archiveweaver.cli.apply_repair",
                return_value={"status": "dry-run"},
            ) as apply,
        ):
            code, output, _ = self.invoke(
                ["repair", "--solution", "paperless-ngx", "--mode", "docker", "--json"]
            )
        self.assertEqual(code, 0)
        self.assertTrue(apply.call_args.kwargs["dry_run"])
        self.assertEqual(json.loads(output)["execution"]["status"], "dry-run")

        with (
            patch("archiveweaver.cli.build_repair_plan", return_value=plan),
            patch("archiveweaver.cli.apply_repair", return_value={"status": "fail"}),
        ):
            code, _, _ = self.invoke(
                [
                    "repair",
                    "--solution",
                    "paperless-ngx",
                    "--mode",
                    "docker",
                    "--apply",
                ]
            )
        self.assertEqual(code, 2)

    def test_catalog_and_readiness_commands_propagate_gate_results(self) -> None:
        with patch("archiveweaver.cli.validate_catalog", return_value=[]):
            code, output, _ = self.invoke(["validate-catalog", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["status"], "pass")
        with patch("archiveweaver.cli.validate_catalog", return_value=["invalid"]):
            code, _, _ = self.invoke(["validate-catalog"])
        self.assertEqual(code, 2)

        with patch(
            "archiveweaver.cli.assess_readiness", return_value={"status": "pass"}
        ):
            code, _, _ = self.invoke(
                ["readiness", "--manifest", "manifest.json", "--json"]
            )
        self.assertEqual(code, 0)
        with patch(
            "archiveweaver.cli.assess_readiness", return_value={"status": "fail"}
        ):
            code, _, _ = self.invoke(["readiness", "--manifest", "manifest.json"])
        self.assertEqual(code, 2)

    def test_evidence_index_build_verify_and_argument_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "archiveweaver.cli.build_evidence_index",
                return_value={"files": [{"path": "evidence.json"}]},
            ) as build:
                code, output, _ = self.invoke(
                    ["evidence-index", "--directory", directory, "--json"]
                )
            self.assertEqual(code, 0)
            payload = json.loads(output)
            self.assertEqual(payload["files"], 1)
            self.assertEqual(build.call_args.args[1], Path(directory) / "evidence-index.json")

        with patch(
            "archiveweaver.cli.verify_evidence_index", return_value={"status": "fail"}
        ):
            code, _, _ = self.invoke(
                ["evidence-index", "--verify", "evidence-index.json"]
            )
        self.assertEqual(code, 2)
        code, _, error = self.invoke(["evidence-index"])
        self.assertEqual(code, 2)
        self.assertIn("exactly one", error)

    def test_provider_digest_dispatches_all_kinds(self) -> None:
        for kind, target in (("file", "digest_file"), ("tree", "digest_tree")):
            with patch(f"archiveweaver.cli.{target}", return_value="a" * 64):
                code, output, _ = self.invoke(
                    ["provider-digest", "--kind", kind, "--path", "provider", "--json"]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["digest"], "a" * 64)

        code, _, error = self.invoke(
            ["provider-digest", "--kind", "quadlet", "--path", "provider"]
        )
        self.assertEqual(code, 2)
        self.assertIn("--service-name", error)
        with patch("archiveweaver.cli.digest_quadlet", return_value="b" * 64):
            code, output, _ = self.invoke(
                [
                    "provider-digest",
                    "--kind",
                    "quadlet",
                    "--path",
                    "provider",
                    "--service-name",
                    "archive",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(output.strip(), "b" * 64)

    def test_hook_digest_text_and_render_output_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "hook"
            executable.write_bytes(b"reviewed hook\n")
            code, output, _ = self.invoke(["hook-digest", str(executable)])
            self.assertEqual(code, 0)
            self.assertIn(
                hashlib.sha256(executable.read_bytes()).hexdigest(), output
            )

            rendered = Path(directory) / "rendered.yml"
            with patch(
                "archiveweaver.cli.render", return_value=({"status": "ready"}, "safe: true\n")
            ):
                code, output, _ = self.invoke(
                    [
                        "render",
                        "--solution",
                        "paperless-ngx",
                        "--mode",
                        "docker",
                        "--output",
                        str(rendered),
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(rendered.read_text(encoding="utf-8"), "safe: true\n")
            self.assertEqual(json.loads(output)["status"], "pass")

        with patch(
            "archiveweaver.cli.render", return_value=({"status": "ready"}, "safe: true\n")
        ):
            code, output, _ = self.invoke(
                ["render", "--solution", "paperless-ngx", "--mode", "docker"]
            )
        self.assertEqual(code, 0)
        self.assertEqual(output, "safe: true\n")

    def test_errors_use_stable_json_or_stderr_contracts(self) -> None:
        with patch("archiveweaver.cli.Catalog", side_effect=OSError("catalog missing")):
            code, output, error = self.invoke(["matrix", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(error, "")
        self.assertEqual(json.loads(output)["errors"], ["catalog missing"])
        with patch("archiveweaver.cli.Catalog", side_effect=OSError("catalog missing")):
            code, output, error = self.invoke(["matrix"])
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("catalog missing", error)


if __name__ == "__main__":
    unittest.main()
