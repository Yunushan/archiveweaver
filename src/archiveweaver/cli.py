from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .catalog import Catalog
from .checks import run_checks
from .evidence import build_evidence_index, verify_evidence_index
from .planner import build_plan
from .provider_digest import digest_file, digest_quadlet, digest_tree
from .repair import apply_repair, build_repair_plan
from .readiness import assess_readiness
from .render import render
from .schema import validate_catalog
from .path_utils import has_symlink_component


RUNTIME_CHOICES = ["raw", "docker", "k3s", "rke2", "pacemaker", "podman-quadlet", "k0s", "docker-swarm", "microk8s", "ansible"]
RENDER_RUNTIME_CHOICES = [mode for mode in RUNTIME_CHOICES if mode != "pacemaker"]
UNDERLYING_RUNTIME_CHOICES = [mode for mode in RUNTIME_CHOICES if mode != "ansible"]


def _dump(value: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(value, indent=2, ensure_ascii=False))
        return
    if isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, indent=2, ensure_ascii=False))


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    line = " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    separator = "-+-".join("-" * width for width in widths)
    return "\n".join([line, separator] + [" | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows])


def _add_common_plan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--solution", required=True, help="solution id, for example paperless-ngx")
    parser.add_argument("--mode", required=True, choices=RUNTIME_CHOICES)
    parser.add_argument("--nodes", default="1", help="1, 2, 3, or 3+")
    parser.add_argument("--os", dest="os_id", default="ubuntu-24.04", help="catalog OS id, for example rocky-9")
    parser.add_argument("--namespace", default="archiveweaver")
    parser.add_argument("--stonith", action="store_true", help="confirm STONITH is configured for Pacemaker")
    parser.add_argument("--qdevice", action="store_true", help="confirm a quorum device/witness is planned")
    parser.add_argument("--external-datastore", action="store_true", help="confirm consensus state is externalized")
    parser.add_argument("--allow-conditional", action="store_true", help="allow a conditional plan after design review")
    parser.add_argument("--underlying-mode", choices=UNDERLYING_RUNTIME_CHOICES, help="underlying provider when --mode ansible is selected")
    parser.add_argument("--json", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="archiveweaver", description="Plan, check and safely repair digital archiving deployments.")
    parser.add_argument("--version", action="version", version=f"ArchiveWeaver {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-solutions", help="list all supported catalog solutions")
    list_parser.add_argument("--json", action="store_true")

    matrix_parser = subparsers.add_parser("matrix", help="show runtime and topology support")
    matrix_parser.add_argument("--solution")
    matrix_parser.add_argument("--json", action="store_true")

    plan_parser = subparsers.add_parser("plan", help="build a safe deployment plan")
    _add_common_plan_args(plan_parser)

    check_parser = subparsers.add_parser("check", help="run read-only host and application checks")
    check_parser.add_argument("--solution", required=True)
    check_parser.add_argument("--mode", choices=RUNTIME_CHOICES)
    check_parser.add_argument("--url")
    check_parser.add_argument("--service")
    check_parser.add_argument("--path", dest="paths", action="append", default=[])
    check_parser.add_argument("--config")
    check_parser.add_argument("--json", action="store_true")

    repair_parser = subparsers.add_parser("repair", help="create or apply an idempotent repair plan")
    repair_parser.add_argument("--solution", required=True)
    repair_parser.add_argument("--mode", required=True, choices=RUNTIME_CHOICES)
    repair_parser.add_argument("--underlying-mode", choices=UNDERLYING_RUNTIME_CHOICES, help="underlying provider when --mode ansible is selected")
    repair_parser.add_argument("--service")
    repair_parser.add_argument("--compose-file", default="docker-compose.yml")
    repair_parser.add_argument("--playbook", default="deploy/ansible/repair.yml")
    repair_parser.add_argument("--inventory", default="deploy/ansible/inventory/production/hosts.yml")
    repair_parser.add_argument("--readiness-manifest", help="controller-side readiness manifest when --mode ansible is selected")
    repair_parser.add_argument("--namespace", default="archiveweaver")
    repair_parser.add_argument("--deployment")
    repair_parser.add_argument("--unit")
    repair_parser.add_argument("--resource")
    repair_parser.add_argument("--allow-fencing-actions", action="store_true")
    repair_parser.add_argument("--operator", help="non-secret operator identity for Ansible verification evidence")
    repair_parser.add_argument("--fixture-set", help="reviewed fixture-set identity for Ansible verification evidence")
    repair_parser.add_argument("--execution-environment-digest", help="approved Ansible controller image SHA-256 digest")
    repair_parser.add_argument("--apply", action="store_true", help="execute the repair actions")
    repair_parser.add_argument("--json", action="store_true")

    validate_parser = subparsers.add_parser("validate-catalog", help="validate generated catalog data")
    validate_parser.add_argument("--json", action="store_true")

    readiness_parser = subparsers.add_parser("readiness", help="score a release against the premium readiness contract")
    readiness_parser.add_argument("--manifest", required=True, help="JSON readiness manifest")
    readiness_parser.add_argument("--json", action="store_true")

    evidence_parser = subparsers.add_parser("evidence-index", help="seal or verify a SHA-256 evidence index")
    evidence_parser.add_argument("--directory", help="evidence directory to seal")
    evidence_parser.add_argument("--output", default="evidence-index.json", help="index path inside --directory")
    evidence_parser.add_argument("--verify", help="existing evidence-index.json to verify")
    evidence_parser.add_argument("--json", action="store_true")

    digest_parser = subparsers.add_parser("provider-digest", help="compute a deterministic provider-content SHA-256")
    digest_parser.add_argument("--kind", choices=["file", "tree", "quadlet"], required=True)
    digest_parser.add_argument("--path", required=True, help="provider file or directory")
    digest_parser.add_argument("--service-name", help="Quadlet service name when --kind quadlet is selected")
    digest_parser.add_argument("--json", action="store_true")

    render_parser = subparsers.add_parser("render", help="render a safe provider envelope")
    render_parser.add_argument("--solution", required=True)
    render_parser.add_argument("--mode", required=True, choices=RENDER_RUNTIME_CHOICES)
    render_parser.add_argument("--nodes", default="1")
    render_parser.add_argument("--os", dest="os_id", default="ubuntu-24.04")
    render_parser.add_argument("--namespace", default="archiveweaver")
    render_parser.add_argument("--underlying-mode", choices=UNDERLYING_RUNTIME_CHOICES, help="underlying provider when --mode ansible is selected")
    render_parser.add_argument("--image", help="pinned image reference; required when the catalog has no image hint")
    render_parser.add_argument("--allow-floating", action="store_true", help="allow a floating image tag such as :latest")
    render_parser.add_argument("--allow-conditional", action="store_true")
    render_parser.add_argument("--output", help="write the rendered envelope to a file")
    render_parser.add_argument("--json", action="store_true")
    return parser


def _print_plan(plan: dict[str, Any]) -> None:
    print(f"{plan['solution_name']} | {plan['mode_name']} | {plan['os_name']} | {plan['nodes']} node(s)")
    if plan.get("underlying_mode"):
        print(f"underlying runtime: {plan['underlying_mode']}")
    print(f"status: {plan['status']} | mode: {plan['support_level']} | topology: {plan['topology_level']}")
    if plan["blockers"]:
        print("\nBlockers")
        for item in plan["blockers"]:
            print(f"- {item}")
    if plan["warnings"]:
        print("\nWarnings")
        for item in plan["warnings"]:
            print(f"- {item}")
    print("\nPrerequisites")
    for item in plan["prerequisites"]:
        print(f"- {item}")
    print("\nExecution stages")
    for index, item in enumerate(plan["steps"], 1):
        print(f"{index}. {item}")
    print("\nReference commands")
    for item in plan["commands"]:
        print(f"$ {item}")
    print("\nSafety")
    for item in plan["data_safety"]:
        print(f"- {item}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        catalog = Catalog()
        if args.command == "list-solutions":
            rows = [[item["id"], item["name"], item["category"], item["mode_support"]["raw"], item["mode_support"]["docker"], item["mode_support"]["ansible"]] for item in catalog.solutions.values()]
            value = {"count": len(rows), "solutions": rows} if args.json else _table(["ID", "Name", "Category", "Raw", "Docker", "Ansible"], rows)
            _dump(value, args.json)
            return 0

        if args.command == "matrix":
            solutions = [catalog.solution(args.solution)] if args.solution else list(catalog.solutions.values())
            rows = []
            for solution in solutions:
                for runtime in catalog.runtimes.values():
                    policy = runtime["topology"]
                    rows.append([solution["id"], runtime["id"], solution["mode_support"][runtime["id"]], policy["1"], policy["2"], policy["3"], policy["3+"]])
            value = {"rows": rows} if args.json else _table(["Solution", "Mode", "Fit", "1", "2", "3", "3+"], rows)
            _dump(value, args.json)
            return 0

        if args.command == "plan":
            plan = build_plan(catalog, args.solution, args.mode, args.nodes, args.os_id, namespace=args.namespace, stonith=args.stonith, qdevice=args.qdevice, external_datastore=args.external_datastore, allow_conditional=args.allow_conditional, underlying_mode=args.underlying_mode).as_dict()
            if args.json:
                _dump(plan, True)
            else:
                _print_plan(plan)
            return 2 if plan["status"] == "blocked" else 0

        if args.command == "check":
            report = run_checks(catalog, args.solution, mode=args.mode, url=args.url, service=args.service, paths=args.paths, config=args.config)
            _dump(report, args.json)
            return 2 if report["summary"]["status"] == "fail" else 0

        if args.command == "repair":
            plan = build_repair_plan(catalog, args.solution, args.mode, service=args.service, compose_file=args.compose_file, playbook=args.playbook, inventory=args.inventory, readiness_manifest=args.readiness_manifest, namespace=args.namespace, deployment=args.deployment, unit=args.unit, resource=args.resource, allow_fencing_actions=args.allow_fencing_actions, underlying_mode=args.underlying_mode, operator=args.operator, fixture_set=args.fixture_set, execution_environment_digest=args.execution_environment_digest)
            result = apply_repair(plan, dry_run=not args.apply)
            payload = {"plan": plan, "execution": result}
            _dump(payload, args.json)
            return 2 if result["status"] == "fail" or plan.get("status") == "blocked" else 0

        if args.command == "validate-catalog":
            errors = validate_catalog(catalog)
            payload = {"status": "fail" if errors else "pass", "errors": errors, "solutions": len(catalog.solutions), "modes": len(catalog.runtimes), "operating_systems": len(catalog.operating_systems)}
            _dump(payload, args.json)
            return 2 if errors else 0

        if args.command == "readiness":
            report = assess_readiness(Path(args.manifest), catalog)
            _dump(report, args.json)
            return 0 if report["status"] == "pass" else 2

        if args.command == "evidence-index":
            if bool(args.directory) == bool(args.verify):
                raise ValueError("specify exactly one of --directory or --verify")
            if args.verify:
                report = verify_evidence_index(Path(args.verify))
            else:
                directory = Path(args.directory)
                output = Path(args.output)
                if not output.is_absolute():
                    output = directory / output
                report = {"status": "pass", "index": str(output), "files": len(build_evidence_index(directory, output)["files"])}
            _dump(report, args.json)
            return 0 if report["status"] == "pass" else 2

        if args.command == "provider-digest":
            path = Path(args.path)
            if args.kind == "file":
                digest = digest_file(path)
            elif args.kind == "tree":
                digest = digest_tree(path)
            else:
                if not args.service_name:
                    raise ValueError("--service-name is required when --kind quadlet is selected")
                digest = digest_quadlet(path, args.service_name)
            payload = {"status": "pass", "kind": args.kind, "path": str(path), "digest": digest}
            _dump(payload if args.json else digest, args.json)
            return 0

        if args.command == "render":
            plan, content = render(catalog, args.solution, args.mode, args.nodes, args.os_id, namespace=args.namespace, image=args.image, allow_floating=args.allow_floating, allow_conditional=args.allow_conditional, underlying_mode=args.underlying_mode)
            if args.output:
                output = Path(args.output)
                if has_symlink_component(output):
                    raise ValueError("render output must not resolve through a symlink")
                output.parent.mkdir(parents=True, exist_ok=True)
                if has_symlink_component(output):
                    raise ValueError("render output must not resolve through a symlink")
                output.write_text(content, encoding="utf-8")
                payload = {"status": "pass", "output": str(output), "plan": plan}
                _dump(payload, args.json)
            elif args.json:
                _dump({"status": "pass", "plan": plan, "content": content}, True)
            else:
                print(content, end="")
            return 0
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
        if getattr(args, "json", False):
            _dump({"status": "fail", "errors": [str(exc)]}, True)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
