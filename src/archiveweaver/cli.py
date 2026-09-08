from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .catalog import Catalog
from .checks import run_checks
from .planner import build_plan
from .repair import apply_repair, build_repair_plan
from .render import render
from .schema import validate_catalog


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
    parser.add_argument("--mode", required=True, choices=["raw", "docker", "k3s", "rke2", "pacemaker", "podman-quadlet", "k0s", "docker-swarm", "microk8s"])
    parser.add_argument("--nodes", default="1", help="1, 2, 3, or 3+")
    parser.add_argument("--os", dest="os_id", default="ubuntu-24.04", help="catalog OS id, for example rocky-9")
    parser.add_argument("--namespace", default="archiveweaver")
    parser.add_argument("--stonith", action="store_true", help="confirm STONITH is configured for Pacemaker")
    parser.add_argument("--qdevice", action="store_true", help="confirm a quorum device/witness is planned")
    parser.add_argument("--external-datastore", action="store_true", help="confirm consensus state is externalized")
    parser.add_argument("--allow-conditional", action="store_true", help="allow a conditional plan after design review")
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
    check_parser.add_argument("--mode", choices=["raw", "docker", "k3s", "rke2", "pacemaker", "podman-quadlet", "k0s", "docker-swarm", "microk8s"])
    check_parser.add_argument("--url")
    check_parser.add_argument("--service")
    check_parser.add_argument("--path", dest="paths", action="append", default=[])
    check_parser.add_argument("--config")
    check_parser.add_argument("--json", action="store_true")

    repair_parser = subparsers.add_parser("repair", help="create or apply an idempotent repair plan")
    repair_parser.add_argument("--solution", required=True)
    repair_parser.add_argument("--mode", required=True, choices=["raw", "docker", "k3s", "rke2", "pacemaker", "podman-quadlet", "k0s", "docker-swarm", "microk8s"])
    repair_parser.add_argument("--service")
    repair_parser.add_argument("--compose-file", default="docker-compose.yml")
    repair_parser.add_argument("--namespace", default="archiveweaver")
    repair_parser.add_argument("--deployment")
    repair_parser.add_argument("--unit")
    repair_parser.add_argument("--resource")
    repair_parser.add_argument("--allow-fencing-actions", action="store_true")
    repair_parser.add_argument("--apply", action="store_true", help="execute the repair actions")
    repair_parser.add_argument("--json", action="store_true")

    validate_parser = subparsers.add_parser("validate-catalog", help="validate generated catalog data")
    validate_parser.add_argument("--json", action="store_true")

    render_parser = subparsers.add_parser("render", help="render a safe provider envelope")
    render_parser.add_argument("--solution", required=True)
    render_parser.add_argument("--mode", required=True, choices=["raw", "docker", "k3s", "rke2", "podman-quadlet", "k0s", "docker-swarm", "microk8s"])
    render_parser.add_argument("--nodes", default="1")
    render_parser.add_argument("--os", dest="os_id", default="ubuntu-24.04")
    render_parser.add_argument("--namespace", default="archiveweaver")
    render_parser.add_argument("--image", help="pinned image reference; required when the catalog has no image hint")
    render_parser.add_argument("--allow-floating", action="store_true", help="allow a floating image tag such as :latest")
    render_parser.add_argument("--allow-conditional", action="store_true")
    render_parser.add_argument("--output", help="write the rendered envelope to a file")
    render_parser.add_argument("--json", action="store_true")
    return parser


def _print_plan(plan: dict[str, Any]) -> None:
    print(f"{plan['solution_name']} | {plan['mode_name']} | {plan['os_name']} | {plan['nodes']} node(s)")
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
    catalog = Catalog()

    try:
        if args.command == "list-solutions":
            rows = [[item["id"], item["name"], item["category"], item["mode_support"]["raw"], item["mode_support"]["docker"]] for item in catalog.solutions.values()]
            value = {"count": len(rows), "solutions": rows} if args.json else _table(["ID", "Name", "Category", "Raw", "Docker"], rows)
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
            plan = build_plan(catalog, args.solution, args.mode, args.nodes, args.os_id, namespace=args.namespace, stonith=args.stonith, qdevice=args.qdevice, external_datastore=args.external_datastore, allow_conditional=args.allow_conditional).as_dict()
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
            plan = build_repair_plan(catalog, args.solution, args.mode, service=args.service, compose_file=args.compose_file, namespace=args.namespace, deployment=args.deployment, unit=args.unit, resource=args.resource, allow_fencing_actions=args.allow_fencing_actions)
            result = apply_repair(plan, dry_run=not args.apply)
            payload = {"plan": plan, "execution": result}
            _dump(payload, args.json)
            return 2 if result["status"] == "fail" or plan.get("status") == "blocked" else 0

        if args.command == "validate-catalog":
            errors = validate_catalog(catalog)
            payload = {"status": "fail" if errors else "pass", "errors": errors, "solutions": len(catalog.solutions), "modes": len(catalog.runtimes), "operating_systems": len(catalog.operating_systems)}
            _dump(payload, args.json)
            return 2 if errors else 0

        if args.command == "render":
            plan, content = render(catalog, args.solution, args.mode, args.nodes, args.os_id, namespace=args.namespace, image=args.image, allow_floating=args.allow_floating, allow_conditional=args.allow_conditional)
            if args.output:
                from pathlib import Path

                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(content, encoding="utf-8")
                payload = {"status": "pass", "output": str(output), "plan": plan}
                _dump(payload, args.json)
            elif args.json:
                _dump({"status": "pass", "plan": plan, "content": content}, True)
            else:
                print(content, end="")
            return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
