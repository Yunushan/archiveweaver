#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
PLACEHOLDER = re.compile(
    r"replace-me|example\.invalid|REPLACE_WITH|(?<![0-9a-f])0{64}(?![0-9a-f])"
)
ALLOWLIST = {
    "deploy/ansible/controller/workflow.yml": "operator-completed controller template values",
    "deploy/ansible/execution-environment/README.md": "documentation of required placeholders",
    "deploy/ansible/group_vars/all/main.yml": "release placeholder; the release is operator-pinned",
    "deploy/ansible/release-manifest.example.json": "example manifest; must keep scoring fail",
    "deploy/ansible/staging-seed-authorization.example.json": "example authorization template",
    "deploy/paperless-ngx/rke2/deployment.yaml": "product template; operator pins the image digest",
    "deploy/paperless-ngx/rke2/ingress.yaml.example": "ingress template; operator supplies host and TLS",
    "deploy/paperless-ngx/rke2/networkpolicy.yaml": "network policy template; operator supplies CIDRs",
    "deploy/paperless-ngx/rke2/paperless.env.example": "environment template; operator supplies secrets",
    "deploy/paperless-ngx/rke2/pvc.yaml": "storage template; operator supplies classes and capacity",
    "deploy/podman/quadlets/archiveweaver-app.container": "Quadlet sample template (D9)",
    "deploy/podman/quadlets/archiveweaver-data.volume": "Quadlet sample template (D9)",
}


def scan(root: Path, allowlist: dict[str, str]) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    hit_files: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(root.parent).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append(f"{relative}: not valid UTF-8, cannot be scanned")
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            match = PLACEHOLDER.search(line)
            if match is None:
                continue
            hit_files.add(relative)
            if relative not in allowlist:
                violations.append(f"{relative}:{number}: placeholder {match.group(0)!r}")
    stale = [f"{entry}: allowlisted but no placeholder remains" for entry in allowlist if entry not in hit_files]
    return violations, stale


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: verify-placeholder-free-deploy.py", file=sys.stderr)
        return 2
    violations, stale = scan(DEPLOY, ALLOWLIST)
    for problem in violations + stale:
        print(problem, file=sys.stderr)
    if violations or stale:
        return 1
    print(f"placeholder gate passed: allowlisted_templates={len(ALLOWLIST)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
