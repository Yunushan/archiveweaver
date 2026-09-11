#!/usr/bin/env python3
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import archiveweaver
from archiveweaver.catalog import Catalog
from archiveweaver.repair import _find_ansible_root, build_repair_plan


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    source_package = repository_root / "src" / "archiveweaver"
    imported_package = Path(archiveweaver.__file__).resolve()
    try:
        imported_package.relative_to(source_package)
    except ValueError:
        pass
    else:
        raise RuntimeError(
            "distribution smoke test imported ArchiveWeaver from the source checkout"
        )

    original_directory = Path.cwd()
    with tempfile.TemporaryDirectory() as temporary_directory:
        os.chdir(temporary_directory)
        try:
            ansible_root = _find_ansible_root()
            required = (
                ansible_root / "ansible.cfg",
                ansible_root / "repair.yml",
                ansible_root / "roles" / "archiveweaver_preflight" / "tasks" / "main.yml",
                ansible_root.parent.parent
                / "scripts"
                / "compile-ansible-lock.py",
                ansible_root.parent.parent
                / "scripts"
                / "generate-ansible-sbom.py",
                ansible_root.parent.parent
                / "scripts"
                / "run-ansible-operational.sh",
            )
            missing = [str(path) for path in required if not path.is_file()]
            if missing:
                raise RuntimeError(
                    "installed operational bundle is incomplete: " + ", ".join(missing)
                )
            plan = build_repair_plan(
                Catalog(),
                "paperless-ngx",
                "ansible",
                underlying_mode="rke2",
            )
            if plan.get("status") != "ready" or len(plan.get("actions", [])) != 4:
                raise RuntimeError("installed Ansible repair planner did not become ready")
        finally:
            os.chdir(original_directory)

    print(f"installed distribution valid: {imported_package}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
