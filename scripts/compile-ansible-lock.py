#!/usr/bin/env python3
"""Build or validate the hash-locked Ansible controller requirements."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import defaultdict
from email.parser import Parser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_IN = ROOT / "deploy" / "ansible" / "requirements.in"
LOCK = ROOT / "deploy" / "ansible" / "requirements.txt"
EE_LOCK = ROOT / "deploy" / "ansible" / "execution-environment" / "requirements.txt"
PYTHON_VERSIONS = ("3.13", "3.14")
LINUX_X86_64_PLATFORMS = (
    "manylinux_2_28_x86_64",
    "manylinux_2_17_x86_64",
    "manylinux2014_x86_64",
)
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)(?:\s+\\)?$")
HASH_RE = re.compile(r"^\s+--hash=sha256:([0-9a-f]{64})(?:\s+\\)?$")


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def compile_versions(destination: Path) -> None:
    run(
        [
            sys.executable,
            "-m",
            "piptools",
            "compile",
            "--quiet",
            "--strip-extras",
            "--no-emit-index-url",
            "--no-emit-trusted-host",
            "--resolver=backtracking",
            f"--output-file={destination}",
            str(REQUIREMENTS_IN),
        ]
    )


def download_wheels(lock: Path, destination: Path, python_version: str) -> None:
    abi = "cp" + python_version.replace(".", "")
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--quiet",
        "--disable-pip-version-check",
        "--no-input",
        "--only-binary=:all:",
        "--implementation=cp",
        f"--python-version={python_version}",
        f"--abi={abi}",
        f"--dest={destination}",
    ]
    for platform in LINUX_X86_64_PLATFORMS:
        command.append(f"--platform={platform}")
    command.extend(("-r", str(lock)))
    run(command)


def validate_target_closure(
    unhashed: str,
    hashes: dict[tuple[str, str], set[str]],
) -> None:
    """Reject dependencies discovered on Linux but omitted by host resolution."""

    locked = set(requirement_groups(unhashed))
    discovered = set(hashes)
    target_only = sorted(discovered - locked)
    if target_only:
        rendered = ", ".join(f"{name}=={version}" for name, version in target_only)
        raise RuntimeError(
            "Linux target dependencies are missing from the compiled lock; "
            f"add exact requirements.in pins for: {rendered}"
        )


def wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as wheel:
        metadata_files = [
            member
            for member in wheel.namelist()
            if member.endswith(".dist-info/METADATA") and member.count("/") == 1
        ]
        if len(metadata_files) != 1:
            raise RuntimeError(f"wheel has an ambiguous METADATA record: {path.name}")
        metadata = Parser().parsestr(
            wheel.read(metadata_files[0]).decode("utf-8", errors="strict")
        )
    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise RuntimeError(f"wheel is missing Name or Version metadata: {path.name}")
    return canonical_name(name), version


def collect_hashes(
    wheelhouses: dict[str, Path],
) -> tuple[dict[tuple[str, str], set[str]], dict[tuple[str, str], set[str]]]:
    hashes: dict[tuple[str, str], set[str]] = defaultdict(set)
    availability: dict[tuple[str, str], set[str]] = defaultdict(set)
    for python_version, wheelhouse in wheelhouses.items():
        wheels = sorted(wheelhouse.glob("*.whl"))
        if not wheels:
            raise RuntimeError(f"no wheels downloaded for Python {python_version}")
        for wheel in wheels:
            identity = wheel_identity(wheel)
            hashes[identity].add(hashlib.sha256(wheel.read_bytes()).hexdigest())
            availability[identity].add(python_version)
    return hashes, availability


def requirement_groups(content: str) -> list[tuple[str, str]]:
    groups: list[tuple[str, str]] = []
    for line in content.splitlines():
        match = REQUIREMENT_RE.fullmatch(line)
        if match:
            groups.append((canonical_name(match.group(1)), match.group(2)))
    if not groups:
        raise RuntimeError("compiled lock contains no exact requirements")
    return groups


def parse_hashed_lock(content: str) -> dict[str, str]:
    """Parse only exact requirements, hashes, comments, and blank lines."""

    versions: dict[str, str] = {}
    hashes: dict[str, set[str]] = defaultdict(set)
    active_name: str | None = None
    for line_number, line in enumerate(content.splitlines(), start=1):
        requirement_match = REQUIREMENT_RE.fullmatch(line)
        if requirement_match:
            name = canonical_name(requirement_match.group(1))
            if name in versions:
                raise RuntimeError(f"lock contains duplicate package {name} on line {line_number}")
            versions[name] = requirement_match.group(2)
            active_name = name
            continue
        hash_match = HASH_RE.fullmatch(line)
        if hash_match:
            if active_name is None:
                raise RuntimeError(f"lock contains a hash before a package on line {line_number}")
            digest = hash_match.group(1)
            if digest in hashes[active_name]:
                raise RuntimeError(f"lock duplicates a hash for {active_name} on line {line_number}")
            hashes[active_name].add(digest)
            continue
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            raise RuntimeError(f"lock contains unsupported active syntax on line {line_number}: {line}")
    if not versions:
        raise RuntimeError("lock contains no exact requirements")
    for name, version in versions.items():
        if not hashes[name]:
            raise RuntimeError(f"requirement is not hash locked: {name}=={version}")
    return versions


def render_hashed_lock(
    unhashed: str,
    hashes: dict[tuple[str, str], set[str]],
    availability: dict[tuple[str, str], set[str]],
) -> str:
    lines = unhashed.splitlines()
    first_requirement = next(
        (index for index, line in enumerate(lines) if REQUIREMENT_RE.fullmatch(line)),
        None,
    )
    if first_requirement is None:
        raise RuntimeError("pip-compile output contains no exact requirements")

    expected_versions = set(PYTHON_VERSIONS)
    rendered = [
        "#",
        "# Generated by scripts/compile-ansible-lock.py from requirements.in.",
        "# Approved artifact scope: CPython 3.13 and 3.14 on Linux x86_64,",
        "# binary wheels only. Install with --require-hashes and --only-binary=:all:.",
        "#",
    ]
    for line in lines[first_requirement:]:
        match = REQUIREMENT_RE.fullmatch(line)
        if not match:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                raise RuntimeError(f"pip-compile emitted unsupported active syntax: {line}")
            normalized = line.replace(
                REQUIREMENTS_IN.as_posix(), "deploy/ansible/requirements.in"
            ).replace(str(REQUIREMENTS_IN), "deploy/ansible/requirements.in")
            rendered.append(normalized)
            continue
        identity = (canonical_name(match.group(1)), match.group(2))
        if availability.get(identity) != expected_versions:
            missing = sorted(expected_versions - availability.get(identity, set()))
            raise RuntimeError(
                f"{identity[0]}=={identity[1]} lacks approved wheels for: "
                + ", ".join(missing)
            )
        artifact_hashes = sorted(hashes.get(identity, set()))
        if not artifact_hashes:
            raise RuntimeError(f"no artifact hash collected for {identity[0]}=={identity[1]}")
        rendered.append(f"{match.group(1)}=={match.group(2)} \\")
        for index, digest in enumerate(artifact_hashes):
            continuation = " \\" if index + 1 < len(artifact_hashes) else ""
            rendered.append(f"    --hash=sha256:{digest}{continuation}")
    return "\n".join(rendered).rstrip() + "\n"


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing to replace symlinked lock: {path}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary_name = temporary.name
        Path(temporary_name).replace(path)
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def direct_requirements(content: str | None = None) -> dict[str, str]:
    result: dict[str, str] = {}
    source = (
        REQUIREMENTS_IN.read_text(encoding="utf-8", errors="strict")
        if content is None
        else content
    )
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = REQUIREMENT_RE.fullmatch(stripped)
        if not match:
            raise RuntimeError(f"direct requirement is not exactly pinned: {stripped}")
        name = canonical_name(match.group(1))
        if name in result:
            raise RuntimeError(f"duplicate direct requirement: {name}")
        result[name] = match.group(2)
    if not result:
        raise RuntimeError("direct requirement input contains no exact requirements")
    return result


def check_lock() -> None:
    if LOCK.read_bytes() != EE_LOCK.read_bytes():
        raise RuntimeError("controller and execution-environment locks differ")
    content = LOCK.read_text(encoding="utf-8")
    if "Approved artifact scope: CPython 3.13 and 3.14 on Linux x86_64" not in content:
        raise RuntimeError("lock does not declare its approved artifact scope")
    root_forms = {str(ROOT), ROOT.as_posix()}
    if any(root in content for root in root_forms):
        raise RuntimeError("lock contains a machine-specific repository path")
    locked = parse_hashed_lock(content)
    direct = direct_requirements()
    for name, version in direct.items():
        if locked.get(name) != version:
            raise RuntimeError(f"direct pin is missing from lock: {name}=={version}")
    print(f"Ansible lock valid: {len(locked)} exact, hash-verified packages")


def generate_lock() -> None:
    with tempfile.TemporaryDirectory(prefix="archiveweaver-ansible-lock-") as temporary:
        temporary_root = Path(temporary)
        unhashed_lock = temporary_root / "requirements.txt"
        compile_versions(unhashed_lock)
        wheelhouses = {
            version: temporary_root / ("cp" + version.replace(".", ""))
            for version in PYTHON_VERSIONS
        }
        for version, wheelhouse in wheelhouses.items():
            wheelhouse.mkdir()
            download_wheels(unhashed_lock, wheelhouse, version)
        hashes, availability = collect_hashes(wheelhouses)
        unhashed = unhashed_lock.read_text(encoding="utf-8")
        validate_target_closure(unhashed, hashes)
        content = render_hashed_lock(
            unhashed, hashes, availability
        )
        atomic_write(LOCK, content)
        atomic_write(EE_LOCK, content)
    check_lock()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the checked-in lock without contacting package indexes",
    )
    arguments = parser.parse_args()
    if arguments.check:
        check_lock()
    else:
        generate_lock()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
