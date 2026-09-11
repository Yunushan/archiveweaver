#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 SBOM from the Ansible hash lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "deploy" / "ansible" / "requirements.txt"
DEFAULT_PROJECT = ROOT / "pyproject.toml"
DEFAULT_OUTPUT = ROOT / "archiveweaver-ansible-controller.spdx.json"
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)(?:\s+\\)?$")
HASH_RE = re.compile(r"^\s+--hash=sha256:([0-9a-f]{64})(?:\s+\\)?$")
VERSION_RE = re.compile(r'^version\s*=\s*"([^"\s]+)"\s*(?:#.*)?$')
SPDX_ID_RE = re.compile(r"[^A-Za-z0-9.-]+")


class LockedPackage(NamedTuple):
    """One package identity and every approved wheel digest in the lock."""

    name: str
    version: str
    hashes: tuple[str, ...]


def canonical_name(value: str) -> str:
    """Return the normalized Python package name used by PyPI package URLs."""

    return re.sub(r"[-_.]+", "-", value).lower()


def read_regular_file(path: Path, label: str) -> bytes:
    """Read a regular, non-symlinked input file."""

    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be a regular non-symlinked file: {path}")
    return path.read_bytes()


def parse_lock(content: str) -> tuple[LockedPackage, ...]:
    """Parse the supported pip hash-lock form and reject ambiguous content."""

    packages: list[LockedPackage] = []
    seen: set[str] = set()
    current_name: str | None = None
    current_version: str | None = None
    current_hashes: set[str] = set()

    def finish_current() -> None:
        nonlocal current_name, current_version, current_hashes
        if current_name is None or current_version is None:
            return
        if not current_hashes:
            raise RuntimeError(
                f"locked package has no SHA-256 artifact hash: "
                f"{current_name}=={current_version}"
            )
        packages.append(
            LockedPackage(current_name, current_version, tuple(sorted(current_hashes)))
        )
        current_name = None
        current_version = None
        current_hashes = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        requirement_match = REQUIREMENT_RE.fullmatch(line)
        if requirement_match:
            finish_current()
            name = canonical_name(requirement_match.group(1))
            version = requirement_match.group(2)
            if name in seen:
                raise RuntimeError(f"duplicate locked package on line {line_number}: {name}")
            seen.add(name)
            current_name = name
            current_version = version
            continue
        hash_match = HASH_RE.fullmatch(line)
        if hash_match:
            if current_name is None:
                raise RuntimeError(
                    f"artifact hash appears before a requirement on line {line_number}"
                )
            digest = hash_match.group(1)
            if digest in current_hashes:
                raise RuntimeError(
                    f"duplicate artifact hash for {current_name} on line {line_number}"
                )
            current_hashes.add(digest)
            continue
        raise RuntimeError(f"unsupported active lock syntax on line {line_number}: {line}")

    finish_current()
    if not packages:
        raise RuntimeError("Ansible lock contains no exact hash-verified packages")
    return tuple(sorted(packages, key=lambda package: package.name))


def project_version(content: str) -> str:
    """Read exactly one version from the TOML project table without dependencies."""

    section = ""
    versions: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section != "project":
            continue
        match = VERSION_RE.fullmatch(stripped)
        if match:
            versions.append(match.group(1))
    if len(versions) != 1:
        raise RuntimeError("pyproject.toml must define exactly one [project] version")
    return versions[0]


def source_epoch(explicit: str | None) -> int:
    """Resolve the deterministic source timestamp used by the SPDX document."""

    value = explicit if explicit is not None else os.environ.get("SOURCE_DATE_EPOCH")
    if value is None or not value.isascii() or not value.isdecimal():
        raise RuntimeError(
            "SOURCE_DATE_EPOCH (or --source-date-epoch) must be a non-negative integer"
        )
    epoch = int(value)
    try:
        datetime.fromtimestamp(epoch, timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise RuntimeError("source date epoch is outside the supported range") from error
    return epoch


def spdx_id(name: str) -> str:
    """Create a deterministic SPDX identifier from a canonical package name."""

    identifier = SPDX_ID_RE.sub("-", name).strip("-.")
    if not identifier:
        raise RuntimeError(f"package name cannot form an SPDX identifier: {name!r}")
    return f"SPDXRef-Package-{identifier}"


def package_record(package: LockedPackage, created: str) -> dict[str, object]:
    """Render one locked Python distribution as an SPDX package record."""

    purl_name = quote(package.name, safe="-._~")
    purl_version = quote(package.version, safe="-._~")
    return {
        "SPDXID": spdx_id(package.name),
        "annotations": [
            {
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": "Tool: archiveweaver-generate-ansible-sbom",
                "comment": f"archiveweaver:approved-wheel-sha256:{digest}",
            }
            for digest in package.hashes
        ],
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": f"pkg:pypi/{purl_name}@{purl_version}",
                "referenceType": "purl",
            }
        ],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": package.name,
        "packageComment": (
            "Checksums identify every approved binary-wheel variant in the "
            "hash lock for CPython 3.13 and 3.14 on Linux x86_64. An installed "
            "artifact must match one listed SHA-256 value."
        ),
        "primaryPackagePurpose": "LIBRARY",
        "versionInfo": package.version,
    }


def build_document(
    lock_bytes: bytes,
    packages: tuple[LockedPackage, ...],
    version: str,
    epoch: int,
) -> dict[str, object]:
    """Build a stable SPDX 2.3 document for the locked controller closure."""

    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    identity = hashlib.sha256(
        f"{version}\0{epoch}\0{lock_digest}".encode("utf-8")
    ).hexdigest()
    root_id = "SPDXRef-Package-archiveweaver-ansible-controller"
    lock_id = "SPDXRef-File-ansible-requirements-lock"
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dependency_packages = [package_record(package, created) for package in packages]
    root_package: dict[str, object] = {
        "SPDXID": root_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": "archiveweaver-ansible-controller",
        "packageComment": (
            "Logical execution-environment package whose dependency closure is "
            "defined by deploy/ansible/requirements.txt."
        ),
        "primaryPackagePurpose": "APPLICATION",
        "versionInfo": version,
    }
    relationships = [
        {
            "relatedSpdxElement": root_id,
            "relationshipType": "DEPENDENCY_MANIFEST_OF",
            "spdxElementId": lock_id,
        }
    ]
    relationships.extend(
        {
            "relatedSpdxElement": spdx_id(package.name),
            "relationshipType": "DEPENDS_ON",
            "spdxElementId": root_id,
        }
        for package in packages
    )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: archiveweaver-generate-ansible-sbom"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": [root_id],
        "documentNamespace": (
            "https://github.com/Yunushan/archiveweaver/spdx/"
            f"ansible-controller/{identity}"
        ),
        "files": [
            {
                "SPDXID": lock_id,
                "checksums": [
                    {
                        "algorithm": "SHA1",
                        "checksumValue": hashlib.sha1(
                            lock_bytes, usedforsecurity=False
                        ).hexdigest(),
                    },
                    {"algorithm": "SHA256", "checksumValue": lock_digest}
                ],
                "copyrightText": "NOASSERTION",
                "fileName": "deploy/ansible/requirements.txt",
                "fileTypes": ["TEXT"],
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
            }
        ],
        "name": f"archiveweaver-ansible-controller-{version}",
        "packages": [root_package, *dependency_packages],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }


def render_document(document: dict[str, object]) -> bytes:
    """Serialize an SPDX document reproducibly as UTF-8 JSON."""

    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_write(path: Path, content: bytes) -> None:
    """Atomically replace a regular output without following an output symlink."""

    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError(f"SBOM output must be a regular non-symlinked file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        Path(temporary_name).replace(path)
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def generate(lock_path: Path, project_path: Path, epoch: int) -> tuple[bytes, int, int]:
    """Generate serialized SPDX bytes and inventory counts from repository inputs."""

    lock_bytes = read_regular_file(lock_path, "Ansible lock")
    project_bytes = read_regular_file(project_path, "project metadata")
    try:
        lock_text = lock_bytes.decode("utf-8", errors="strict")
        project_text = project_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("SBOM inputs must be valid UTF-8") from error
    packages = parse_lock(lock_text)
    document = build_document(lock_bytes, packages, project_version(project_text), epoch)
    return render_document(document), len(packages), sum(len(item.hashes) for item in packages)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--project", type=Path, default=DEFAULT_PROJECT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--source-date-epoch")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that the existing output is byte-for-byte reproducible",
    )
    arguments = parser.parse_args()
    try:
        rendered, package_count, artifact_count = generate(
            arguments.lock,
            arguments.project,
            source_epoch(arguments.source_date_epoch),
        )
        if arguments.check:
            actual = read_regular_file(arguments.output, "SBOM output")
            if actual != rendered:
                raise RuntimeError(f"SBOM is stale or non-reproducible: {arguments.output}")
            action = "verified"
        else:
            atomic_write(arguments.output, rendered)
            action = "generated"
    except (OSError, RuntimeError) as error:
        print(f"Ansible SBOM error: {error}", file=sys.stderr)
        return 1
    print(
        f"Ansible SBOM {action}: packages={package_count}, "
        f"approved_artifacts={artifact_count}, output={arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
