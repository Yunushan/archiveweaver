#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


CHUNK_SIZE = 1024 * 1024


def _validated_artifact(path: Path) -> tuple[Path, bool]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact must be a regular, non-symlink file: {path}")
    is_sdist = path.name.endswith(".tar.gz")
    if not (path.name.endswith(".whl") or is_sdist):
        raise ValueError(f"artifact must be a wheel or .tar.gz source distribution: {path}")
    return path.resolve(strict=True), is_sdist


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_artifact(path: Path) -> int:
    artifact, is_sdist = _validated_artifact(path)
    digest = _sha256(artifact)
    requirement_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="archiveweaver-artifact-",
            suffix=".txt",
            delete=False,
        ) as requirement:
            requirement.write(f"{artifact.as_uri()} --hash=sha256:{digest}\n")
            requirement.flush()
            requirement_path = Path(requirement.name)

        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-index",
            "--no-cache-dir",
            "--require-hashes",
            "--no-deps",
            "--force-reinstall",
        ]
        if is_sdist:
            # The caller must provision the build backend from a reviewed lock.
            command.append("--no-build-isolation")
        command.extend(("-r", str(requirement_path)))
        print(f"installing local artifact sha256:{digest}")
        completed = subprocess.run(command, check=False)
        return completed.returncode if completed.returncode >= 0 else 1
    finally:
        if requirement_path is not None:
            requirement_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install one local distribution through pip hash verification"
    )
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args(argv)
    try:
        return install_artifact(args.artifact)
    except (OSError, ValueError) as exc:
        print(f"local artifact installation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
