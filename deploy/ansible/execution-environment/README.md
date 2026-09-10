# Pinned execution environment

The production controller must run an execution-environment image identified
by an immutable digest. The base image is intentionally a required build
argument; the build wrapper rejects tag-only or malformed references before
the engine starts, and the Containerfile repeats that check inside the build.

```bash
bash scripts/build-ansible-execution-environment.sh \
  --engine podman \
  --base-image registry.example.invalid/approved-ansible-ee@sha256:REPLACE_WITH_64_HEX_DIGEST \
  --tag registry.example.invalid/archiveweaver-ee:REPLACE_WITH_RELEASE
```

The wrapper rejects tag-only or malformed base references before Podman or
Docker is invoked, accepts only the approved engines, and does not expose an
arbitrary build-argument surface. The in-Containerfile check is retained as
defense in depth. After the build, record the engine's immutable image digest;
the tag is only a local build label and is not a release identity.

Record the final image digest, package lock, source commit, SBOM, signature,
and vulnerability-scan result in the release readiness manifest. Promote the
image only after the controller can run syntax, lint, staging, restore, and
verification workflows with it.
