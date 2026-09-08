# Pinned execution environment

The production controller must run an execution-environment image identified
by an immutable digest. The base image is intentionally a required build
argument and the Containerfile rejects tag-only or malformed references, so a
floating `latest` tag cannot enter the release accidentally.

```bash
podman build \
  --build-arg BASE_IMAGE=registry.example.invalid/approved-ansible-ee@sha256:REPLACE_WITH_DIGEST \
  --tag registry.example.invalid/archiveweaver-ee:REPLACE_WITH_RELEASE \
  .
```

Record the final image digest, package lock, source commit, SBOM, signature,
and vulnerability-scan result in the release readiness manifest. Promote the
image only after the controller can run syntax, lint, staging, restore, and
verification workflows with it.
