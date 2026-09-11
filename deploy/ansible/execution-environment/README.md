# Pinned execution environment

The production controller must run an execution-environment image identified
by an immutable digest. The base image is intentionally a required build
argument; the build wrapper rejects tag-only or malformed references before
the engine starts, and the Containerfile repeats that check inside the build.
The checked controller wheel set is restricted to CPython 3.13 or 3.14 on
Linux x86_64. The build fails explicitly on another Python/platform pair and
requires every package to match a reviewed SHA-256 hash.

```bash
bash scripts/build-ansible-execution-environment.sh \
  --engine podman \
  --base-image registry.example.invalid/approved-ansible-ee@sha256:REPLACE_WITH_64_HEX_DIGEST \
  --tag registry.example.invalid/archiveweaver-ee:REPLACE_WITH_RELEASE \
  --source-revision REPLACE_WITH_FULL_LOWERCASE_COMMIT_SHA
```

The wrapper rejects tag-only or malformed base references before Podman or
Docker is invoked, accepts only the approved engines, and does not expose an
arbitrary build-argument surface. It embeds and verifies OCI labels for the
full source revision, release, and approved base-image digest. After building,
it exercises the image as UID/GID 65532, verifies the exact locked Ansible Core,
Ansible Runner, and ansible-lint versions, requires their command entry points
plus the Git/GPG/SSH and shell utilities used by the controller trust boundary,
and runs an Ansible localhost ping. A build that
cannot support those controller operations is rejected. The image itself also
declares UID/GID 65532 as its default user, creates a matching passwd/group
identity, uses `/runner` as its private writable home and working directory,
marks itself as an Ansible execution environment, forwards PID 1 signals
through a hash-locked `dumb-init`, and disables Python bytecode writes. The
wrapper exercises these actual image defaults instead of trusting image
metadata alone. The in-Containerfile checks are retained as defense in depth.
After validation, record the pushed
image's immutable registry digest; the reported local image ID and mutable tag
are not release identities.

For a signed `v*` tag, `.github/workflows/release.yml` performs the same build
with Docker, rejects high or critical findings, validates an SPDX 2.3 image
SBOM, transfers and revalidates the exact local image ID, OCI labels, Ansible
EE marker, default UID/GID, working directory, entrypoint, and command in a
credential-separated job, then reruns the image through its real default
entrypoint before publishing it to GHCR. The workflow signs and verifies the digest,
attaches and verifies the SPDX attestation, emits GitHub build provenance, and
publishes a signed `archiveweaver-ee.publication.json` binding the release to
the final registry digest. The workflow fails closed unless the protected
GitHub `release` environment defines
`ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE` as an approved digest reference.
Publication retries reuse an existing version tag only when its remote config
digest exactly matches the validated local image ID; different content is never
overwritten.

Record the final image digest, package lock, source commit, SBOM, signature,
and vulnerability-scan result in the release readiness manifest. Promote the
image only after the controller can run syntax, lint, staging, restore, and
verification workflows with it.
