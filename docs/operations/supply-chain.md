# Supply-chain controls

Premium operation requires the automation controller and the deployed product
release to be reproducible and attributable. The repository supplies the
content contract; the organization supplies the signing and registry policy.

## Controller image

Build `deploy/ansible/execution-environment/Containerfile` with an approved
base image digest; the Containerfile rejects a tag-only or malformed base
image. The image must contain the exact Ansible Core and
ansible-lint versions in both requirements files. Record the final image
digest, source commit, package lock, SBOM, signature, and vulnerability-scan
result in the release manifest's Ansible execution-environment object. The
controller must inject the same immutable digest into applied jobs and expose
the trusted value as `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST`; preflight
compares both bindings with the manifest before proceeding.

## Product artifacts

For every image or package in `release.artifacts`:

- store the artifact inside the controlled release bundle;
- record its actual SHA-256 digest and let the readiness command recompute it;
- record the reviewed provider bundle (Compose/Swarm file or Kustomize
  archive) as a release artifact, record its artifact SHA-256, and record the
  canonical SHA-256 of the staged remote content as `remote_digest` bound to
  the Ansible variables used on the managed hosts. For raw systemd and
  Quadlet, the same field binds the rendered unit or deterministic file set
  (with Kustomize paths canonicalized relative to the bundle root);
- attach the SBOM and detached signature;
- verify the signature using the approved cosign, GPG, or registry policy;
- attach the verification output as `signature_verification.evidence`.

Compute provider bindings with the repository CLI so the controller and
release tooling use the same canonical form:

```bash
PYTHONPATH=src python3 -m archiveweaver provider-digest --kind file --path compose.yml
PYTHONPATH=src python3 -m archiveweaver provider-digest --kind tree --path kustomize/
PYTHONPATH=src python3 -m archiveweaver provider-digest --kind quadlet \
  --path quadlet/ --service-name paperless-ngx
```

The command returns the `sha256:`-prefixed manifest form. Store that full form
as `release.provider_bundle.remote_digest`; Ansible's provider group variables
use the same digest without the prefix.

Do not use floating tags, unreviewed collections, mutable Git branches, or
credentials in build arguments. The readiness gate rejects placeholders,
absolute/out-of-bundle paths, digest mismatches, and unverified artifact
records.

## Promotion

Promotion is a signed change: catalog and tests, release verification, staging
preview, backup/restore evidence, manual approval, production apply, and
post-deployment verification. Store the resulting controller job record and
evidence index in immutable audit storage.
