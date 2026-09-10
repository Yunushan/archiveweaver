# Supply-chain controls

Premium operation requires the automation controller and the deployed product
release to be reproducible and attributable. The repository supplies the
content contract; the organization supplies the signing and registry policy.

## Controller image

Build `deploy/ansible/execution-environment/Containerfile` through
`scripts/build-ansible-execution-environment.sh` with an approved base image
digest. The wrapper rejects a tag-only or malformed base image before the
container engine resolves `FROM`; the Containerfile repeats the same check as
defense in depth. The image must contain the exact Ansible Core and
ansible-lint versions in both requirements files. Record the final image
digest, source commit, package lock, SBOM, signature, and vulnerability-scan
result in the release manifest's Ansible execution-environment object. The
controller must inject the same immutable digest into applied jobs and expose
the trusted value as `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST`; preflight
compares both bindings with the manifest before proceeding. Controller
preflight also checks the live Ansible Core and `ansible-lint` versions against
the pinned execution-environment requirements.

Before running tests or any playbook, the controller must also verify that its
checkout is the approved signed commit and has no tracked or unapproved
untracked worktree changes:

```bash
bash scripts/verify-source-identity.sh "$ARCHIVEWEAVER_IMMUTABLE_REF"
```

The verifier accepts only a full commit SHA, resolves it as a commit, compares
it with `HEAD`, rejects tracked and non-approved untracked worktree changes, and
requires a valid Git commit signature. Ignored files are not a bypass: only the
selected inventory files, encrypted Vault file, release manifests, and the
evidence bundle are permitted as operator inputs. Controller code, Ansible
configuration, generated playbooks, and tooling caches cannot be smuggled
through ignored files, and permitted operator files must be regular files with
no symlinked path components. The controller should inject
`ARCHIVEWEAVER_IMMUTABLE_REF` from the signed project metadata; do not
substitute a branch, tag, or floating ref. The readiness and evidence controls
still govern the permitted operator inputs.

The source verifier also requires the controller to provide
ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS and to match the signed commit's
VALIDSIG fingerprint against that allowlist. A valid signature from an
unapproved key is not sufficient for production.

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
- attach an SBOM and detached signature to the reviewed Ansible provider
  bundle as well as to each product artifact;
- ensure the in-toto provenance subject digest matches the bytes of each
  referenced product artifact and, for Ansible, the reviewed provider bundle
  artifact (and the immutable image digest for the controller execution
  environment's separate attestation);
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

For Quadlet, the reviewed directory must contain
`archiveweaver-<solution-id>.network`, `archiveweaver-<solution-id>.volume`,
and `<solution-id>.container`; the network and volume are deliberately
solution-scoped to prevent cross-service collisions on a shared host.

Do not use floating tags, unreviewed collections, mutable Git branches, or
credentials in build arguments. The readiness gate rejects placeholders,
absolute/out-of-bundle paths, digest mismatches, and unverified artifact
records.

## Promotion

Promotion is a signed change: catalog and tests, release verification, staging
preview, backup/restore evidence, manual approval, production apply, and
post-deployment verification. Store the resulting controller job record and
evidence index in immutable audit storage.

Repository automation reinforces this contract. The `Security` workflow runs
CodeQL, Bandit, and a strict audit of the pinned Ansible controller
dependencies on pushes, pull requests, and a weekly schedule. The `Release
artifacts` workflow builds the Python package only from a version-matching tag,
emits an SPDX SBOM, creates and verifies Sigstore signatures for the package
files, uploads the release bundle, and creates GitHub build provenance
attestations. These checks improve the repository's supply-chain
baseline but do not replace the operator-owned manifest, detached signatures,
provider-bundle proof, execution-environment proof, or immutable evidence
retention required by the readiness gate.
