# Supply-chain controls

Premium operation requires the automation controller and the deployed product
release to be reproducible and attributable. The repository supplies the
content contract; the organization supplies the signing and registry policy.

## Controller image

Build `deploy/ansible/execution-environment/Containerfile` through
`scripts/build-ansible-execution-environment.sh` with an approved base image
digest. The wrapper rejects a tag-only or malformed base image before the
container engine resolves `FROM`; the Containerfile repeats the same check as
defense in depth. Supply the full lowercase source commit with
`--source-revision`; the resulting OCI revision, release-version, and base-name
labels are checked after the build. The wrapper then exercises the image under
an unprivileged numeric UID, verifies the exact locked Ansible Core, Ansible
Runner, and ansible-lint versions, requires their entry points plus the
Git/GPG/SSH and shell commands used by the controller boundary, and runs a
localhost Ansible ping. The final image also
defaults to a named numeric UID/GID 65532 identity, a private writable `/runner`
home/workspace, the standard Ansible EE marker, and a hash-locked `dumb-init`
entrypoint for PID 1 signal forwarding; a base image cannot silently restore a
root user or unrelated startup command. Record the final pushed image
digest, source commit, package lock, SBOM, signature, and vulnerability-scan
result in the release manifest's Ansible execution-environment object. The
controller must inject the same immutable digest into applied jobs and expose
the trusted value as `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST`; preflight
compares both bindings with the manifest before proceeding. Controller
preflight also checks the live Ansible Core, `ansible-runner`, and
`ansible-lint` versions against the pinned execution-environment requirements.

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
- validate SPDX 2.3 with the official SPDX validator (or CycloneDX 1.6/1.7
  against its matching official JSON schema) before sealing the evidence;
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

Provider digesting rejects links, special files, non-portable or
case-colliding names, files larger than 64 MiB, trees larger than 10,000 files
or 20,000 total entries, and trees whose regular-file content exceeds 256 MiB.
It snapshots path identity before and after measurement and fails if the tree
changes, so a digest cannot silently combine two concurrent provider states.

The command returns the `sha256:`-prefixed manifest form. Store that full form
as `release.provider_bundle.remote_digest`; Ansible's provider group variables
use the same digest without the prefix.
Tree digests deliberately accept only ASCII letters, digits, `.`, `_`, `-`,
and `/` in relative filenames. Both the CLI and Ansible enforce this before
serializing `path:sha256` rows, preventing delimiter ambiguity and
cross-platform filename drift.

For Quadlet, the reviewed directory must contain
`archiveweaver-<solution-id>.network`, `archiveweaver-<solution-id>.volume`,
and `<solution-id>.container`; the network and volume are deliberately
solution-scoped to prevent cross-service collisions on a shared host.

Do not use floating tags, unreviewed collections, mutable Git branches, or
credentials in build arguments. The readiness gate rejects placeholders,
absolute/out-of-bundle paths, digest mismatches, and unverified artifact
records.

## Release validation toolchain

`requirements/release-tools.txt` locks the complete 51-package validation and
build toolchain to SHA-256-verified binary wheels for CPython 3.14 on Linux
x86_64. It also binds `setuptools`, so release builds use `python -m build
--no-isolation` and source-distribution installation uses
`--no-build-isolation`; neither operation may silently resolve a different
backend from the network. Regenerate and validate the lock in a disposable
development environment with:

```bash
python -m pip install pip-tools==7.6.1
make release-tools-lock
make release-tools-check
```

The lock compiler resolves only wheels for the declared release-runner target,
rejects ambiguous wheel metadata and unpinned inputs, and fails if any package
shared with the Ansible controller lock resolves to a conflicting version.
Dependabot monitors the direct input, while CI, release validation, and the
security audit consume or inspect only the complete hash lock.

## Controller dependency SBOM

The Python distribution SBOM does not inventory the separately installed
Ansible controller environment. Generate its dedicated SPDX 2.3 document from
the exact hash lock, using the source commit timestamp so repeated builds of
the same release are byte-identical:

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python3 scripts/generate-ansible-sbom.py
python3 scripts/generate-ansible-sbom.py --check
pyspdxtools -i archiveweaver-ansible-controller.spdx.json
```

The generator fails closed on unpinned requirements, unsupported active lock
syntax, missing or duplicate hashes, non-UTF-8 inputs, symlinked inputs or
outputs, and a missing deterministic timestamp. The SBOM identifies all 36
locked packages, every approved Linux x86_64 wheel digest for CPython 3.13 and
3.14, the dependency-manifest digest, and package URLs. The release workflow
generates the distribution SBOM and validates both documents with the SPDX
project's pinned validator before either crosses into the privileged job. The
privileged job only downloads digest-checked distributions and SBOMs, then
checksums, signs, verifies, attests, and publishes them.

## Promotion

Promotion is a signed change: catalog and tests, release verification, staging
preview, backup/restore evidence, manual approval, production apply, and
post-deployment verification. Store the resulting controller job record and
evidence index in immutable audit storage.

Repository automation reinforces this contract. The `Security` workflow runs
CodeQL, Bandit, and strict audits of the pinned Ansible controller and release
validation dependencies on pushes, pull requests, and a weekly schedule. The `Release
artifacts` workflow can validate an unsigned candidate through a manual run,
but its privileged inventory, signing, attestation, and publication job runs
only for a version-matching, cryptographically verified annotated `v*` tag
whose target is the workflow commit. That job must use a GitHub `release`
environment configured with required human reviewers, deployment restricted to
protected release tags, and the non-secret environment variable
`ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE` set to the approved base image's full
digest reference. Set `ARCHIVEWEAVER_RELEASE_ACTORS_JSON` to a bounded JSON array
of approved GitHub logins. Privileged jobs accept only push events for `v*` tags
and require both the original push actor and any rerun actor to be in that
environment-owned allowlist; a manual dispatch can validate but cannot publish.
Configure exactly one release-environment secret,
`ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN`, as an expiring fine-grained token or
GitHub App installation token scoped to this repository with **Administration:
read-only**, **Environments: read-only**, and **Metadata: read-only**. The
issuing principal must be able to inspect repository ruleset bypass actors.
The workflow uses that token only to read hosted controls, including the
immutable-release setting and environment secret names; release and asset writes continue to use
the short-lived built-in `GITHUB_TOKEN`. Do not grant the settings token
Contents, Packages, or Administration write access, and do not add unrelated
environment secrets. Restrict GHCR package write access to this release
workflow and approved administrators, enable immutable GitHub Releases, and
consume the controller image only by the digest in its signed publication
record. The workflow itself refuses to overwrite an existing release image
tag with different content. A retry may reuse the tag only when the remote
manifest's config digest exactly matches the previously validated local image
ID. An ambiguous registry lookup fails closed instead of attempting a push;
registry immutability and permissions remain the external enforcement boundary.

Run `GITHUB_REPOSITORY=owner/repository make github-audit` with a read-only
administrative audit credential before release activation and after any hosted
settings change. `scripts/audit-github-production-controls.py` reads twelve
repository, Actions, security, environment, and ruleset controls and returns a
nonzero status unless all are proven. The JSON certificate records the
authoritative repository identity, stable numeric and node IDs, the clean
checkout's existing GitHub-verified full commit SHA, API version, and UTC audit
time. The source commit must be reachable from protected `main`, preventing a
release tag from selecting an unreviewed side-branch commit. The credential
therefore needs read-only Administration, Contents,
Environments, and Metadata access. Reference that file
from `release.github_controls.path`, copy its repository identity and commit
into the corresponding release fields, and bind its exact SHA-256 digest,
non-empty Sigstore bundle, and passing identity-verification record in the rest
of the `release.github_controls` object. The report, signature bundle, and
verification record must be distinct indexed files. The canonical Sigstore
v0.3 keyless bundle's embedded blob digest and the release-provenance subject
must both bind the report bytes. Run readiness within 24 hours. Reports with
unknown fields, duplicate/missing controls, stale
timestamps, mismatched source identity, unsigned or mismatched bytes, or any
non-passing control are rejected.
The auditor performs no writes. Because GitHub's
documented deployment-policy response omits the branch-versus-tag type, archive
the environment configuration change and a successful protected-tag release
deployment alongside the JSON audit output.
The privileged release job reruns the auditor after actor authorization and
before the first registry mutation, then includes the passing certificate in
`SHA256SUMS`, Sigstore signing, provenance attestation, the short-lived complete
workflow artifact, and the immutable GitHub Release.

The quality gate runs Ruff over application, test, and automation code and
strict mypy over both the application package and every Python automation
script. The release-tools lock includes the matching PyYAML stubs, so YAML
validators and controller-contract code are not excluded from static typing.

GitHub Release publication is also fail closed. The validated job transfers the
reviewed standard-library publisher into the credentialed job as a
digest-checked artifact; the credentialed job never checks out mutable source.
Before creating a draft, uploading an asset, or publishing, the publisher uses
the read-only settings token to confirm that immutable releases are enabled.
It re-verifies the signed annotated tag at the publication boundary, stages all
assets in a draft, and compares each existing asset's name, uploaded state,
size, and server-reported SHA-256 digest with the local file. Exact assets are
reused, missing assets are uploaded without replacement, and different or
unexpected assets stop the run. It publishes only a complete draft, then reads
the release back and requires `immutable: true`; an already published release
is accepted only when it is immutable and byte-for-byte complete. No path uses
`gh release upload --clobber`. Every GitHub CLI operation has a bounded timeout
and an indeterminate timeout is a hard failure, never a reason to retry a
mutation blindly. If an interrupted draft contains a rerun-specific
signature or scan file whose bytes have changed, publication deliberately
stops for operator inspection instead of deleting or replacing evidence.
Before any mutation, the publisher also bounds the local set to 64 assets,
1 GiB per asset, and 2 GiB in aggregate. Every asset must remain a regular,
single-link file with no symlink or Windows reparse-point component while it is
hashed; identity, size, and modification changes fail the run. GitHub API
responses are parsed as strict JSON: duplicate object keys and non-finite
numbers are rejected rather than interpreted ambiguously.

The workflow records SHA-256 checksums, emits a distribution SPDX SBOM, accepts
the independently validated Ansible controller SPDX SBOM, builds and scans the
non-root controller image, validates its SPDX SBOM, and revalidates the
transferred image identity, Ansible EE marker, numeric user, `/runner` working
directory, `dumb-init` entrypoint, default command, and actual default-runtime
identity before granting registry credentials. It creates
and verifies Sigstore signatures for package files, checksum and evidence
manifests, SBOMs, scan output, and the final image publication record; signs and
verifies the GHCR digest; attaches and verifies the image's SPDX attestation;
and creates GitHub build-provenance attestations for package, publication, and
image subjects. These checks improve the repository's supply-chain
baseline but do not replace the operator-owned manifest, detached signatures,
provider-bundle proof, execution-environment proof, or immutable evidence
retention required by the readiness gate.

Package timestamps are bound to the source commit's Unix timestamp. The wheel
build honors `SOURCE_DATE_EPOCH`; the source archive is then rewritten in
canonical path order with that timestamp and neutral ownership metadata. CI
checks the normalized archive, rebuilds both distribution formats independently,
and rejects any byte difference before installation or release.
