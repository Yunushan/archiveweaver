# Premium service activation

This runbook turns the ArchiveWeaver automation framework into one operated
service. It is intentionally an activation procedure, not a sample evidence
bundle: operators must record facts from the selected product release,
controller, infrastructure, and approved service organization.

## Activation decision

Choose and record one immutable service identity before collecting evidence:

| Decision | Required binding |
| --- | --- |
| Product and exact release | `service.solution_id`, `release.version` |
| Ansible provider and underlying runtime | `service.runtime: ansible`, `service.underlying_runtime` |
| Host baseline and target | `service.os_id`, `service.environment` |
| Topology and failure domains | production inventory, `resilience` evidence |
| Change and evidence identity | change ticket, operator, fixture set, timezone-qualified timestamps, approval expiry |

Do not certify a release for one product, runtime, OS, or environment and then
reuse the manifest for another. The readiness command binds all evidence to
this identity and the Ansible preflight checks it again before mutation.

## Evidence ownership

The following inputs are required before the readiness command can return
100/100. The named owner must supply the evidence; a boolean or a placeholder
identifier is not proof.

| Domain | Owner | Required activation input |
| --- | --- | --- |
| Control | Release/platform owner | Validated catalog, green CI record, approved change ticket |
| Release | Release owner | Product artifacts, provider bundle, exact SHA-256 digests, SPDX/CycloneDX SBOMs, detached signatures, signature-verification records, in-toto provenance, and the pinned Ansible execution-environment image |
| Product | Product owner | Dependency, smoke, migration, format/preservation, and API tests using the selected release and representative fixture set |
| Resilience | Platform/product owner | Quorum and fencing review plus node, service, dependency, and storage failure drills |
| Data protection | Preservation owner | At least two immutable backup copies, clean-environment restore, fixity result, and measured RPO/RTO |
| Security | Security/platform owner | Dedicated SBOM, TLS, secret-provider, vulnerability-scan, and penetration-review evidence |
| Observability | SRE/platform owner | Metrics, alert rules, dashboards, on-call rotation, and delivered-alert test |
| Recovery | Release/platform owner | Different pinned previous release, signed artifact, rollback test, and named-resource repair test |
| Governance | Service owner | Risk review, approver, current approval window (maximum 30 days), change record, immutable/access-logged retention, and retention-control evidence |
| Support | Service owner | Service owner, primary/secondary on-call, approved SLA, RPO/RTO agreement, and current runbooks |

## Repository release prerequisites

Before creating the first production tag, apply a repository ruleset to
`main` that requires pull requests, at least one independent approval,
CODEOWNERS review for workflow/lock/controller changes, resolved conversations,
signed commits, linear history, and the complete required CI and Security check
set; block force pushes and branch deletion, and configure no ruleset bypass
actors. Keep emergency access outside the normal ruleset path under the
documented incident process. Protect `v*` tags from update or deletion. Restrict Actions to
the reviewed actions used by this repository and enforce full commit-SHA
pinning. Enable dependency-graph vulnerability alerts, Dependabot security
updates, secret-scanning push protection and validity checks, and private
vulnerability reporting. These hosted controls are release gates, not optional
documentation conventions.

Configure the GitHub `release` environment with at least one reviewer who
cannot approve their own deployment, prevent administrator bypass where the
plan supports it, and restrict deployments to approved protected `v*` tags.
Define the non-secret environment variable
`ARCHIVEWEAVER_ANSIBLE_EE_BASE_IMAGE` as the security-reviewed base image's
complete `registry/repository@sha256:<64 lowercase hex>` reference; do not store
credentials or floating tags in that variable. Define
`ARCHIVEWEAVER_RELEASE_ACTORS_JSON` as a JSON array containing 1 to 32 explicitly
approved GitHub logins. Both the account that pushed the release tag and the
account that initiates a rerun must be listed; manual workflow runs are
validation-only and cannot reach privileged release jobs. Add the sole environment secret
`ARCHIVEWEAVER_RELEASE_SETTINGS_TOKEN` as an expiring, repository-scoped
fine-grained token or GitHub App installation token with repository
Administration, Contents, Environments, and Metadata **read-only** permissions. The
issuing principal must be able to inspect repository ruleset bypass actors.
Give it no write permission. The publisher
uses the built-in short-lived `GITHUB_TOKEN` for release writes and the separate
token only to verify the immutable-release setting immediately before mutation.
Give only the release workflow and approved administrators write access to the
repository's GHCR package, enable immutable GitHub Releases before the first
release, and prohibit manual replacement of published version tags.

After configuring these controls, authenticate `gh` with a read-only audit
credential that can inspect repository administration, Actions, environments,
and security settings, set `GITHUB_REPOSITORY=owner/repository`, and run
`make github-audit`, saving its JSON output at the path named by
`release.github_controls.path`. The target binds the report to the clean
checkout's full `HEAD`; copy the report's canonical repository name and numeric
ID into `release.source_repository` and `release.source_repository_id`, and
copy that commit into `release.source_revision`. Populate the remaining
`release.github_controls` fields with the report's SHA-256 digest, its
identity-verified Sigstore bundle, and a passing indexed signature-verification
record bound to that digest. The report, bundle, and verification record must
be distinct indexed files. The machine-readable audit must report all 12
controls as passing, resolve the source SHA to an existing GitHub-verified
commit reachable from protected `main`, and be less than 24 hours old when the
100-point gate runs.
It never changes GitHub state. The
GitHub REST response for a deployment branch policy currently omits whether the
pattern was created for a branch or tag, so retain the environment change record
and require a successful protected-tag deployment as the additional proof that
the `v*` policy is a tag policy.
The credentialed release job repeats the same audit after environment approval
and before its first registry or GitHub Release mutation. Its passing report is
checksummed, Sigstore-signed, build-attested, and published with the immutable
release evidence set; use that published report and bundle for the deployment
manifest rather than an unsigned local copy.

Create a version-matching, cryptographically signed annotated tag. Accept the
release only if the workflow validates both Python distributions, builds and
functionally tests the non-root Ansible Core/Runner execution environment,
reports no high
or critical image vulnerabilities, validates every SPDX document, signs and
verifies the artifacts and image, publishes build provenance, and emits the
signed `archiveweaver-ee.publication.json`. Copy that record's immutable image
digest—not its tag or local image ID—into the service release manifest. A
missing `release` environment, base-image variable, settings token, readable
immutable-release setting, or final immutable release state is an intentional
fail-closed condition.

## Controller activation

The platform owner must configure the approved automation controller with:

1. a project pinned to a full signed commit;
2. `ARCHIVEWEAVER_IMMUTABLE_REF` set to that commit SHA;
3. `ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS` set to the approved signer list;
4. `ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` set as protected metadata to the
   SHA-256 of the approved operator readiness manifest, whose
   `evidence_index_digest` field binds the exact sealed evidence index;
5. the exact execution-environment image digest in both the controller metadata
   and `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST`;
6. separate read-only, staging, production-change, certification, restore,
   and audit credentials;
7. the `archiveweaver-production` single-flight lock and manual approval nodes;
8. immutable, access-logged job and evidence retention;
9. the scheduled verification, restore, and failure-domain workflows from
   `deploy/ansible/controller/workflow.yml`.

For every reviewed certification, drill, rollback, and evidence-publication
hook, bind both the executable's lowercase SHA-256 digest and the complete
canonical argv digest. Generate the pair on the controller with
`archiveweaver hook-digest --json -- /absolute/hook arg`. The Ansible hook
preflight rejects relative paths, symlinks, missing files, byte changes, and
any unreviewed argument change before execution.

Run the controller contract validator and source check from the approved
checkout before importing the workflow:

```bash
python3 scripts/validate-controller-contract.py
bash scripts/verify-source-identity.sh "$ARCHIVEWEAVER_IMMUTABLE_REF"
```

The source check must run against a clean checkout. Do not weaken it to accept
a branch, unsigned commit, untracked controller code, or an unapproved signer.

## Product and infrastructure activation

The generic renderer is not the product stack. The product owner must stage
the selected upstream application's complete, tested dependency graph—such as
database, search, queue, converters, object storage, ingress, migrations, and
secret references—at the configured provider path. Bind its canonical digest
to `archiveweaver_product_stack_sha256` or
`archiveweaver_kustomize_bundle_sha256` as appropriate. Set
`archiveweaver_product_stack_ready: true` only after the stack has passed the
isolated product matrix.

The platform owner must replace every example inventory value, label actual
failure domains, verify non-root become access, install host prerequisites,
and provide the reviewed HTTPS health endpoint. Kubernetes-family providers
also require a protected kubeconfig and a verified staged Kustomize bundle.
Pacemaker requires an independently reviewed VIP, storage, resource, quorum,
and STONITH design; ArchiveWeaver does not invent those resources.

## Promotion sequence

Run the stages in this order and preserve their controller job records:

```text
source integrity
  -> catalog/tests and Ansible quality
  -> staging preview
  -> product certification
  -> failure-domain drill
  -> backup/restore/fixity drill
  -> readiness score
  -> manual production approval
  -> serial production apply
  -> mandatory post-apply read-only verification
  -> evidence publication and retention verification
```

The final readiness check is:

```bash
PYTHONPATH=src python3 -m archiveweaver readiness \
  --manifest deploy/ansible/release-manifest.json \
  --json
```

Proceed only when it returns `status: pass`, `score: 100`, and no errors. Then
run the controller's production verification workflow and confirm the
published evidence index can be verified from immutable storage. A local
SHA-256 index alone does not prove retention, access logging, monitoring, or
support coverage.

## Acceptance and re-certification

The service owner accepts activation only when all ten domains pass for the
same product/release/runtime/OS/environment identity and the post-deployment
verification is green. Re-run certification after any product release,
dependency, provider bundle, execution-environment, topology, backup policy,
health endpoint, hosted GitHub control, or SLA/on-call change. A hosted-control
certificate expires for scoring after 24 hours, so regenerate and reseal it
immediately before approval and production promotion. Every other passing
record is also subject to the domain cadence in
[`premium-readiness.md`](premium-readiness.md); in particular, backup proof
cannot be older than the declared RPO and vulnerability-scan proof expires
after seven days. Freeze promotion and preserve the evidence index after any
signature, fixity, alert, restore, or rollback failure.
