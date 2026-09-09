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
| Change and evidence identity | change ticket, operator, fixture set, timezone-qualified timestamps |

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
| Governance | Service owner | Risk review, approver, change record, immutable/access-logged retention, and retention-control evidence |
| Support | Service owner | Service owner, primary/secondary on-call, approved SLA, RPO/RTO agreement, and current runbooks |

## Controller activation

The platform owner must configure the approved automation controller with:

1. a project pinned to a full signed commit;
2. `ARCHIVEWEAVER_IMMUTABLE_REF` set to that commit SHA;
3. `ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS` set to the approved signer list;
4. `ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` set as protected metadata to the
   SHA-256 of the approved operator readiness manifest;
5. the exact execution-environment image digest in both the controller metadata
   and `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST`;
6. separate read-only, staging, production-change, certification, restore,
   and audit credentials;
7. the `archiveweaver-production` single-flight lock and manual approval nodes;
8. immutable, access-logged job and evidence retention;
9. the scheduled verification, restore, and failure-domain workflows from
   `deploy/ansible/controller/workflow.yml`.

For every reviewed certification, drill, rollback, and evidence-publication
hook, bind the executable's lowercase SHA-256 digest alongside its argv. The
Ansible hook preflight rejects relative paths, symlinks, missing files, and
byte changes before execution.

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
health endpoint, or SLA/on-call change. Freeze promotion and preserve the
evidence index after any signature, fixity, alert, restore, or rollback failure.
