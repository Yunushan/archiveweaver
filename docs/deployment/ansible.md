# Ansible enterprise orchestration

ArchiveWeaver now includes an Ansible edition for controlled, repeatable
deployment and recovery workflows. It is deliberately layered over the
existing provider modes instead of pretending that Ansible is a workload
runtime.

## What level exists today?

| Level | What ArchiveWeaver provides | What it does not claim |
| --- | --- | --- |
| Current core | Catalog, topology policy, read-only checks, provider envelopes, plan-only repair, tests, and documentation | Vendor support, a complete product stack, application certification, or an SLA |
| Ansible enterprise baseline | Version-controlled inventory shape, FQCN-based roles, host preflight, least-privilege service identity, serial execution, `any_errors_fatal`, check-mode/diff workflow, explicit approval/backup/release gates, Vault boundary, named-resource repair, and redacted evidence | HA, quorum, fencing, database/search/storage replication, or product-specific migrations |
| Premium operating service | A pinned execution environment, controlled automation controller, RBAC-separated credentials, signed content, approval workflow, centralized job history, immutable evidence retention, restore/fixity drills, monitoring, and an organizational support/SLA process | These controls cannot be created by a repository playbook alone; they require the operator's platform and governance |

The repository is currently an alpha, production-aware automation framework—not
a vendor-supported premium service. The Ansible baseline raises the delivery
quality substantially, but production certification still requires a tested
release set for the selected archive product and its dependencies.

## Provider selection

Set `archiveweaver_runtime` in `deploy/ansible/group_vars/all/main.yml`:

| Underlying runtime | Ansible behavior |
| --- | --- |
| `raw` | Creates a hardened systemd unit and starts the named service |
| `podman-quadlet` | Creates network, volume, and container Quadlet units |
| `docker` | Validates and reconciles the separately staged, official product Compose stack |
| `docker-swarm` | Validates and deploys the separately staged, official product Swarm stack |
| `k3s`, `rke2`, `k0s`, `microk8s` | Validates and applies the separately staged product Kustomize bundle from the designated control host |
| `pacemaker` | Inspects state only; resource creation remains a reviewed runbook |

The CLI can generate a provider-specific Ansible entry point. For example:

```bash
archiveweaver render \
  --solution paperless-ngx \
  --mode ansible \
  --underlying-mode rke2 \
  --nodes 3 \
  --os ubuntu-24.04 \
  --output generated/paperless-rke2.yml
```

Use the same provider binding when reviewing a plan so the topology policy is
evaluated against RKE2 rather than against Ansible's orchestration layer:

```bash
archiveweaver plan \
  --solution paperless-ngx \
  --mode ansible \
  --underlying-mode rke2 \
  --nodes 3 \
  --os ubuntu-24.04
```

Generated entry points keep both mutation and verification disabled by default
and are review artifacts. Production controller and CLI operations use the
fixed approved playbooks through `scripts/run-ansible-operational.sh`; do not
invoke a generated path directly for a production mutation. Bind the release
manifest, operator, fixture set, and provider content through the approved
inventory and workflow, or use the dedicated `verify.yml` workflow.

The generic provider renderer is intentionally incomplete. Stage the upstream
product's official application, database, search, queue, object-storage,
ingress, and migration content as one pinned and tested release set at the
configured Compose or Kustomize path before setting
`archiveweaver_product_stack_ready: true`; the Ansible provider refuses to
overwrite or apply the generic envelope as a substitute. Docker/Swarm stacks
and Kubernetes Kustomize bundles must also match their configured SHA-256
release binding before apply or repair, and every rendered product image must
use an approved full `@sha256:` digest rather than a mutable or placeholder
tag. The controller also compares the complete rendered image set with the
signed, indexed `release.artifacts[].image` set before apply and during
independent verification; digest syntax alone is not release proof.
For Kubernetes, Ansible sends those checked rendered bytes directly to
`kubectl apply -f -`, so mutation does not re-render the Kustomize tree.
For a Kubernetes-family runtime, set `archiveweaver_kubeconfig` to the
protected absolute kubeconfig path on the designated control host and
`archiveweaver_kube_context` to its reviewed cluster context. Preflight
also requires `archiveweaver_kubeconfig_sha256`, the file's approved bare
64-character SHA-256 digest, for apply, verification, repair, and staging
preview. Apply and repair recheck the digest immediately before mutation.
The kubeconfig must be root-owned, regular, non-symlinked, and mode 0600 or
0640; copy a user-owned config to a protected root-owned path before use.
All Ansible `kubectl` commands pass the kubeconfig and context flags explicitly.
Controller jobs using an older binding set must supply both new values before
running again.

Raw systemd and Quadlet templates are rendered into a private host staging
directory and hash-checked before they are copied into the active service path;
an apply cannot leave a newly rendered live unit behind a failed digest gate.

In the readiness manifest, identify this deployment as
`service.runtime: ansible` and set `service.underlying_runtime` to the selected
provider (for example, `rke2`). This prevents a release certified for one
provider from being applied through another.

## Apply gates

Ansible will not mutate a target while the following are not explicitly ready:

- `archiveweaver_apply: true` or `archiveweaver_repair_apply: true`;
- a non-placeholder pinned release and change ID;
- a non-empty approval ticket;
- verified restorable backup;
- verified release manifest;
- verified product dependency/application stack;
- for non-systemd providers, an HTTPS health endpoint with certificate validation;
- for Pacemaker repair, explicit fencing permission and verified STONITH.

Topology exceptions are separate gates: set
`archiveweaver_topology_design_approved: true` only for a reviewed multi-node
Compose, raw, or Quadlet design, and set
`archiveweaver_single_node_production_approved: true` only for a documented
single-node Kubernetes/Swarm edge exception. These approvals do not make the
underlying runtime highly available; they record that the limitation was
accepted before mutation.
Two-node Docker Swarm is rejected for deployment and repair even with external
quorum or storage flags; multi-node Swarm needs at least three manager hosts.

The default inventory and variable files are examples. Copy them into the
operator-only paths, encrypt the Vault file, and use a protected execution
environment. Label control hosts with distinct failure domains (availability
zone, rack, or equivalent); the preflight role checks that diversity before
mutation. No secret is passed in CLI arguments or written to evidence.
Host preparation bounds data, log, and release-record paths to the dedicated
`/srv/archiveweaver/`, `/var/log/archiveweaver/`, and `/etc/archiveweaver/`
prefixes before it creates or owns them.

## Recommended pipeline

```text
catalog validate
       ↓
inventory and release review
       ↓
syntax-check + ansible-lint
       ↓
staging check-mode/diff
       ↓
product certification and failure-domain drill
       ↓
backup and fixity gate
       ↓
100/100 readiness gate
       ↓
serial production apply
       ↓
read-only verification and evidence
       ↓
product smoke, restore, and failure tests
```

The exact commands and role layout are in [`deploy/ansible/README.md`](../../deploy/ansible/README.md).
Read-only verification also re-hashes and re-renders the staged provider
bundle, catching post-deployment drift before the evidence is accepted.

## 100-point readiness gate

Before a production mutation, create the operator-owned readiness manifest
from `deploy/ansible/release-manifest.example.json` and run:

```bash
PYTHONPATH=src python3 -m archiveweaver readiness \
  --manifest deploy/ansible/release-manifest.json \
  --json
```

The command scores ten independently evidenced domains. Ordinary production
apply, repair, rollback, and verification require success at 100/100;
placeholders, missing files, failed tests, or evidence paths
outside the manifest bundle keep the deployment non-ready. The manifest's
`evidence_index` must be a verified SHA-256 index, and every file referenced by
the manifest must be listed in that index. The Ansible preflight role reruns
the controller-side command before apply or repair. For apply, repair, and
verification it also derives the managed host's catalog OS identifier from
Ansible facts and rejects a mismatch with `archiveweaver_os_id`.
Release integrity additionally requires a fresh `make github-audit` JSON
certificate for the manifest's exact GitHub repository ID and source commit;
all twelve hosted production controls must pass, and the indexed report expires
for scoring after 24 hours.
See [`premium-readiness.md`](../operations/premium-readiness.md) for the
contract and ownership model.

### First Paperless-ngx installation on RKE2

The first production installation has a separate, on-demand controller branch.
It is limited to Paperless-ngx on a three-or-more-node RKE2 inventory whose
dedicated namespace, release record, data root, and log root do not exist.
Use it only after a real staging installation and product certification,
restore, failure, repair, and rollback drills there. A distinct on-demand
`staging-seed-apply` job can create the first staging installation when the
ordinary staging apply is blocked by its 100/100 gate. Its protected staging
manifest must have valid `control`, `release`, `governance`, and `support`
evidence, no validation errors, and a score from 40 to 90. A separate
`staging_seed_authorization` with `purpose: first-staging-apply` binds the
exact staging service, release, signed source, execution environment, provider,
Kustomize, kubeconfig, cluster context, namespace, and approval. Protect its
canonical JSON digest in `ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256`.
Protect the root-owned staging inventory bytes separately in
`ARCHIVEWEAVER_STAGING_INVENTORY_SHA256` and bind that digest into the
authorization object.
The seed is limited to an empty staging target, creates the namespace once,
and forces service verification and staging-only evidence publication. It
cannot use the production bootstrap authorization. Run certification and
drills only after the seed evidence is reviewed.

The protected production manifest must score exactly 90/100 with all domains
except `observability` passing and with no validation errors. A distinct
`bootstrap_authorization` object in that manifest binds the exact release,
signed source commit, execution environment, provider and Kustomize digests,
kubeconfig and context, namespace, change ticket, approval ticket, and
approver. The controller holds its canonical JSON SHA-256 digest in
`ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256`, protected independently from
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256`. Authorization is valid for at most
24 hours and also binds the root-owned production inventory digest held in
`ARCHIVEWEAVER_PRODUCTION_INVENTORY_SHA256`. It
must fall within the governance approval window, and needs a
different approver from the change operator. See the exact field contract and
digest calculation in the [controller guide](../../deploy/ansible/controller/README.md).

After separate human approval, the bootstrap job runs `site.yml` with
`archiveweaver_apply=true` and `archiveweaver_bootstrap_apply=true` against the
complete production inventory. It verifies the empty target before mutation,
limits every rendered Kubernetes resource to the approved namespace, and
rechecks and atomically creates that namespace immediately before applying
the validated rendered bytes. The control-host verification record includes
the claimed namespace UID. The same playbook forces post-apply verification
and evidence sealing. Bootstrap never reports a
100/100 score. Promote the resulting production observations into the
protected evidence index and manifest, then run the ordinary 100/100 gate.
Before writing a release record, the provider compares every live Deployment,
StatefulSet, Job, and CronJob image in the dedicated namespace with the
reviewed rendered model and rejects extra or changed workloads.
A partially applied bootstrap cannot be retried as first use; it requires a
separately approved incident and recovery procedure.

The product-specific test requirements are in
[`product-certification.md`](../operations/product-certification.md), and the
on-call, incident, SLA, and evidence lifecycle is in
[`service-management.md`](../operations/service-management.md).

The pinned controller-image and artifact promotion contract is in
[`supply-chain.md`](../operations/supply-chain.md).
The owner-by-owner activation checklist is in
[`premium-activation.md`](../operations/premium-activation.md).
