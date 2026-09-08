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
  --output deploy/ansible/generated/paperless-rke2.yml
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

Generated entry points keep both mutation and verification disabled by default;
enable them only after binding the release manifest, operator, fixture set, and
provider content, or use the dedicated `verify.yml` workflow.

The generic provider renderer is intentionally incomplete. Stage the upstream
product's official application, database, search, queue, object-storage,
ingress, and migration content as one pinned and tested release set at the
configured Compose or Kustomize path before setting
`archiveweaver_product_stack_ready: true`; the Ansible provider refuses to
overwrite or apply the generic envelope as a substitute. Docker/Swarm stacks
and Kubernetes Kustomize bundles must also match their configured SHA-256
release binding before apply or repair.

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
- for Pacemaker repair, explicit fencing permission and verified STONITH.

Topology exceptions are separate gates: set
`archiveweaver_topology_design_approved: true` only for a reviewed multi-node
Compose, raw, or Quadlet design, and set
`archiveweaver_single_node_production_approved: true` only for a documented
single-node Kubernetes/Swarm edge exception. These approvals do not make the
underlying runtime highly available; they record that the limitation was
accepted before mutation.

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

The command scores ten independently evidenced domains. It returns success
only at 100/100; placeholders, missing files, failed tests, or evidence paths
outside the manifest bundle keep the deployment non-ready. The manifest's
`evidence_index` must be a verified SHA-256 index, and every file referenced by
the manifest must be listed in that index. The Ansible preflight role reruns
the controller-side command before apply or repair. For apply, repair, and
verification it also derives the managed host's catalog OS identifier from
Ansible facts and rejects a mismatch with `archiveweaver_os_id`.
See [`premium-readiness.md`](../operations/premium-readiness.md) for the
contract and ownership model.

The product-specific test requirements are in
[`product-certification.md`](../operations/product-certification.md), and the
on-call, incident, SLA, and evidence lifecycle is in
[`service-management.md`](../operations/service-management.md).

The pinned controller-image and artifact promotion contract is in
[`supply-chain.md`](../operations/supply-chain.md).
