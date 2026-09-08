# ArchiveWeaver Ansible edition

This directory is the enterprise-oriented orchestration layer for ArchiveWeaver.
It provides a reviewed inventory shape, fail-closed approval gates, idempotent
host preparation, provider envelopes, check-mode/diff workflows, rolling
execution, repair gates, and per-host evidence. It does not turn an upstream
archive product into a universal one-command installer.

Ansible is an orchestration layer, not a runtime or an HA system. The variable
`archiveweaver_runtime` selects the underlying provider envelope:

- `raw` — managed systemd unit;
- `podman-quadlet` — managed Quadlet unit;
- `docker` — validates and reconciles a separately staged official Compose stack;
- `docker-swarm` — validates and deploys a separately staged official Swarm stack;
- `k3s`, `rke2`, `k0s`, `microk8s` — validates and applies a separately staged official Kustomize bundle from a control host;
- `pacemaker` — deliberately fail-closed; resource definitions remain a
  change-controlled cluster runbook.

The product's official application, database, search, queue, object-storage,
ingress, migration, backup, and fixity assets must be supplied as one tested
release set. The playbooks refuse to apply while that release set, backup
verification, approval ticket, and release manifest are not explicitly marked
ready. Docker/Swarm/Kubernetes provider tasks also refuse to overwrite a
staged product bundle with the generic ArchiveWeaver envelope.

## Bootstrap a working copy

```bash
cd deploy/ansible
cp inventory/production/hosts.yml.example inventory/production/hosts.yml
cp inventory/staging/hosts.yml.example inventory/staging/hosts.yml
cp inventory/restore/hosts.yml.example inventory/restore/hosts.yml
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
cp release-manifest.example.json release-manifest.json
ansible-vault encrypt group_vars/all/vault.yml
python3 -m pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml
```

Every operational playbook checks the controller's live `ansible-playbook`
Core version against `requirements.txt` before it executes. This includes
certification, restore, failure-domain, and rollback paths.

Edit the copied inventory and `group_vars/all/main.yml`. Give every managed
multi-node host an explicit `archiveweaver_failure_domain` label, and give the
control plane enough distinct domains for the declared topology. Production
preflight rejects unlabeled managed nodes. Keep the encrypted
`vault.yml` outside pull requests unless the repository's secret-management
policy explicitly permits encrypted blobs. Prefer an approved execution
environment and external secret manager for production credentials.

Run `archiveweaver readiness --manifest release-manifest.json` from this
controller working directory and keep the default manifest path in `main.yml`
only after it reports 100/100. Before that gate can pass, create and verify the
SHA-256 index named by the manifest's `evidence_index` field; all referenced
artifacts and evidence must be listed in that index. The playbooks re-run that
controller-side check before any mutation; setting a boolean gate alone is
insufficient.
Host preparation also constrains the managed data, log, and release-record
paths to `/srv/archiveweaver/`, `/var/log/archiveweaver/`, and
`/etc/archiveweaver/` respectively, so an inventory typo cannot redirect
directory creation or ownership changes into a broad system path.
For Ansible releases, the manifest's `release.provider_bundle` must identify
the reviewed provider bundle, its artifact `digest`, and the canonical
`remote_digest` of the content staged on managed hosts. The preflight role
binds the latter to the staged remote content.

For Docker or Swarm, set `archiveweaver_product_stack_sha256` to the reviewed
Compose/Swarm file digest and set `remote_digest` to the same digest when the
staged file is the reviewed artifact. For Kubernetes-family runtimes, set
`archiveweaver_kustomize_bundle_sha256` to the deterministic digest of the
staged Kustomize file set (sorted paths relative to the bundle root) and record
that value as `remote_digest`. Apply and
repair reject content that does not match these release bindings. For raw
systemd, set `archiveweaver_provider_bundle_sha256` to the SHA-256 of the
rendered unit; for Podman Quadlet, use the deterministic digest of the three
rendered files (`network:<sha256>`, `volume:<sha256>`, and
`container:<sha256>` joined with newlines).

The repository CLI computes these bindings without relying on
platform-specific archive metadata:

```bash
PYTHONPATH=../../src python3 -m archiveweaver provider-digest \
  --kind file --path /path/to/reviewed-compose.yml
PYTHONPATH=../../src python3 -m archiveweaver provider-digest \
  --kind tree --path /path/to/reviewed-kustomize
PYTHONPATH=../../src python3 -m archiveweaver provider-digest \
  --kind quadlet --path /path/to/quadlet --service-name paperless-ngx
```

Use the returned `sha256:...` value as `release.provider_bundle.remote_digest`;
strip the `sha256:` prefix for the matching Ansible group variable, which
expects the bare 64-character hexadecimal value. The staged content must be
byte-for-byte identical to the reviewed binding.
For raw and Quadlet, the mutation-time digest check is intentionally skipped by
`--check` because Ansible does not write the candidate template in check mode;
the real apply and the read-only verification playbook hash the deployed files.
Quadlet image references are additionally required to use a full SHA-256
digest; mutable image tags are not accepted by the provider role.

Every passing evidence record must carry the exact solution, provider/runtime,
OS, release, environment, operator, fixture-set, and timezone-qualified
timestamp fields required by the readiness contract. For Ansible evidence,
also carry the exact `release.execution_environment.digest` used by the
controller. JSON evidence files must
also contain a matching `status: pass` payload; the evidence index alone does
not make an empty or unrelated file valid.
Set `archiveweaver_evidence_environment` to the release target (normally
`production`). Certification and drill roles additionally record their actual
isolated execution environment, so staging/restore infrastructure can prove a
production release without mislabeling the test location.

## Safe execution sequence

Run from this directory so `ansible.cfg` and the local roles are selected:

```bash
bash ../../scripts/validate-ansible.sh

# Or run the individual checks when diagnosing one playbook:
ansible-playbook site.yml --syntax-check
ansible-lint site.yml verify.yml repair.yml product-certification.yml restore-drill.yml failure-drill.yml rollback.yml

# Review changes without applying them. The explicit apply variable makes the
# playbook calculate the real mutation set; --check still prevents changes.
ansible-playbook site.yml --check --diff -e archiveweaver_apply=true

# Apply only after the approval, backup, release-manifest, and product-stack
# gates in group_vars/all/main.yml have been reviewed and set true.
ansible-playbook site.yml -e archiveweaver_apply=true

# Collect read-only verification and evidence.
ansible-playbook verify.yml

# Run the product matrix in the isolated certification environment. Supply
# the five reviewed argv hooks and an approved certification change ID.
ansible-playbook -i inventory/staging/hosts.yml product-certification.yml --check --diff
ansible-playbook -i inventory/staging/hosts.yml product-certification.yml -e archiveweaver_certification_apply=true

# Preview the approved restore/fixity drill against a non-production inventory.
ansible-playbook -i inventory/restore/hosts.yml restore-drill.yml --check --diff

# Preview failure-domain hooks in staging and a release rollback plan.
ansible-playbook -i inventory/staging/hosts.yml failure-drill.yml --check --diff
ansible-playbook rollback.yml --check --diff
```

`archiveweaver_apply` defaults to `false`. An apply or check-mode apply also
requires `archiveweaver_approval_ticket`, `archiveweaver_backup_verified`,
`archiveweaver_release_manifest_verified`, `archiveweaver_product_stack_ready`,
and a non-placeholder release. Secrets are never placed on the command line.
The verification playbook re-runs the 100/100 identity gate and re-hashes and
re-renders the staged provider bundle, so post-deployment drift fails closed.
For production exceptions, `archiveweaver_topology_design_approved` gates
multi-node raw/Compose/Quadlet designs, while
`archiveweaver_single_node_production_approved` gates single-node
Kubernetes/Swarm designs; each requires a documented review and does not
claim that Ansible supplies HA.

## Repair

The repair playbook is separate from deployment and defaults to read-only:

```bash
ansible-playbook repair.yml --syntax-check
ansible-playbook repair.yml --check --diff
ansible-playbook repair.yml -e archiveweaver_repair_apply=true
```

When invoking repair through the CLI, pass the non-secret evidence identity or
bind it in the protected inventory variables:

```bash
archiveweaver repair --solution paperless-ngx --mode ansible \
  --underlying-mode rke2 --operator release-operator \
  --fixture-set paperless-fixtures-v1 --json
```

Service restarts and provider reconciliation are limited to named resources.
There is no volume deletion, PVC deletion, data purge, TLS-verification
bypass, authentication bypass, cluster reset, or automatic Pacemaker resource
creation. Pacemaker repair additionally requires both an explicit allow flag
and verified fencing state.

`product-certification.yml` is separate from production apply. It accepts only
staging/restore/DR targets, requires exactly five reviewed hooks (`dependencies`,
`smoke`, `migration`, `formats`, and `api`), suppresses hook output, writes
return-code-only evidence, and seals it into the shared index.

`rollback.yml` is approval-gated, requires a pinned previous artifact and
verified backup, and requires two separate reviewed argv hooks. The readiness
manifest must carry the previous artifact bytes, SBOM, detached signature, and
signature-verification evidence bound to its digest:
`archiveweaver_rollback_command` performs the rollback and
`archiveweaver_rollback_verify_command` proves the previous release is healthy.
The previous release and artifact digest must also match the recovery binding
in the reviewed readiness manifest.
The rollback evidence records both return codes without storing hook output.
Compose and Kustomize provider paths are restricted to
`/etc/archiveweaver/<solution>/` so reviewed content cannot be sourced from an
unbounded host path.

## Enterprise operating model

For a premium production service, run these playbooks from a pinned Ansible
execution environment through a controlled automation controller. Use signed
and reviewed content, RBAC-separated credentials, Vault or an external secret
manager, protected inventories, approval nodes, serial/rolling execution,
central job history, immutable evidence storage, and scheduled restore/fixity
tests. In every non-check-mode production evidence run, supply the reviewed
archiveweaver_evidence_publish_command and
archiveweaver_evidence_verify_command hooks together with the retention,
immutability, and access-logging bindings. The repository supplies the safe
content boundary; an automation controller and operational policy provide the
organization-level governance.

Enable the managed read-only health timer with
`archiveweaver_observe_enabled: true` only after installing the ArchiveWeaver
checker on the host and setting an HTTPS health URL. It writes results to the
system journal; the controller workflow is responsible for alert routing,
retention, and escalation.
