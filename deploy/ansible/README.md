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
# Create release-manifest-staging.json and release-manifest-restore.json only
# when those isolated workflows use distinct, protected manifest bindings.
ansible-vault encrypt group_vars/all/vault.yml
python3 -m pip install --require-hashes --only-binary=:all: -r requirements.txt
ansible-galaxy collection install -r requirements.yml
```

Every operational playbook checks the controller's live `ansible-playbook`,
`ansible-runner`, and `ansible-lint` versions against the pinned requirements
before it executes. This includes certification, restore, failure-domain, and
rollback paths.
`requirements.in` contains the direct controller pins. Install
`pip-tools==7.6.1` in a disposable development environment and run
`make ansible-lock` to regenerate the complete transitive lock and its
approved wheel hashes. The controller lock intentionally supports CPython
3.13 and 3.14 on Linux x86_64; another architecture requires its own reviewed
artifact set and execution validation rather than silently falling back to a
source build. Keep
`requirements.txt` and `execution-environment/requirements.txt` aligned;
`scripts/validate-ansible.sh` rejects lock drift or missing hashes. CI and the
execution image require the checked hashes and accept binary distributions
only, while the signed final execution-image digest binds the resolved
artifacts. Build the controller image with
`scripts/build-ansible-execution-environment.sh` so the immutable base digest
is validated before the container engine resolves `FROM`.
Controller workflows must invoke `bash ../../scripts/run-ansible-operational.sh`
from this directory for every operational playbook. The runner allowlists the
approved playbooks and rejects partial-target, task-selection, credential,
transport, and code-loading overrides (including `--limit`/`-l`, `--tags`/`-t`,
`--skip-tags`, `--start-at-task`, `--step`, and vault/key/user/connection
options). Use raw `ansible-playbook` only for syntax checks or local
diagnostics. The runner clears ambient Ansible configuration, credentials,
transport, inventory, module, collection, plugin, and Vault-path variables,
plus `PYTHONPATH` and `PYTHONHOME`, then pins `ANSIBLE_CONFIG` and
`ANSIBLE_ROLES_PATH` to this reviewed bundle.
Every invocation must provide exactly one of `inventory/production/hosts.yml`,
`inventory/staging/hosts.yml`, or `inventory/restore/hosts.yml`; arbitrary
inventory paths and inventory directories are rejected. The runner also
requires the selected inventory to exist as a regular file beneath the
physical reviewed inventory directory and rejects symlinked path components
before Ansible parses it. Extra variables must
be explicit key/value bindings listed in
`controller/allowed-extra-vars.txt`. Extra-vars files, raw
YAML/JSON variable documents, protected controller identity/parallelism
bindings, and `ansible_*` connection or privilege bindings are rejected.
After the playbook, only `--check`/`-C`, `--diff`/`-D`, `--syntax-check`, the
single approved inventory option, and explicit `-e`/`--extra-vars` bindings are
accepted. Extra positional playbooks, `--`, and any other unreviewed option
are rejected.
Applied operational playbooks also require the controller environment variable
`ARCHIVEWEAVER_IMMUTABLE_REF`, the approved signer list, and the protected
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` binding. They verify the signed,
clean Git checkout and exact manifest bytes before they contact managed hosts.
Check-mode previews remain available without that production-only source gate.

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
The release section must bind its GitHub owner/repository, numeric repository
ID, full source commit, and a less-than-24-hour-old indexed JSON report produced
by `GITHUB_REPOSITORY=owner/repository make github-audit`; all twelve hosted
production controls in that report must pass.
Controller-local readiness and evidence helpers run with the same
`ansible_playbook_python` interpreter that launched Ansible; overriding that
interpreter binding is rejected by controller preflight.
Host preparation also constrains the managed data, log, and release-record
paths to `/srv/archiveweaver/`, `/var/log/archiveweaver/`, and
`/etc/archiveweaver/` respectively, so an inventory typo cannot redirect
directory creation or ownership changes into a broad system path.
For Ansible releases, the manifest's `release.provider_bundle` must identify
the reviewed provider bundle, its artifact `digest`, and the canonical
`remote_digest` of the content staged on managed hosts. It must also carry an
indexed SBOM, detached signature, and signature-verification record. Every
release, provider, execution-environment, and rollback proof path must be
unique so one file cannot be presented as multiple independent attestations.
The release provenance must carry the provider bundle's artifact digest, and
the preflight role binds the latter remote digest to the staged content.

For Docker or Swarm, set `archiveweaver_product_stack_sha256` to the reviewed
Compose/Swarm file digest and set `remote_digest` to the same digest when the
staged file is the reviewed artifact. For Kubernetes-family runtimes, set
`archiveweaver_kustomize_bundle_sha256` to the deterministic digest of the
staged Kustomize file set (sorted paths relative to the bundle root) and record
that value as `remote_digest`. Apply and
repair reject content that does not match these release bindings. For raw
systemd, set `archiveweaver_provider_bundle_sha256` to the SHA-256 of the
rendered unit; for Podman Quadlet, use the deterministic digest of the three
solution-scoped rendered files (`network:<sha256>`, `volume:<sha256>`, and
`container:<sha256>` joined with newlines). The network and volume filenames
include the solution ID so multiple Quadlet services on one host cannot
silently share an ArchiveWeaver network or collide on provider definitions.
The generated Quadlet volume is a bind-backed named volume whose device is
`archiveweaver_data_root`; it does not silently create an unmanaged node-local
volume outside the controlled data path.

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
The staged Compose/Swarm file must remain a regular root-owned file without
group/world write permission; rendered raw units and Quadlet definitions use
mode `0644`. Verification checks ownership and permissions again after
deployment. Kubernetes bundle roots must remain root-owned directories without
group/world write permission.
For raw and Quadlet, the mutation-time digest check is intentionally skipped by
`--check` because Ansible does not write the candidate template in check mode;
the real apply renders into a private `.provider-staging` directory, verifies
the digest before copying anything into the active systemd/Quadlet path, and
the read-only verification playbook hashes the deployed files again.
Quadlet image references are additionally required to use a full SHA-256
digest; the Docker, Swarm, and Kubernetes provider roles apply the same
requirement to every image in their rendered product model. Mutable or
placeholder image references are not accepted by the provider roles.

Every passing evidence record must carry the exact solution, provider/runtime,
OS, release, environment, operator, fixture-set, and timezone-qualified
timestamp fields required by the readiness contract. For Ansible evidence,
also carry the exact `release.execution_environment.digest` used by the
controller. JSON evidence files must
also contain a matching `status: pass` payload; the evidence index alone does
not make an empty or unrelated file valid.
The readiness contract additionally requires dedicated passing evidence
records for security SBOM/TLS/secret-provider claims, each observability
surface and on-call rotation, and support ownership/on-call/SLA claims. The
human-readable values are identifiers only; they cannot replace indexed proof.
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
bash ../../scripts/run-ansible-operational.sh site.yml --check --diff -i inventory/production/hosts.yml -e archiveweaver_apply=true

# Apply only after the approval, backup, release-manifest, and product-stack
# gates in group_vars/all/main.yml have been reviewed and set true.
bash ../../scripts/run-ansible-operational.sh site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true

# Collect read-only verification and evidence.
bash ../../scripts/run-ansible-operational.sh verify.yml -i inventory/production/hosts.yml

# Run the product matrix in the isolated certification environment. Supply
# the five reviewed argv hooks and an approved certification change ID.
bash ../../scripts/run-ansible-operational.sh product-certification.yml --check --diff -i inventory/staging/hosts.yml
bash ../../scripts/run-ansible-operational.sh product-certification.yml -i inventory/staging/hosts.yml -e archiveweaver_certification_apply=true

# Preview the approved restore/fixity drill against a non-production inventory.
bash ../../scripts/run-ansible-operational.sh restore-drill.yml --check --diff -i inventory/restore/hosts.yml

# Preview failure-domain hooks in staging and a release rollback plan.
bash ../../scripts/run-ansible-operational.sh failure-drill.yml --check --diff -i inventory/staging/hosts.yml
bash ../../scripts/run-ansible-operational.sh rollback.yml --check --diff -i inventory/production/hosts.yml
```

`archiveweaver_apply` defaults to `false`. An apply or check-mode apply also
requires `archiveweaver_approval_ticket`, `archiveweaver_backup_verified`,
`archiveweaver_release_manifest_verified`, `archiveweaver_product_stack_ready`,
and a non-placeholder release. Secrets are never placed on the command line.

Host package installation is also disabled by default. Production images
should pre-provision the small prerequisite set, or an operator may enable
`archiveweaver_manage_packages` only through trusted inventory after the OS
repositories and package lifecycle are governed externally; an unpinned live
package repository is not treated as a reproducible release.
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
bash ../../scripts/run-ansible-operational.sh repair.yml --syntax-check -i inventory/production/hosts.yml
bash ../../scripts/run-ansible-operational.sh repair.yml --check --diff -i inventory/production/hosts.yml
bash ../../scripts/run-ansible-operational.sh repair.yml -i inventory/production/hosts.yml -e archiveweaver_repair_apply=true
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

The example readiness manifest pre-populates the five certification rows and
four failure-domain rows with `pending` status. Keep their stable names, replace
the host/change placeholders, and point them at the distinct JSON files emitted
by the corresponding playbooks. Restore and fixity likewise use separate
`restore-<host>.json` and `fixity-<host>.json` records; a shared summary file
cannot satisfy both claims.

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
execution environment containing exact Ansible Core, Ansible Runner, and
ansible-lint versions through a controlled automation controller. Use signed
and reviewed content, RBAC-separated credentials, Vault or an external secret
manager, protected inventories, approval nodes, serial/rolling execution,
central job history, immutable evidence storage, and scheduled restore/fixity
tests. Before the controller runs tests or playbooks, verify the signed
immutable checkout with `bash scripts/verify-source-identity.sh "$ARCHIVEWEAVER_IMMUTABLE_REF"`.
In every non-check-mode production evidence run, supply the reviewed
archiveweaver_evidence_publish_command and
archiveweaver_evidence_verify_command hooks together with the retention,
immutability, and access-logging bindings. The repository supplies the safe
content boundary; the shared hook preflight also requires each reviewed hook
to use an absolute regular executable whose bytes match its lowercase SHA-256
binding and whose complete canonical argv matches a separate SHA-256 binding.
Generate both with `archiveweaver hook-digest --json -- /absolute/hook arg`.
An automation controller and operational policy provide the organization-level
governance.

Enable the managed read-only health timer with
`archiveweaver_observe_enabled: true` only after installing the ArchiveWeaver
checker on the host, binding its executable and argv digests as
`archiveweaver_check_command_sha256` and
`archiveweaver_check_command_argv_sha256`, and setting an HTTPS health URL. It
writes results to the system journal; the controller workflow is responsible
for alert routing, retention, and escalation.
The argv digest must bind the exact managed command, for example:

```bash
archiveweaver hook-digest --json -- /usr/local/bin/archiveweaver check \
  --solution paperless-ngx --mode rke2 \
  --url https://paperless.example.org/ --json
```
