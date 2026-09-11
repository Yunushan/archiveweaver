# ArchiveWeaver

Deployment planning, installation envelopes, health checking, and guarded repair automation for digital-archiving platforms.

ArchiveWeaver is designed for operators who need one consistent operational model across research repositories, digital-preservation systems, DMS/ECM products, DAM platforms, archival-description tools, and file-sync systems.

## Recommended GitHub identity

- **Project name:** ArchiveWeaver
- **Repository name:** `archiveweaver`
- **Recommended URL:** `https://github.com/Yunushan/archiveweaver`
- **Short description:** `Production deployment, health-check, and safe-repair automation for open digital archiving platforms.`
- **License:** 0BSD

`archiveweaver` matches the naming style of the companion automation projects and is short enough for CLI commands, package names, and deployment labels.

## What is included

- 30 product catalog entries with official upstream links, dependencies, service aliases, health paths, format families, and mode support;
- support for raw/native, Docker Compose, K3s, RKE2, Pacemaker/Corosync + STONITH, Podman Quadlet, k0s, Docker Swarm, and MicroK8s;
- an Ansible orchestration edition with inventory, Vault/secret boundaries, fail-closed approvals, rolling execution, provider envelopes, repair gates, and evidence;
- topology policy for standalone, two-node, three-node, and three-plus-node deployments;
- OS catalog for Ubuntu 22.04/24.04/26.04, Rocky Linux 8/9/10, RHEL 8/9/10, AlmaLinux 8/9/10, Debian 12/13;
- read-only host, runtime, systemd, HTTP, storage-path, and configuration checks;
- plan-only and explicitly gated repair actions;
- a fail-closed 100-point production-readiness evaluator and tamper-evident evidence index;
- safe provider envelopes for systemd, Docker, Podman Quadlet, Swarm, and Kubernetes-family runtimes;
- English default documentation plus Turkish README and operations summaries;
- HLD, LLD, ADRs, deployment patterns, backup/restore, security, and full format-family catalog;
- stdlib unit tests and GitHub Actions CI.

## Important support boundary

“Supported” has a precise meaning here:

- **native:** the upstream project has a source/package/install path suitable for the mode;
- **validated:** the upstream project documents or publishes the deployment path;
- **portable:** ArchiveWeaver can render/check the infrastructure pattern, but the product's application-level HA and state behavior require validation;
- **conditional:** possible only after a design review, release pin, and failure test;
- **not-recommended:** blocked by the planner unless an exception is documented.

The repository does not claim that every product has an official Helm chart, Docker image, active/active cluster mode, or vendor support on every listed OS. Frameworks such as Hyrax and Islandora need a host/application composition; Archivematica and Alfresco need multiple services; Fedora is a repository backend; OpenKM's upstream GitHub repository is archived in 2026. Those facts are visible in the catalog instead of hidden behind one generic installer.

## Quick start

The core has no third-party Python runtime dependency.

Release validation uses the separately reviewed, wheel-only hash lock at
`requirements/release-tools.txt`; it is not a runtime dependency of the core
package. See the [supply-chain controls](docs/operations/supply-chain.md) for
regeneration and verification instructions.

```bash
git clone https://github.com/Yunushan/archiveweaver.git
cd archiveweaver

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

archiveweaver validate-catalog --json
archiveweaver list-solutions
```

## Python support

The core package supports Python 3.9 through 3.15 and the full test suite runs
against every version in that range. The Ansible edition is validated with
Python 3.13 and 3.14 using the pinned controller requirements. CI opts into
prerelease resolution for the core 3.15 job while it is not yet stable; the
same matrix will select the stable 3.15 release automatically when it is
published. The Ansible job follows the controller stack's declared support
range and will expand when its pinned dependencies declare 3.15 support.

Plan a three-node RKE2 deployment:

```bash
archiveweaver plan \
  --solution paperless-ngx \
  --mode rke2 \
  --nodes 3 \
  --os ubuntu-24.04
```

Render a provider envelope with an immutable image reference:

```bash
archiveweaver render \
  --solution paperless-ngx \
  --mode rke2 \
  --nodes 3 \
  --os rocky-9 \
  --image registry.example.org/paperless-ngx@sha256:<digest> \
  --namespace archive \
  --output generated/paperless-rke2.yaml
```

Run read-only checks:

```bash
archiveweaver check \
  --solution paperless-ngx \
  --mode rke2 \
  --url https://paperless.example.org/ \
  --service paperless \
  --path /srv/paperless \
  --config /etc/rancher/rke2/config.yaml \
  --json > reports/paperless-check.json
```

Use the enterprise Ansible orchestration edition:

```bash
cd deploy/ansible
cp inventory/production/hosts.yml.example inventory/production/hosts.yml
cp inventory/staging/hosts.yml.example inventory/staging/hosts.yml
cp inventory/restore/hosts.yml.example inventory/restore/hosts.yml
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
cp release-manifest.example.json release-manifest.json
bash ../../scripts/run-ansible-operational.sh site.yml --syntax-check -i inventory/production/hosts.yml
bash ../../scripts/run-ansible-operational.sh site.yml --check --diff -i inventory/production/hosts.yml -e archiveweaver_apply=true
```

To generate a review-only Ansible entry point for a specific provider, use for example
`archiveweaver render --solution paperless-ngx --mode ansible --underlying-mode rke2 --nodes 3 --os ubuntu-24.04 --output generated/paperless-rke2.yml`.
Production operations use the fixed approved playbooks through
`scripts/run-ansible-operational.sh`.
Build the controller execution environment only through
`scripts/build-ansible-execution-environment.sh`; it requires an immutable
base-image digest before Podman or Docker is invoked and verifies the locked
Ansible Core, Ansible Runner, and ansible-lint toolchain.

The operational runner requires exactly one of the protected production,
staging, or restore inventories and accepts only explicit keys in
`deploy/ansible/controller/allowed-extra-vars.txt`; inventory directories, extra-vars files,
raw YAML/JSON variables, controller/transport overrides, ambient Ansible
plugin paths, and Python import-path overrides are rejected or cleared.

Ansible coordinates the selected provider; it does not provide quorum,
fencing, scheduler HA, database replication, or product-level failover. Keep
`archiveweaver_apply: false` until the release manifest, dependency stack,
backup evidence, and change approval are complete.

Use the 100-point readiness gate before production mutation:
`PYTHONPATH=src python3 -m archiveweaver readiness --manifest deploy/ansible/release-manifest.json --json`.
The example intentionally fails until a real release manifest, product test
evidence, and verified SHA-256 evidence index are supplied. The contract is
documented in [premium readiness](docs/operations/premium-readiness.md).

Create a repair plan. It will not execute until `--apply` is supplied:

```bash
archiveweaver repair \
  --solution paperless-ngx \
  --mode docker \
  --compose-file /srv/paperless/docker-compose.yml \
  --json > reports/paperless-repair-plan.json
```

## Supported solution families

| Family | Products |
| --- | --- |
| Research repositories | InvenioRDM, DSpace, Dataverse, EPrints |
| Digital preservation | Archivematica, RODA Community, Asalae, Maarch RM |
| Repository backends/frameworks | Fedora Repository, Samvera Hyrax, Islandora |
| DMS/ECM | Mayan EDMS, Maarch Courrier, Docspell, Alfresco Community, SeedDMS, Paperless-ngx, Papermerge, OpenKM Community, Teedy, LogicalDOC Community |
| DAM/collections/description | ResourceSpace, ArchivesSpace, AtoM, CollectiveAccess, Omeka S |
| File sync and share | Nextcloud Server, Seafile Community |
| Digitization workflow | Kitodo.Production, Goobi workflow |

The complete catalog is in [the generated solution reference](docs/reference/solutions-catalog.md), with one page per solution under [`docs/solutions/`](docs/solutions/).
The generated [product support matrix](docs/reference/support-matrix.md) and [format-family matrix](docs/reference/format-matrix.md) provide consolidated views.

## Runtime and topology support

| Runtime | Standalone | 2 nodes | 3 nodes | 3+ nodes |
| --- | --- | --- | --- | --- |
| Raw/native | supported | conditional | conditional | conditional |
| Docker Compose | supported | conditional | conditional | conditional |
| K3s | supported | not-recommended | supported | supported |
| RKE2 | supported | not-recommended | supported | supported |
| Pacemaker/Corosync + STONITH | supported | supported-with-stonith | supported | supported |
| Podman Quadlet | supported | conditional | conditional | conditional |
| k0s | supported | not-recommended | supported | supported |
| Docker Swarm | supported | not-recommended | supported | supported |
| MicroK8s | supported | not-recommended | supported | supported |
| Ansible orchestration adapter | supported | supported | supported | supported |

Two-node Pacemaker requires a real fencing design. Two-node embedded-etcd or two-manager consensus is intentionally not treated as resilient HA. See [the runtime matrix](docs/deployment/runtime-matrix.md) and [the two-node design](docs/deployment/two-node.md).

Ansible is shown in the matrix as an orchestration adapter. Its topology row
describes the number of hosts it can coordinate, not an HA guarantee; the
underlying runtime and application state design still determine resilience.

## Linux baseline

ArchiveWeaver catalogs and checks these host families:

| Debian family | Enterprise Linux family |
| --- | --- |
| Ubuntu 22.04 LTS | Rocky Linux 8 |
| Ubuntu 24.04 LTS (preferred) | Rocky Linux 9 (preferred) |
| Ubuntu 26.04 LTS (forward validation) | Rocky Linux 10 (forward validation) |
| Debian 12 | RHEL 8 / AlmaLinux 8 (legacy conditional) |
| Debian 13 | RHEL 9 / AlmaLinux 9 |
|  | RHEL 10 / AlmaLinux 10 (forward validation) |

This is an ArchiveWeaver host baseline, not a blanket upstream application certification. Read [the OS matrix](docs/deployment/os-matrix.md) before pinning a product release.

## Architecture documentation

- [HLD](docs/architecture/HLD.md) — logical architecture, HA patterns, data protection, security, and failure domains;
- [LLD](docs/architecture/LLD.md) — catalog contract, CLI behavior, renderer details, repair safety, ports, and evidence bundles;
- [ADRs](docs/architecture/DECISIONS.md) — why the core is catalog-driven, why two-node consensus is blocked, and why envelopes are used;
- [Standalone](docs/deployment/standalone.md), [two-node](docs/deployment/two-node.md), [three-node](docs/deployment/three-node.md), and [three-plus-node](docs/deployment/three-plus-node.md) designs;
- [Kubernetes-family deployment](docs/deployment/kubernetes.md), [containers](docs/deployment/containers.md), and [Pacemaker](docs/deployment/pacemaker.md);
- [Ansible enterprise orchestration](docs/deployment/ansible.md) and the runnable [Ansible edition](deploy/ansible/README.md);
- [Checking](docs/operations/checking.md), [repair](docs/operations/repair.md), [backup/restore](docs/operations/backup-restore.md), [product certification](docs/operations/product-certification.md), [service management](docs/operations/service-management.md), and [security](docs/operations/security.md);
- [premium activation](docs/operations/premium-activation.md) — owner-by-owner activation inputs and the 100/100 promotion sequence;
- [Supply-chain controls](docs/operations/supply-chain.md);
- [full format catalog](docs/reference/formats.md), [format-family matrix](docs/reference/format-matrix.md), [product support matrix](docs/reference/support-matrix.md), and [upstream source links](docs/reference/upstream-sources.md).

## Format support model

The catalog includes documents, spreadsheets, presentations, images, audio, video, e-books, archives, e-mail exports, web/markup, scientific/geospatial, structured data, fonts, and preservation packages. It includes a broad extension and MIME inventory in [formats.md](docs/reference/formats.md).

An extension is not a preview/OCR/preservation guarantee. ArchiveWeaver separates:

1. intake and upload;
2. bitstream storage;
3. MIME/magic-byte identification;
4. virus scanning;
5. OCR and text extraction;
6. derivative/preview generation;
7. indexing and search;
8. preservation normalization and fixity.

The exact release, plugin, converter, and storage policy must be tested with representative fixtures.

## Safety model

- plans are read-only;
- checks are read-only;
- repair requires `--apply`;
- Pacemaker repair additionally requires `--allow-fencing-actions`;
- no built-in action runs `down -v`, deletes PVCs, purges application data, disables TLS verification, bypasses authentication, or disables STONITH;
- generated envelopes require an explicitly pinned image and do not invent database/search/object-storage versions;
- secrets and private documents are never generated or committed.

## Development

```bash
make generate
make validate
make test
make smoke
```

To add or update a product, edit `src/archiveweaver/catalog_source.py`, add upstream references and representative health/dependency facts, regenerate the catalog, add/adjust tests, and document any conditional HA behavior.

## Upstream attribution

ArchiveWeaver is an independent operations project. The listed products remain owned and licensed by their respective communities and organizations. Use each upstream project's current release documentation and license notices. See [upstream-sources.md](docs/reference/upstream-sources.md).

## License

ArchiveWeaver is released under the [Zero-Clause BSD (0BSD)](LICENSE). Upstream product licenses remain applicable to the products, images, plugins, and dependencies referenced by a deployment.
