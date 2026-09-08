# Low-Level Design (LLD)

## 1. Repository layout

```text
archiveweaver/
├── src/archiveweaver/
│   ├── catalog.py          # read-only catalog access
│   ├── catalog_source.py   # maintainable source facts
│   ├── checks.py           # read-only host and endpoint checks
│   ├── cli.py              # public command-line interface
│   ├── planner.py          # support and topology policy
│   ├── render.py           # provider envelopes
│   ├── repair.py           # gated repair plans and executor
│   ├── readiness.py        # 100-point release/service readiness gate
│   ├── evidence.py         # SHA-256 evidence index builder/verifier
│   ├── schema.py           # catalog validation
│   └── data/*.json         # generated runtime data
├── deploy/                 # provider examples, safe templates, and Ansible roles
├── docs/                   # HLD, LLD, runbooks and product pages
├── scripts/                # bootstrap, check and catalog generators
└── tests/                  # stdlib unit tests
```

The generated JSON files are committed so an operator can run the CLI without the generator. `catalog_source.py` remains the change-review source of truth. CI regenerates and validates the output.

## 2. Catalog contract

Each solution record contains:

```json
{
  "id": "paperless-ngx",
  "name": "Paperless-ngx",
  "category": "document-management",
  "upstream_repo": "https://github.com/paperless-ngx/paperless-ngx",
  "source_repo": "https://github.com/paperless-ngx/paperless-ngx",
  "official_docs": "https://docs.paperless-ngx.com/setup/",
  "homepage": "https://docs.paperless-ngx.com/",
  "license": "GPL-3.0",
  "architecture_components": ["Django web", "Celery workers", "PostgreSQL", "Redis"],
  "format_profiles": ["documents", "images", "email", "archives", "structured"],
  "dependencies": ["Python", "PostgreSQL", "Redis", "Tesseract"],
  "health": {
    "service_aliases": ["paperless", "celery", "redis", "postgresql"],
    "http_paths": ["/"],
    "default_port": 80,
    "checks": ["process-or-service", "http", "storage-paths", "dependency-reachability", "configuration-presence"]
  },
  "mode_support": {
    "raw": "native",
    "docker": "validated",
    "k3s": "portable",
    "rke2": "portable",
    "pacemaker": "conditional",
    "podman-quadlet": "portable",
    "k0s": "portable",
    "docker-swarm": "portable",
    "microk8s": "portable",
    "ansible": "portable"
  }
}
```

The schema validator requires every solution to declare every mode. This prevents a newly added runtime from silently disappearing from the support matrix.

## 3. Planning algorithm

1. Resolve solution, runtime, and OS IDs.
2. Normalize node count into `1`, `2`, `3`, or `3+`.
3. For Ansible, resolve `--underlying-mode` and read both the adapter fit and
   the selected provider's product/topology policy; for other modes, use the
   selected runtime directly.
4. Add blockers for `not-recommended`, conditional modes without `--allow-conditional`, two-node consensus without external state, and Pacemaker two-node plans without `--stonith`.
5. Add warnings for legacy/forward OS tiers, Compose multi-host assumptions, Quadlet multi-node assumptions, missing externalized state, and Ansible's lack of intrinsic HA.
6. Emit prerequisites, stages, reference commands, and data-safety policy.
7. Return exit code `2` for a blocked plan; a conditional plan is returned with warnings so an operator can review it.

The planner does not contact the target hosts and does not execute commands.

## 4. Check engine

`archiveweaver check` performs only read-only operations:

- parse `/etc/os-release`;
- read kernel, architecture, and hostname;
- check command availability with `shutil.which`;
- query service state using `systemctl is-active` when available;
- probe an operator-supplied URL using normal TLS verification;
- check operator-supplied storage/configuration paths;
- report skip/warn/fail evidence without “fixing” the host.

Example:

```bash
PYTHONPATH=src python3 -m archiveweaver check \
  --solution paperless-ngx \
  --mode rke2 \
  --url https://paperless.example.org/ \
  --path /srv/paperless \
  --config /etc/rancher/rke2/config.yaml \
  --json > reports/paperless-check.json
```

Health probes never disable certificate verification or authentication. A protected endpoint can be checked by passing a pre-authenticated internal health URL or by extending an adapter; do not place credentials on the command line.

## 5. Repair engine

The repair engine first constructs a plan. Only `--apply` executes it. Commands are passed to `subprocess.run` as argument arrays; shell interpolation is not used.

| Mode | Plan actions | Destructive actions intentionally absent |
| --- | --- | --- |
| Raw | capture status, restart service, verify active | no package purge, data deletion, migration, or permission reset |
| Docker | `compose config`, `compose up -d --remove-orphans`, `compose ps` | no `down -v`, volume prune, or image deletion |
| Quadlet | daemon reload, restart unit, verify active | no data-path cleanup |
| Pacemaker | status, resource cleanup, status | gated; no fencing bypass or cluster-wide disable |
| Swarm | stack config, stack deploy, service status | no volume deletion or forced manager recovery |
| Kubernetes | node check, rolling restart, rollout status | no PVC deletion, force delete, or cluster reset |
| Ansible | syntax-check, check-mode/diff, named provider reconciliation, verification/evidence | no automatic product migration, data deletion, secret output, or Pacemaker resource invention |

Pacemaker recovery is blocked unless `--allow-fencing-actions` is explicitly supplied. Operators must review quorum, STONITH devices, constraints, and the change ticket first.

## 6. Rendering contract

`archiveweaver render` produces an envelope, not a complete application chart. It accepts a pinned image with `--image` or a catalog image hint. Floating `:latest` tags are blocked by default.

```bash
PYTHONPATH=src python3 -m archiveweaver render \
  --solution paperless-ngx \
  --mode rke2 \
  --nodes 3 \
  --os rocky-9 \
  --image registry.example.org/paperless-ngx@sha256:<digest> \
  --output generated/paperless-rke2.yaml
```

Renderer behavior:

- raw: emits a hardened systemd unit envelope with a deliberate placeholder command;
- Docker: emits a single-host Compose envelope and a durable data mount;
- Podman Quadlet: emits a systemd-managed container envelope;
- Swarm: emits a service with anti-concentration and rolling update hints;
- K3s/RKE2/k0s/MicroK8s: emits Namespace, RWX PVC, Deployment, anti-affinity, and Service;
- Pacemaker: uses the resource templates under `deploy/pacemaker` because fencing and resource identity are environment-specific.
- Ansible: emits an entry point for the checked-in roles under `deploy/ansible`; `--underlying-mode` selects the provider envelope and the playbook is plan-only until explicit gates are satisfied.

The envelope explicitly does not create the product's database, search engine, queue, object store, ingress TLS, backup target, or application-specific migrations. Add those from the upstream release documentation and pin them as one tested release set.

## 6.1 Ansible execution contract

The Ansible edition is an orchestration adapter over an underlying provider.
`deploy/ansible/site.yml` uses `serial: 1` and `any_errors_fatal: true`, runs
preflight checks before mutation, and keeps `archiveweaver_apply: false` by
default. A check-mode apply is the required preview path; a real apply also
requires a non-placeholder release, approval ticket, verified backup, verified
release manifest, and a reviewed product dependency stack. Docker, Swarm, and
Kubernetes adapters validate a separately staged product bundle and never
replace it with the generic renderer output. The repair
playbook is separate and has its own apply variable. Pacemaker deployment
resources are never invented from placeholders.

Before apply or repair, the controller must run the repository's readiness
manifest command and receive 100/100. The manifest is evidence-backed rather
than a trusted score field; the preflight role invokes the command with
`check_mode: false`, `delegate_to: localhost`, and `no_log: true`.

## 7. Kubernetes details

The generated Kubernetes envelope assumes:

- a CSI storage class with `ReadWriteMany` semantics for a shared content path;
- external PostgreSQL/MySQL, search, queue, and object storage where the product requires them;
- a real ingress controller and TLS certificate strategy;
- three or more control-plane nodes for HA control-plane state;
- pod anti-affinity or topology spread across failure domains;
- a PodDisruptionBudget and resource requests/limits to be added per product;
- application readiness/liveness endpoints to be configured per product.

Do not use a local-path volume for a multi-replica stateful archive unless the application explicitly supports node-local sharding and the restore procedure is tested.

## 8. Pacemaker details

Pacemaker is a resource manager, not an application cluster. A production active/passive resource group normally contains:

1. a tested STONITH device for every node;
2. quorum configuration or a witness/qdevice;
3. a service IP/VIP;
4. the application systemd service or Podman Quadlet unit;
5. dependent mounts and storage resources;
6. ordering and colocation constraints;
7. monitor operations and failure timeouts;
8. a documented recovery and fencing test.

Never set `stonith-enabled=false` to make an installation green. If a lab test needs that behavior, isolate it from production and keep it out of the committed production profile.

## 9. Ports and network zones

Use an allow-list rather than opening every port on every node:

| Zone | Typical ports | Notes |
| --- | --- | --- |
| User/ingress | TCP 80/443 | Redirect HTTP to HTTPS; expose only the approved VIP/ingress |
| Kubernetes API | TCP 6443 | Control-plane endpoint; restrict to admins/nodes |
| K3s/RKE2 supervisor | TCP 9345 | RKE2/K3s node registration/control traffic as applicable |
| etcd | TCP 2379/2380 | Control-plane private network only |
| Swarm | TCP 2377, TCP/UDP 7946, UDP 4789 | Manager, node-discovery, and overlay traffic |
| Corosync | UDP 5405/5406 as configured | Private redundant cluster links |
| PostgreSQL | TCP 5432 | App/DB network only |
| MySQL/MariaDB | TCP 3306 | App/DB network only |
| Redis | TCP 6379 | App/queue network only |
| Solr/OpenSearch/Elasticsearch | TCP 8983/9200 | App/search network only |
| RabbitMQ | TCP 5672/15672 | App/queue network; management port restricted |

Exact ports vary by product release and must be confirmed in the upstream documentation.

## 10. Evidence format

Store a deployment evidence bundle outside the application data path:

```text
reports/<change-id>/
├── input.json
├── plan.json
├── readiness.json
├── host-check.json
├── runtime-status.txt
├── deployment-manifest.yaml
├── smoke-test.json
├── backup-restore.json
├── fixity-summary.json
├── evidence-index.json
└── operator-signoff.md
```

Do not store credentials, tokens, private keys, or raw sensitive documents in this bundle.

