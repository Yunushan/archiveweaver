# Runtime and topology matrix

The following matrix is the policy applied by the planner. Product-specific fit is stored per solution in `src/archiveweaver/catalog_source.py`; the runtime topology rules below apply to all products and are then narrowed by product dependencies and state requirements.

| Runtime | Standalone | 2 nodes | 3 nodes | 3+ nodes | Production note |
| --- | --- | --- | --- | --- | --- |
| Raw / native | supported | conditional | conditional | conditional | Follow upstream native clustering or use active/passive failover |
| Docker Compose | supported | conditional | conditional | conditional | Compose is not a multi-host scheduler |
| K3s | supported | not-recommended | supported | supported | 3/5 servers for embedded-etcd HA |
| RKE2 | supported | not-recommended | supported | supported | 3 server nodes are the normal embedded-etcd baseline |
| Pacemaker / Corosync | supported | supported-with-stonith | supported | supported | STONITH-backed active/passive resource management |
| Podman Quadlet | supported | conditional | conditional | conditional | Single-host systemd lifecycle; Pacemaker for failover |
| k0s | supported | not-recommended | supported | supported | 3/5 controllers and a control-plane endpoint |
| Docker Swarm | supported | not-recommended | supported | supported | At least 3 managers for manager-failure tolerance; 3 or 5 are the normal quorum sizes |
| MicroK8s | supported | not-recommended | supported | supported | HA datastore and 3/5 control-plane nodes |
| Ansible orchestration adapter | supported | supported | supported | supported | Coordinates an underlying provider; it is not an HA runtime |

## Product fit and topology are separate

For example, `paperless-ngx + RKE2 + 3 nodes` is *portable/supported* at the infrastructure layer, but it still requires PostgreSQL, Redis, OCR, Tika/Gotenberg, and durable media storage to be deployed and tested correctly. `Hyrax + Docker` is possible as a host application container, but Hyrax itself is a Rails engine that must be mounted into a Rails application. `Islandora` is a Drupal/Fedora/Solr composition rather than a single image.

Ansible's row describes the hosts it can coordinate. It does not change the
underlying runtime topology policy or create HA by itself; use a real
Kubernetes, Swarm, Pacemaker, or product-native design for resilience.

For Docker Swarm, `--nodes` counts all hosts, not managers. Two hosts could be
two managers (neither manager can fail without losing quorum) or one manager
and one worker (a functioning Swarm with no manager failover). The planner
cannot distinguish those roles from the node count, so both two-host cases
remain blocked for a production HA plan, including through Ansible. Neither
`--external-datastore` nor `--allow-conditional` can change Swarm's internal
manager quorum. Use at least three managers on separate hosts and verify the
actual roles and failure behavior before promotion. See the
[Docker Swarm administration guide](https://docs.docker.com/engine/swarm/admin_guide/).

## Required exception inputs

- `--allow-conditional`: acknowledges that a product/mode needs design review;
- `--external-datastore`: acknowledges externally managed consensus or state for runtimes that support it; it does not externalize Docker Swarm's manager state;
- `--stonith`: confirms fencing exists for Pacemaker two-node plans;
- `--qdevice`: records that a quorum witness/device is planned.

These flags do not create the infrastructure. They make the assumption visible in the generated plan.
