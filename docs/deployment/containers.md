# Docker, Podman Quadlet, and Swarm

## Docker Compose

Use Compose for a single host or as the product's upstream development/packaging method. Pin all images and volumes, put the published port behind a reverse proxy, and keep databases/storage on protected volumes. Do not use `docker compose down -v` as a repair action.

## Podman Quadlet

Quadlet turns declarative `.container`, `.volume`, `.network`, and related files into systemd units. Place system-level files under `/etc/containers/systemd/`, run `systemctl daemon-reload`, and enable the generated unit. For an operated deployment, use a bind-backed volume that points at the reviewed data path instead of an implicit node-local volume. Quadlet is not a multi-host scheduler. For a two-node active/passive design, combine it with Pacemaker and STONITH after testing the data path.

## Docker Swarm

Use an odd number of managers, normally three or five. Put workers and stateful services in deliberate placement constraints. A local volume follows a node; it is not a shared archive. Use an approved distributed storage driver or external database/object storage, and test manager quorum loss and recovery.

For every multi-node Swarm plan, `--external-storage` is a reviewed assertion,
not an automatic provisioner. The rendered stack references
`ARCHIVEWEAVER_DATA_VOLUME` as an existing external volume and will not silently
fall back to node-local state.

The generic Swarm stacks do not publish the application port through the
routing mesh. Add a reviewed TLS reverse proxy in the same stack or attach its
service to a reviewed overlay network shared with the app. Route to the app's
service name and container port. Configure the public listener, TLS, access
controls, and health checks as part of that product-specific stack before
calling the deployment ready.

When upgrading a stack that previously published the app port, deploy and test
the TLS proxy and its route to the app first. Confirm an external request and
the proxy health check succeed, then apply the stack that removes the routing
mesh port. Recheck external reachability after the change; do not remove the
old route before its replacement is serving traffic.

## Render examples

```bash
PYTHONPATH=src python3 -m archiveweaver render --solution mayan-edms --mode podman-quadlet --nodes 1 --os rocky-9 --image mayanedms/mayanedms@sha256:<digest>
PYTHONPATH=src python3 -m archiveweaver render --solution dspace --mode docker-swarm --nodes 3 --os ubuntu-24.04 --image registry.example.org/dspace@sha256:<digest> --external-storage
```
