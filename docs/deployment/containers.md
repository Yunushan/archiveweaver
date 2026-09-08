# Docker, Podman Quadlet, and Swarm

## Docker Compose

Use Compose for a single host or as the product's upstream development/packaging method. Pin all images and volumes, put the published port behind a reverse proxy, and keep databases/storage on protected volumes. Do not use `docker compose down -v` as a repair action.

## Podman Quadlet

Quadlet turns declarative `.container`, `.volume`, `.network`, and related files into systemd units. Place system-level files under `/etc/containers/systemd/`, run `systemctl daemon-reload`, and enable the generated unit. Quadlet is not a multi-host scheduler. For a two-node active/passive design, combine it with Pacemaker and STONITH after testing the data path.

## Docker Swarm

Use an odd number of managers, normally three or five. Put workers and stateful services in deliberate placement constraints. A local volume follows a node; it is not a shared archive. Use an approved distributed storage driver or external database/object storage, and test manager quorum loss and recovery.

## Render examples

```bash
PYTHONPATH=src python3 -m archiveweaver render --solution mayan-edms --mode podman-quadlet --nodes 1 --os rocky-9 --image mayanedms/mayanedms@sha256:<digest>
PYTHONPATH=src python3 -m archiveweaver render --solution dspace --mode docker-swarm --nodes 3 --os ubuntu-24.04 --image registry.example.org/dspace@sha256:<digest>
```

