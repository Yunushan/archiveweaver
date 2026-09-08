# Repair mechanisms

## Default workflow

```bash
# 1. Create a plan; this does not execute anything.
PYTHONPATH=src python3 -m archiveweaver repair \
  --solution paperless-ngx \
  --mode docker \
  --compose-file /srv/paperless/docker-compose.yml \
  --json > reports/paperless-repair-plan.json

# 2. Review the plan and the backup/fixity state.

# 3. Apply only after approval.
PYTHONPATH=src python3 -m archiveweaver repair \
  --solution paperless-ngx \
  --mode docker \
  --compose-file /srv/paperless/docker-compose.yml \
  --apply \
  --json > reports/paperless-repair-result.json
```

## Action policy

| Repair family | Safe examples | Not performed automatically |
| --- | --- | --- |
| Native | restart a named service and verify it | delete data, purge packages, reset permissions, run migrations |
| Docker | validate Compose, reconcile declared services, inspect status | delete volumes, prune images, recreate external databases |
| Quadlet | reload systemd units, restart a named unit | remove mounts or content |
| Pacemaker | inspect cluster, clean a failed resource operation | disable STONITH, force both nodes online, delete cluster state |
| Swarm | validate/deploy stack, inspect service replicas | force manager recovery, delete volumes |
| Kubernetes | inspect nodes, rolling restart, observe rollout | delete PVCs, reset cluster, force-delete arbitrary pods |

## Pacemaker gate

```bash
PYTHONPATH=src python3 -m archiveweaver repair \
  --solution nextcloud-server \
  --mode pacemaker \
  --resource nextcloud-app \
  --allow-fencing-actions
```

The command remains plan-only. Add `--apply` only after reviewing `pcs status --full`, quorum, STONITH, constraints, storage state, and the change ticket. This flag is intentionally named to make a cluster-recovery operation visible in logs and code review.

## Incident sequence

1. Freeze unrelated changes.
2. Capture service, cluster, database, search, queue, storage, and recent application logs.
3. Verify the latest restorable backup and fixity state.
4. Run a read-only ArchiveWeaver check.
5. Generate the smallest repair plan.
6. Apply with an approved operator identity.
7. Run checks and product smoke tests.
8. Record root cause, observed RTO/RPO, and follow-up changes.

