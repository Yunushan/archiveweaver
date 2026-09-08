# Two-node deployment

Two nodes are useful for active/passive services or for an application tier in front of external HA state. Two nodes are not a generic replacement for three-node consensus.

## Recommended patterns

### Pattern A: Pacemaker active/passive

Use when the selected product is natively deployable as one service or one container stack and shared/replicated state is available.

```text
node-a ─┐
        ├─ Corosync + Pacemaker + STONITH ─ VIP ─ application ─ external DB/storage
node-b ─┘
                         └─ quorum witness/qdevice
```

The application resource, VIP, mounts, and dependency ordering must be declared as one tested resource group. A failed health monitor must not cause both nodes to write to the same uncoordinated data path.

### Pattern B: two application nodes, external state

Run two web/API replicas behind HAProxy or an ingress load balancer. Use a separately managed HA database, search cluster, queue, and object/file store. Confirm session handling, background job de-duplication, file locks, and migrations before scaling replicas.

### Pattern C: external Kubernetes datastore

Some Kubernetes distributions document two or more servers when the datastore is external. This does not make the application automatically HA and must not be confused with a two-member embedded-etcd cluster.

## Required command review

```bash
PYTHONPATH=src python3 -m archiveweaver plan \
  --solution nextcloud-server \
  --mode pacemaker \
  --nodes 2 \
  --os rocky-9 \
  --stonith \
  --qdevice \
  --allow-conditional
```

The plan remains conditional because the actual STONITH agent, storage replication, VIP, and application failover semantics are environment-specific.

## Failure tests

- stop the application process and verify a controlled restart;
- power off one node through the real fencing interface;
- isolate the cluster network and verify that split-brain protection wins over availability;
- restore the failed node without allowing stale data to overwrite current data;
- test database failover and object-store recovery separately;
- document the observed RTO/RPO.

