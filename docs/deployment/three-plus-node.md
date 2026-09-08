# Three-plus-node deployment

Use three-plus nodes when control-plane isolation, workload scale, failure-domain placement, or maintenance windows justify additional roles.

## Suggested role pools

| Pool | Typical count | Responsibility |
| --- | ---: | --- |
| Control plane | 3 or 5 | Kubernetes/Swarm consensus and API |
| Ingress | 2 or more | HAProxy, keepalived, ingress controller, TLS |
| Application | 2 or more | Stateless web/API replicas |
| Workflow/transform | 2 or more | OCR, normalization, media derivatives, queue workers |
| Database | 3 or vendor-recommended | PostgreSQL/MySQL HA and backup |
| Search | 3 or vendor-recommended | Solr/OpenSearch/Elasticsearch; rebuildable indexes |
| Storage | 3 or vendor-recommended | S3/MinIO/Ceph/NFS/CSI with integrity controls |
| Witness/backup | independent | quorum witness, immutable backup, restore target |

Counts are starting points, not universal sizing. Product concurrency, collection size, OCR rate, preview rate, retention, and RTO/RPO determine the final design.

## Placement rules

- use odd control-plane/manager counts;
- avoid placing all database/search/storage replicas on one power or hypervisor failure domain;
- keep database and storage traffic on private networks;
- use taints/tolerations or dedicated worker pools for converter workloads;
- control noisy-neighbor behavior with requests, limits, quotas, and I/O policy;
- run upgrade rehearsals with real data volume and representative format fixtures.

## Scale-out gate

Before adding nodes, confirm that the bottleneck is actually CPU, memory, I/O, network, queue workers, database connections, search, or storage throughput. Adding app replicas does not fix a slow database or an undersized object store.

