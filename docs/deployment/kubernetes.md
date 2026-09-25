# Kubernetes-family deployments

ArchiveWeaver can render and check K3s, RKE2, k0s, and MicroK8s envelopes. The generated envelope is intentionally small: it gives the application a namespace, a durable data claim, anti-affinity, a deployment, a service, and a default-deny NetworkPolicy. The product's official database/search/queue/object-storage manifests must be added for the selected release.

Cluster node count does not set the application replica count. The generic examples keep one application replica and use `Recreate` so an update does not overlap two complete containers. This is a conservative review posture, not an application availability claim. For Paperless-ngx, Kubernetes rendering intentionally fails because the renderer cannot bind a release-specific bundle. The [v3.2.1 RKE2 reference bundle](../../deploy/paperless-ngx/rke2/README.md) records the required database, Redis-compatible broker, secrets, storage paths, ingress, egress, and upgrade review inputs. It contains unresolved site values and protected secret inputs; do not use the checked-in generic RKE2 overlay as a Paperless-ngx deployment. The [versioned Paperless-ngx configuration](https://raw.githubusercontent.com/paperless-ngx/paperless-ngx/v3.2.1/docs/configuration.md) and [PostgreSQL Compose example](https://raw.githubusercontent.com/paperless-ngx/paperless-ngx/v3.2.1/docker/compose/docker-compose.postgres.yml) identify the distinct data paths and port 8000.

## Common controls

- pin images by digest or approved immutable tag;
- use a real ingress controller and certificate strategy;
- set readiness/liveness probes for the product's documented endpoints;
- use a CSI driver with the access modes the product actually needs;
- set resource requests/limits and a PodDisruptionBudget;
- set topology spread across nodes/failure domains;
- use NetworkPolicies to isolate database/search/queue traffic;
- add explicit allow policies for the approved ingress-controller source and each required DNS, database, search, queue, object-storage, and external destination; the generated and checked-in policies deny all application ingress and egress until those rules are supplied;
- verify that the cluster CNI actually enforces NetworkPolicy before claiming isolation;
- keep the application service-account token unmounted unless the product has a documented Kubernetes API dependency;
- encrypt Kubernetes Secrets at rest and use external secret management when required;
- schedule etcd/control-plane snapshots and test restore;
- use separate node pools for OCR, media conversion, or preservation workers.

When upgrading an existing deployment from the former permissive policy,
install and test the product-specific ingress and egress allow policies first.
Probe the application through its intended ingress and confirm its dependency
connections. Then apply the new default-deny policy and repeat those probes.
Changing the existing policy before the allow rules are effective will cut
application traffic.

## Distribution-specific notes

| Distribution | Control-plane baseline | Default data warning |
| --- | --- | --- |
| K3s | 3 or 5 embedded-etcd servers | local-path storage is not shared HA storage |
| RKE2 | 3 server nodes for embedded-etcd HA | SQLite is not the multi-server HA datastore |
| k0s | 3 or 5 controllers with etcd | single-node SQLite is not clustered state |
| MicroK8s | 3 or 5 control-plane nodes | HA requires a highly available datastore |

## Render example

```bash
PYTHONPATH=src python3 -m archiveweaver render \
  --solution invenio-rdm \
  --mode k3s \
  --nodes 3 \
  --os rocky-9 \
  --image registry.example.org/invenio-rdm@sha256:<digest> \
  --namespace archive \
  --output generated/invenio-rdm-k3s.yaml
```
