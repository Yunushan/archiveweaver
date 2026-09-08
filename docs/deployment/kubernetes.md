# Kubernetes-family deployments

ArchiveWeaver can render and check K3s, RKE2, k0s, and MicroK8s envelopes. The generated envelope is intentionally small: it gives the application a namespace, a durable data claim, anti-affinity, a deployment, and a service. The product's official database/search/queue/object-storage manifests must be added for the selected release.

## Common controls

- pin images by digest or approved immutable tag;
- use a real ingress controller and certificate strategy;
- set readiness/liveness probes for the product's documented endpoints;
- use a CSI driver with the access modes the product actually needs;
- set resource requests/limits and a PodDisruptionBudget;
- set topology spread across nodes/failure domains;
- use NetworkPolicies to isolate database/search/queue traffic;
- encrypt Kubernetes Secrets at rest and use external secret management when required;
- schedule etcd/control-plane snapshots and test restore;
- use separate node pools for OCR, media conversion, or preservation workers.

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

