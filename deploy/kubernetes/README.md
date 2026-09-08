# Kubernetes-family envelopes

The `base` and `overlays` directories are generic Kustomize envelopes for K3s, RKE2, k0s, and MicroK8s. They are deliberately not application stacks: replace the placeholder image, port, probes, storage class, secrets, database/search/queue endpoints, ingress, and product-specific migration jobs from the selected upstream release.

Render a product-specific envelope when possible:

```bash
PYTHONPATH=src python3 -m archiveweaver render \
  --solution paperless-ngx \
  --mode rke2 \
  --nodes 3 \
  --os ubuntu-24.04 \
  --image registry.example.org/paperless-ngx@sha256:<digest> \
  --output generated/paperless-rke2.yaml
```

The checked-in overlays are reviewable starting points and are not safe to apply until every placeholder has been replaced and dependencies have been tested. Use a CSI-backed `ReadWriteMany` storage class for shared content only when the product supports it; otherwise use the product's documented storage topology.
