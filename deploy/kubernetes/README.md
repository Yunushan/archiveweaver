# Kubernetes-family envelopes

The `base` and `overlays` directories are generic Kustomize review envelopes for K3s, RKE2, k0s, and MicroK8s. They are not application stacks: replace the placeholder image, port, probes, storage class, secrets, database/search/queue endpoints, ingress, and product-specific migration jobs from the selected upstream release. The overlays use one application replica and `Recreate`; cluster node count does not prove that a product can run multiple full containers safely.

The renderer deliberately refuses `--solution paperless-ngx` with a Kubernetes mode; it does not accept a product bundle as input. A digest-pinned image alone cannot supply Paperless-ngx's PostgreSQL database, Redis-compatible broker, secret key and public URL, product data and media paths, consume and export paths, ingress, or dependency egress. Its all-in-one container also needs a tested upgrade procedure that does not overlap full instances. A [v3.2.1 RKE2 reference bundle](../paperless-ngx/rke2/README.md) provides a release-specific starting point; it contains invalid placeholders and requires a protected secret file, site values, and live validation before use. Tika and Gotenberg are optional services for the document types that use them; configure and test them if the selected format policy needs them. See the [versioned upstream configuration](https://raw.githubusercontent.com/paperless-ngx/paperless-ngx/v3.2.1/docs/configuration.md) and [versioned PostgreSQL Compose example](https://raw.githubusercontent.com/paperless-ngx/paperless-ngx/v3.2.1/docker/compose/docker-compose.postgres.yml).

For other products, render a generic review envelope when useful:

```bash
PYTHONPATH=src python3 -m archiveweaver render \
  --solution dspace \
  --mode rke2 \
  --nodes 3 \
  --os ubuntu-24.04 \
  --image registry.example.org/dspace@sha256:<digest> \
  --output generated/dspace-rke2.yaml
```

The generated YAML is a review artifact, not a Kustomize directory. The checked-in overlays are also not safe to apply until every placeholder has been replaced and dependencies have been tested. The base and generated NetworkPolicies deny all application ingress and egress. Add separately reviewed allow policies for the ingress controller, DNS, and each required product dependency or external destination, and verify that the CNI enforces them. Use a CSI-backed `ReadWriteMany` storage class for shared content only when the product supports it; otherwise use the product's documented storage topology.
