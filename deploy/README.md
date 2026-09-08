# Deployment templates

These files are provider envelopes and review templates for ArchiveWeaver. They are not universal product stacks. A real deployment must add the selected product's official application, database, search, queue, object-storage, ingress, and migration assets at pinned versions.

The `ansible/` directory is the enterprise orchestration edition. It adds
inventory structure, fail-closed approval gates, rolling execution, Vault
boundaries, named-resource repair, verification, and redacted evidence while
continuing to use the provider envelopes below. Ansible does not provide
quorum or application HA by itself.

Generate an envelope from the catalog:

```bash
PYTHONPATH=src python3 -m archiveweaver render \
  --solution paperless-ngx \
  --mode docker \
  --nodes 1 \
  --os ubuntu-24.04 \
  --image registry.example.org/paperless-ngx@sha256:<digest> \
  --output generated/paperless-compose.yml
```

Review the plan before applying the provider command. Product dependencies and state must be deployed separately according to the upstream release documentation.

For Ansible setup and the safe check-mode/apply workflow, see
[`ansible/README.md`](ansible/README.md) and
[`../docs/deployment/ansible.md`](../docs/deployment/ansible.md). The
100-point evidence contract is in
[`../docs/operations/premium-readiness.md`](../docs/operations/premium-readiness.md).

