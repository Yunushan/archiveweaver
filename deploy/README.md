# Deployment templates

These files are provider envelopes and review templates for ArchiveWeaver. They are not universal product stacks. A real deployment must add the selected product's official application, database, search, queue, object-storage, ingress, and migration assets at pinned versions.

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

