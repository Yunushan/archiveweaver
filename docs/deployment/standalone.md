# Standalone deployment

Standalone is the default for development, evaluation, migration rehearsal, or a small archive with an explicitly accepted single failure domain.

## Workflow

```bash
make generate
PYTHONPATH=src python3 -m archiveweaver plan \
  --solution invenio-rdm \
  --mode docker \
  --nodes 1 \
  --os ubuntu-24.04

PYTHONPATH=src python3 -m archiveweaver render \
  --solution paperless-ngx \
  --mode docker \
  --nodes 1 \
  --os ubuntu-24.04 \
  --image registry.example.org/paperless-ngx@sha256:<digest> \
  --output generated/paperless-compose.yml
```

## Minimum controls

- dedicated service account and data directory;
- TLS at a reverse proxy;
- external database where the product requires one;
- backup to a second failure domain;
- fixity verification for original bitstreams;
- resource limits and upload-size limits;
- monitoring of disk, inode, database, search, queue, and backup state.

## Acceptance

1. Deploy the pinned release in a clean test directory.
2. Run `archiveweaver check` with the exact URL, service, storage path, and config path.
3. Upload a representative format fixture from each format family.
4. Verify search, download, preview, OCR, export, and fixity behavior.
5. Restore the database and content store into a clean environment.

