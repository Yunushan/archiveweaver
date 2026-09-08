# Checking and acceptance

## Principles

Checks are read-only. They should make a failure easier to diagnose without changing the application, storage, cluster, or security posture.

## Basic commands

```bash
make validate

PYTHONPATH=src python3 -m archiveweaver check \
  --solution archivematica \
  --mode rke2 \
  --url https://archivematica.example.org/ \
  --service archivematica \
  --path /srv/archivematica \
  --config /etc/rancher/rke2/config.yaml \
  --json > reports/archivematica-check.json
```

The shell wrapper is equivalent:

```bash
./scripts/check-archiveweaver.sh --solution archivematica --mode docker --url https://localhost/
```

## Check layers

1. **Host:** OS, kernel, architecture, hostname, time, and required command availability.
2. **Runtime:** Docker, Podman/systemd, Pacemaker/pcs, Swarm, or Kubernetes client availability.
3. **Process/service:** configured systemd aliases or an explicitly supplied unit.
4. **HTTP:** normal TLS-verified endpoint response; authentication is never bypassed.
5. **Storage:** operator-supplied data, mount, backup, and configuration paths.
6. **Dependencies:** application-specific DB/search/queue/storage checks, implemented through an adapter or an approved external probe.
7. **Application:** login, upload, retrieval, preview/OCR, workflow, API, export, and fixity smoke tests.

The Ansible edition adds remote preflight, provider-command checks, direct
2xx-only TLS-verified endpoint probing without redirects, service facts,
storage-path inspection, and redacted per-host evidence. It does not replace the product-specific
dependency and preservation smoke tests in layers 6–7.

The built-in CLI implements layers 1–5. Layers 6–7 are intentionally explicit because credentials, schemas, collection data, and product release semantics differ.

## Exit status

- `0`: no failures reported;
- `2`: one or more checks failed or the plan is blocked;
- `3`: wrapper refused an unsupported apply operation.

## Evidence

Persist JSON output with the change ID. Redact tokens, cookies, document content, credentials, and personal data before sharing it.

