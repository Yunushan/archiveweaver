# Contributing

ArchiveWeaver changes can affect deployment and recovery workflows. Keep every
change reviewable, fail closed at trust boundaries, and distinguish generic
planning envelopes from product-specific production stacks.

## Local verification

Use Python 3.14 for the complete release-quality toolchain and run:

```bash
python3 -m pip install -e .
python3 -m pip install --require-hashes --only-binary=:all: \
  -r requirements/release-tools.txt
make generate
make test
make quality
PYTHONPATH=src python3 -m coverage run -m unittest discover -s tests
PYTHONPATH=src python3 -m coverage report
```

Ansible changes must also pass `make ansible-validate` in a Linux environment
using the exact lock in `deploy/ansible/requirements.txt`. Regenerate that lock
only through `make ansible-lock`, review every transitive change, and keep the
execution-environment copy identical.

## Change requirements

- Update `src/archiveweaver/catalog_source.py`, never generated catalog JSON by
  itself, then run `make generate`.
- Add both allowed and rejected cases for planner, renderer, repair, path, hook,
  evidence, and readiness-boundary changes.
- Pin production OCI images by full SHA-256 digest and GitHub Actions by commit.
- Do not weaken source identity, inventory, hook, evidence-index, approval, or
  100-point readiness checks to make a test pass.
- Do not commit secrets, private archive content, operator inventories, Vault
  data, generated production manifests, or real controller output.
- Treat checked-in Docker, Kubernetes, systemd, Pacemaker, and Ansible content
  as reviewable envelopes until the selected product release and dependencies
  have separate environment evidence.

Production promotion requires a signed immutable source commit, green CI and
security workflows, a reviewed release artifact, and a current 100/100
environment-specific readiness manifest. Repository tests are not a substitute
for restore, failover, alert-delivery, penetration, or product certification.

Report vulnerabilities through the private process in `SECURITY.md`, not a
public issue.
