# Premium readiness contract

ArchiveWeaver's premium score is environment-specific. A repository can be
well engineered while a particular product release is still uncertified. The
score therefore reaches 100 only when every control below has a passing,
local evidence file for the exact solution, release, runtime, and environment.
For the Ansible edition, set `service.runtime` to `ansible` and identify the
provider it coordinates with `service.underlying_runtime`; the preflight role
binds both values to the controller invocation.

## Run the gate

Start from the repository root on the automation controller:

```bash
PYTHONPATH=src python3 -m archiveweaver readiness \
  --manifest deploy/ansible/release-manifest.json \
  --json
```

Use `deploy/ansible/release-manifest.example.json` as the shape, copy it to
the ignored operator file, and replace every placeholder. Evidence paths must
be relative to the manifest and resolve to files inside that evidence bundle.
The `evidence_index` field must point to a verified SHA-256 index. Every
referenced artifact, signature, provenance file, test record, and runbook must
be inside the index's directory and listed by that index; a merely existing
file is not enough.
The manifest must not contain passwords, tokens, private keys, or document
content.
The provenance reference must point to an indexed JSON attestation containing
recognizable subject/build/predicate content, and each SBOM reference must
point to an indexed SPDX or CycloneDX JSON document with package/component
content. A passing boolean beside an empty file is not release proof.

## 100-point rubric

| Domain | Points | Required proof |
| --- | ---: | --- |
| Control baseline | 10 | Catalog validation, green CI, and change-control record |
| Release integrity | 10 | Immutable version, verified artifact digest, SBOM, signature, signature-verification record, provenance, signed/SBOM-backed Ansible execution-environment image, reviewed provider-bundle artifact digest, and canonical staged-content `remote_digest` |
| Product certification | 10 | Catalog-bound component/dependency/format coverage plus smoke, migration, and API matrix |
| Resilience | 10 | Quorum/fencing review and recorded node, service, dependency, and storage failure tests |
| Data protection | 10 | Immutable backup, successful restore, fixity verification, and measured RPO/RTO |
| Security | 10 | SBOM verification, vulnerability scan, penetration review, TLS verification, and secret-provider proof |
| Observability | 10 | Metrics, alert rules, dashboards, escalation/on-call, and alert-delivery test |
| Recovery | 10 | Signed, digest-verified previous-release artifact, rollback, and named-resource repair tests |
| Governance | 10 | Risk review, approver, change ticket, immutable/access-logged evidence retention, and retention-control evidence |
| Support | 10 | Service owner, on-call rotation, SLA, RPO/RTO, and current runbooks |

The CLI returns exit code 0 only at 100/100. Any missing, placeholder,
out-of-bundle, unindexed, tampered, or failed evidence keeps the result
non-ready. Every domain must explicitly declare `status: pass`. The Ansible
preflight role runs the same controller-side command before a mutation, so a
manually changed boolean cannot bypass the score.
For Ansible, the release section must also identify and hash the reviewed
provider bundle. Its artifact `digest` is checked against the release bundle;
its canonical `remote_digest` is compared with the staged remote Compose,
Swarm, Kustomize, raw systemd, or Quadlet content.
The same release section must identify the immutable Ansible execution
environment image, matching image digest, provenance, SBOM, signature, and
signature-verification record. Applied playbooks also compare the controller's
injected execution-environment digest with that manifest value.
Every passing evidence record must carry a stable `name` and the exact manifest `solution`,
`runtime`, `underlying_runtime` (for Ansible), `os_id`, `release`, and target
`environment`, plus a timezone-qualified RFC 3339 `recorded_at`, an operator,
and a fixture-set identifier. For Ansible, it must also carry the exact
`release.execution_environment.digest` used by the controller. If a test runs in an isolated environment, record
that location as `execution_environment` without changing the target environment.
JSON evidence targets must also contain a
matching `status: pass` record; hashing an empty or semantically empty file is
not sufficient. Governance approval must use the same timestamp form;
arbitrary text is not accepted as audit time. The recovery section must also
identify a different previous release and an indexed rollback artifact whose
bytes, SBOM, detached signature, and signature-verification record match its
SHA-256 digest. A current-release label, an undigested rollback claim, or a
digest string without the previous artifact proof does not satisfy the
recovery domain.

## Operational ownership

The release owner supplies product-specific manifests and test evidence. The
platform owner supplies the controller, execution environment, inventory,
RBAC, network, and monitoring. The preservation owner signs off backup,
restore, fixity, and representative-format results. The service owner accepts
the SLA and maintains the on-call and incident runbooks.

The repository provides the contract and safe execution boundary; it does not
invent application dependencies, fabricate failure evidence, or create an SLA
without those owners and their systems.

The supplied `restore-drill.yml` is a non-production hook runner. It refuses
production targets, defaults to plan-only, requires reviewed argument-vector
hooks for both restore and fixity, suppresses command output, and records only
redacted return-code evidence. Product owners must provide the actual restore
and fixity procedures for the selected release.

Every operational playbook, including certification and restore/failure/
rollback drills, first checks the controller's live `ansible-playbook` version
against the pinned execution-environment version. A controller with a
different Core version is stopped before it can run a drill or mutation.

`failure-drill.yml` follows the same boundary for node, service, dependency,
and storage failure hooks. `rollback.yml` is separately approval-gated and
requires a pinned previous artifact, verified backup, a reviewed rollback hook,
and a separate reviewed post-rollback verification hook. Neither playbook
fabricates a product-specific recovery command.

After each deploy, verification, repair, restore, failure-drill, or rollback
playbook, the Ansible evidence role seals the shared controller evidence root:

```bash
PYTHONPATH=src python3 -m archiveweaver evidence-index \
  --directory deploy/ansible/evidence \
  --output evidence-index.json \
  --json

PYTHONPATH=src python3 -m archiveweaver evidence-index \
  --verify deploy/ansible/evidence/evidence-index.json \
  --json
```

Upload the index and files to immutable, access-controlled storage. The index
detects post-run modification and unindexed files; it does not replace storage
immutability, signatures, access logging, or retention policy.
For non-check-mode production evidence runs, the role also requires reviewed
controller-side publication and verification argv hooks and passes the
retention/immutability/access-logging bindings to them. A successful local
index alone cannot satisfy the external retention control.
The verification role separately re-hashes and re-renders staged Compose,
Swarm, and Kustomize content so a deployment that drifts from the certified
provider bundle cannot silently remain ready.
