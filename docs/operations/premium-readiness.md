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
The CLI also rejects a manifest, evidence index, referenced file, or provider
digest input whose path contains a symlinked directory component, and rejects
symlinked entries while sealing a tree; containment is checked before path
resolution so a link cannot redirect the review outside the bundle.
The manifest must not contain passwords, tokens, private keys, or document
content.
JSON manifests, evidence attestations, and evidence indexes are parsed with
duplicate-key rejection; a document with ambiguous repeated object keys is not
eligible for any passing criterion.
The release provenance reference must point to an indexed in-toto Statement
with a valid statement type and recognizable subject/build/predicate content,
and each SBOM reference must point to an indexed SPDX or CycloneDX JSON
document with a valid format/version identity and package/component content.
Each in-toto release-provenance `subject` must carry the exact manifest
artifact/provider-bundle name together with the SHA-256 digest of every
referenced product artifact and the reviewed Ansible provider bundle; the
execution-environment provenance must carry the exact execution-environment
name and digest of its immutable image. A passing boolean beside an empty,
unrelated, or
digest-mismatched file is not release proof.
The control and governance change tickets must agree. When both domains pass,
the support and data-protection RPO/RTO values must agree, and the
observability and support on-call identifiers must agree.

## 100-point rubric

| Domain | Points | Required proof |
| --- | ---: | --- |
| Control baseline | 10 | Catalog validation, green CI, and change-control record |
| Release integrity | 10 | Immutable version, verified product and provider-bundle artifact digests, SBOMs, signatures, signature-verification records, provenance bound to every product and Ansible provider artifact, signed/SBOM-backed Ansible execution-environment image, and canonical staged-content `remote_digest` |
| Product certification | 10 | Catalog-bound component/dependency/format coverage plus smoke, migration, and API matrix |
| Resilience | 10 | Quorum/fencing review and recorded node, service, dependency, and storage failure tests |
| Data protection | 10 | Immutable backup, successful restore, fixity verification, and measured RPO/RTO |
| Security | 10 | Dedicated indexed SBOM, TLS, and secret-provider verification records, plus vulnerability scan and penetration review |
| Observability | 10 | Dedicated indexed metrics, alert-rule, dashboard, and on-call records, plus an alert-delivery test |
| Recovery | 10 | Signed, digest-verified previous-release artifact, rollback, and named-resource repair tests |
| Governance | 10 | Risk review, approver, change ticket, immutable/access-logged evidence retention, and retention-control evidence |
| Support | 10 | Dedicated indexed service-owner, on-call, and SLA records, plus RPO/RTO and current runbooks |

The CLI returns exit code 0 only at 100/100. Any missing, placeholder,
out-of-bundle, unindexed, tampered, or failed evidence keeps the result
non-ready. Every domain must explicitly declare `status: pass`. The Ansible
preflight role runs the same controller-side command before a mutation, so a
manually changed boolean cannot bypass the score.
The controller workflow's standalone readiness node also verifies the
protected `ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` value before scoring, so
promotion cannot score a different operator manifest from the one later
accepted by operational preflight.
For Ansible, the release section must also identify and hash the reviewed
provider bundle. Its artifact `digest` is checked against the release bundle;
its canonical `remote_digest` is compared with the staged remote Compose,
Swarm, Kustomize, raw systemd, or Quadlet content.
Artifact names and proof paths must be unique across the release artifacts,
provider bundle, execution-environment attestations, and rollback artifact;
the same release section must identify the immutable Ansible execution
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
recovery domain. Passing security, observability, and support sections must
also include dedicated indexed evidence records for each operational claim;
the human-readable endpoint, policy, ownership, or SLA fields are identifiers,
not proof by themselves. Each dedicated claim record and each named
certification or failure-domain test must point to its own indexed evidence
file; duplicating one file across claims or test rows cannot satisfy the gate.

## Operational ownership

The release owner supplies product-specific manifests and test evidence. The
platform owner supplies the controller, execution environment, inventory,
RBAC, network, and monitoring. The preservation owner signs off backup,
restore, fixity, and representative-format results. The service owner accepts
the SLA and maintains the on-call and incident runbooks.

The repository provides the contract and safe execution boundary; it does not
invent application dependencies, fabricate failure evidence, or create an SLA
without those owners and their systems.

The readiness manifest is operator-owned because it contains environment- and
release-specific evidence bindings, but it is not trusted merely because its
fields say `pass`. For every non-check-mode operational workflow, the approved
controller must protect `ARCHIVEWEAVER_READINESS_MANIFEST_SHA256`; controller
preflight compares that digest with the actual regular manifest file before
contacting managed hosts. The signed source checkout and this protected digest
must be set together for the same promotion.

The supplied `restore-drill.yml` is a non-production hook runner. It refuses
production targets, defaults to plan-only, requires reviewed argument-vector
hooks for both restore and fixity, suppresses command output, and records only
redacted return-code evidence. Product owners must provide the actual restore
and fixity procedures for the selected release.

Every operational playbook, including certification and restore/failure/
rollback drills, first checks the controller's live `ansible-playbook` and
`ansible-lint` versions against the pinned execution-environment versions. A
controller with a different toolchain is stopped before it can run a drill or
mutation. Controller preflight also rejects symlinked components in the source,
manifest, and evidence paths before any controller-local evidence directory is
created. Each verification, repair, certification, restore, failure-drill, and
rollback role repeats the boundary check for its derived output directory
immediately before writing. The evidence role also requires an attested
completion fact from every upstream managed target before sealing; production
mutations and repairs reject tag-filtered runs so verification and evidence
cannot be skipped accidentally. The controller and managed preflight
attestations are tied to a current-run entrypoint, and the operational runner
rejects partial `--limit` runs as well as `--tags`, `--skip-tags`, `--step`,
credential, transport, and module-path overrides. This prevents an operator
from selecting a mutation while omitting verification, evidence sealing, or
part of the target group, or from replacing the controller-bound execution
identity. It also requires exactly one protected production, staging, or
restore inventory and accepts only explicit `archiveweaver_*` key/value
bindings; extra-vars files, raw YAML/JSON documents, protected controller
identity/parallelism values, and `ansible_*` transport or privilege values are
rejected.

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
retention/immutability/access-logging bindings to them. Their executable paths
must be absolute, regular, non-symlink files whose bytes match the supplied
lowercase SHA-256 bindings. Ansible re-verifies the local index after the
publication hook returns, and a successful local index alone cannot satisfy
the external retention control.
The verification role separately re-hashes and re-renders staged Compose,
Swarm, Kustomize, raw systemd, and Quadlet content so a deployment that drifts
from the certified provider bundle cannot silently remain ready.
