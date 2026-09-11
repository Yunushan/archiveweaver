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
The `evidence_index` field must point to a verified SHA-256 index, and
`evidence_index_digest` must contain the lowercase `sha256:` digest of the
exact index bytes. Because the controller separately protects the readiness
manifest digest, this binding transitively protects the selected evidence
inventory as well as the manifest fields. Every referenced artifact,
signature, provenance file, test record, and runbook must be inside the
index's directory and listed by that index; a merely existing file is not
enough.
The CLI also rejects a manifest, evidence index, referenced file, or provider
digest input whose path contains a symlink, Windows junction, or other reparse
point, and rejects link-like entries while sealing a tree; containment is
checked before path resolution so a redirected component cannot move the
review outside the bundle. The manifest and evidence files are measured
through stable regular file descriptors and must have exactly one hard link,
so an out-of-bundle alias cannot mutate sealed bytes. The index accepts only
canonical non-negative byte counts and lowercase SHA-256 values with no
unknown schema fields. Every
artifact or evidence document is remeasured against the verified index at the
moment it is consumed, so replacing a same-size file after initial index
verification still fails closed.
The manifest must not contain passwords, tokens, private keys, or document
content.
JSON manifests, evidence attestations, and evidence indexes are parsed with
duplicate-key rejection; a document with ambiguous repeated object keys is not
eligible for any passing criterion. Non-standard or non-finite JSON numbers,
excessive nesting, oversized structured evidence, oversized manifests and
unbounded evidence indexes also fail closed instead of exhausting the
controller.
The release provenance reference must point to an indexed in-toto Statement
v1 carrying a SLSA provenance v1 predicate, non-duplicate SHA-256 subjects,
an absolute build-type URI, external parameters, and an identified builder.
Each SBOM reference must point to an indexed production-profile document:
SPDX 2.3 requires its document identity, CC0 data license, namespace, creation
metadata, unique packages, and an explicit `documentDescribes` subject;
CycloneDX 1.6 or 1.7 requires its official schema identity, serial number,
positive BOM version, timestamp, typed metadata subject, and typed component
inventory. The named release artifact must be the described SPDX package or
the CycloneDX metadata component, not merely an unrelated dependency that
happens to share a name.
Each in-toto release-provenance `subject` must carry the exact manifest
artifact/provider-bundle name together with the SHA-256 digest of every
referenced product artifact and the reviewed Ansible provider bundle; the
execution-environment provenance must carry the exact execution-environment
name and digest of its immutable image. The release provenance's SLSA
`resolvedDependencies` must also name the canonical GitHub source repository
and bind its `gitCommit` digest to `release.source_revision`. A passing boolean beside an empty,
unrelated, or
digest-mismatched file is not release proof.
Release integrity also binds the code to its hosted GitHub enforcement. Set
`release.source_repository` to the canonical `owner/repository` slug,
`release.source_repository_id` to GitHub's positive numeric repository ID, and
`release.source_revision` to the exact lowercase 40-character commit SHA.
From that clean, signed checkout, create `release.github_controls` with:

```bash
GITHUB_REPOSITORY=owner/repository make github-audit \
  > deploy/ansible/evidence/github-production-controls.json
```

`release.github_controls` is a signed-reference object, not a bare path. Set
its `path` to the generated certificate, `digest` to the certificate's exact
SHA-256 digest, `signature` to its non-empty Sigstore bundle, and
`signature_verified` to `true` only after identity verification. Its
`signature_verification` record must be passing, name the verifier, bind
`artifact_digest` to the same digest, and carry the common release metadata.
The certificate, signature bundle, and verification record must be three
distinct files listed in the evidence index. The bundle must be canonical
Sigstore v0.3 keyless blob-signing JSON with a certificate, transparency-log
material, and an embedded SHA-256 digest matching the certificate bytes. The
release provenance must include the certificate filename and digest as a
subject, alongside the product and provider artifacts.

The certificate is bound to the authoritative repository name, stable
repository ID and node ID, local `HEAD`, GitHub API version, and a UTC
observation time; the source SHA must resolve to an existing GitHub-verified
commit reachable from protected `main` in that repository. It is eligible for
the score for no more than 24 hours. Its
schema must be exact, with no unknown or duplicate fields, and all twelve
repository, security, Actions, environment, release-immutability, branch, and
tag controls must be present exactly once with `passed: true`. A copied report
for another repository or commit, an unsigned or digest-mismatched report, a
stale report, or a top-level success flag masking a failed or missing control
fails release integrity.
The control and governance change tickets must agree. When both domains pass,
the support and data-protection RPO/RTO values must agree, and the
observability and support on-call identifiers must agree.

## 100-point rubric

| Domain | Points | Required proof |
| --- | ---: | --- |
| Control baseline | 10 | Catalog validation, green CI, and change-control record |
| Release integrity | 10 | Fresh, digest-bound, Sigstore-signed, source-bound 12-control GitHub production certificate; immutable version; verified product and provider-bundle artifact digests, SBOMs, signatures, and signature-verification records; provenance bound to every product and Ansible provider artifact; signed/SBOM-backed Ansible execution-environment image; and canonical staged-content `remote_digest` |
| Product certification | 10 | Catalog-bound component/dependency/format coverage plus smoke, migration, and API matrix |
| Resilience | 10 | Quorum/fencing review and recorded node, service, dependency, and storage failure tests |
| Data protection | 10 | Immutable backup, successful restore, fixity verification, and measured RPO/RTO |
| Security | 10 | Dedicated indexed SBOM, TLS, and secret-provider verification records, plus vulnerability scan and penetration review |
| Observability | 10 | Dedicated indexed metrics, alert-rule, dashboard, and on-call records, plus an alert-delivery test |
| Recovery | 10 | Signed, digest-verified previous-release artifact, rollback, and named-resource repair tests |
| Governance | 10 | Risk review, approver, change ticket, unexpired approval window, immutable/access-logged evidence retention, and retention-control evidence |
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
not sufficient. Every manifest claim in that record must be represented
identically in the indexed JSON evidence, although the evidence may add further
detail. Future-dated evidence is rejected. Governance approval and
expiry must use the same timestamp
form; approval cannot be future-dated, must still be current, and may cover at
most 30 days. Reassess and reapprove rather than extending an old manifest.
Passing records are also rejected when `recorded_at` exceeds the cadence for
their operational domain:

| Evidence record | Maximum age |
| --- | ---: |
| Control baseline | 24 hours |
| Release verification | 30 days; the hosted GitHub audit remains limited to 24 hours |
| Product certification | 90 days |
| Resilience and failure-domain drills | 90 days |
| Data-protection baseline | 30 days |
| Backup | The smaller of 24 hours and the declared RPO |
| Restore drill | 90 days |
| Fixity test | 30 days |
| Security baseline, TLS, SBOM, and secrets-provider checks | 30 days |
| Vulnerability scan | 7 days |
| Penetration test | 365 days |
| Observability and alert-delivery checks | 30 days |
| Rollback and repair drills | 90 days |
| Governance evidence | 30 days, in addition to the approval window |
| Service ownership, on-call, SLA, and runbook evidence | 90 days |

The five-minute clock-skew tolerance is only a collection-time allowance; it
does not extend the operating cadence. Refresh the underlying test or control
evidence instead of rewriting an old timestamp.
Arbitrary text is not accepted as audit time. The recovery section must also
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
restore inventory and accepts only exact keys in the reviewed
`deploy/ansible/controller/allowed-extra-vars.txt` file; extra-vars files, raw
YAML/JSON documents, protected controller
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

sha256sum deploy/ansible/evidence/evidence-index.json
```

After the final index is generated, copy the command's lowercase digest into
the operator manifest as `evidence_index_digest: sha256:<digest>`, then compute
and protect `ARCHIVEWEAVER_READINESS_MANIFEST_SHA256`. Keep the operator
manifest outside the indexed evidence directory: the manifest binds the index,
so indexing that manifest would create a circular digest dependency. Rebuild
and rebind the index after any evidence change.

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
