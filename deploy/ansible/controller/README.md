# Controller operating contract

`workflow.yml` is a controller-neutral operating contract for AWX, Red Hat
Ansible Automation Platform, or another approved automation controller. It is
not a credential export and contains no controller secrets.
CI and scripts/validate-ansible.sh run
scripts/validate-controller-contract.py to reject workflow-order, RBAC,
single-flight-lock, approval, binding, schedule, and secret-key drift.

The platform owner must create a project pinned to a full, signed immutable Git
commit, build or approve an execution-environment image pinned by digest, bind
RBAC-separated credentials, and enable immutable job/evidence retention. The
controller must run `scripts/verify-source-identity.sh` with the checked-out
commit SHA and the approved signer fingerprint list before tests or deployment.
It rejects a ref mismatch, tracked or unapproved untracked worktree changes,
an invalid commit signature, or a signer outside that list. Only the
documented operator inventory, Vault, release-manifest, and evidence paths may
be ignored inputs. The
production apply node must be a manual approval step; scheduled verification
and restore drills must use separate read-only credentials and targets. The
controller preflight also runs `scripts/verify-path-boundary.py` against the
checkout, readiness manifest, and evidence root before any controller-local
evidence directory is created; each evidence-producing role repeats the check
for its derived output directory immediately before writing. The
controller must enforce the `archiveweaver-production` single-flight lock
declared in `workflow.yml` across production apply, verification, rollback,
and repair workflows; `serial: 1` alone does not prevent separate jobs from
racing one another.
The standalone readiness node also verifies the protected
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` binding and requires the manifest's
`release.source_revision` to equal `ARCHIVEWEAVER_IMMUTABLE_REF` before it
scores the operator manifest. The later operational preflight repeats both
checks against the signed checkout used for that job.
Every source-gated certification, drill, apply, verification, repair, and
rollback job must inherit both source-integrity environment bindings so a
direct playbook invocation cannot run without the immutable-ref and trusted-
signer context. It must also inherit the controller-protected
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` binding; preflight runs
`scripts/verify-readiness-manifest.py` against the actual selected manifest
bytes and approved source commit for every source-gated operational job, so
changing an operator-owned manifest cannot bypass source verification. This
also permits staging and restore jobs to use their own approved manifest path.
Every operational role additionally requires the controller-preflight
completion attestation, so selecting only a provider/repair/verify tag or
skipping the `always` tag cannot reach a role without the controller checks.
The preflight attestation is tied to a current-run entrypoint, so
`--start-at-task` cannot jump directly to the completion fact. Non-check-mode
operational workflows also reject partial `--limit` runs and tag-filtered runs;
the shared evidence role requires an attested completion fact from every
upstream managed host before it can seal or publish evidence.
Every controller playbook command must use the repository's
`scripts/run-ansible-operational.sh` runner. It allowlists the seven approved
operational playbooks and rejects `--limit`, `--tags`, `--skip-tags`,
`--start-at-task`, and `--step` (plus the `-l`/`-t` aliases), including their
value-bearing forms. It also rejects credential, transport, and module-path
overrides, and pins the reviewed `ansible.cfg` and role tree. The runner clears
ambient Ansible configuration, credentials, transport, inventory, module,
collection, plugin, and Vault-path variables, plus `PYTHONPATH` and
`PYTHONHOME`, before exporting the reviewed config and role path. It requires
exactly one of the three protected operator inventories (`production`, `staging`, or `restore`),
rejects arbitrary inventory paths and inventory directories, and accepts only
explicit key/value bindings from `allowed-extra-vars.txt`. Extra-vars files,
raw YAML/JSON
documents, protected controller identity/parallelism values, and
`ansible_*` connection or privilege values are rejected. The
controller job template must not expose an alternate raw `ansible-playbook`
command for these workflows. After the approved playbook, the runner accepts
only check/diff/syntax-check flags, the single approved inventory binding, and
explicit `archiveweaver_*` extra variables; extra positional playbooks,
`--`, and all other unreviewed options are rejected.

The playbook verifies the controller's `ansible-playbook --version`,
`ansible-runner --version`, and `ansible-lint --version` outputs against the
pinned Core, Runner, and Lint versions before verification, repair, or
mutation. A controller with a different toolchain is rejected so job execution,
module behavior, lint policy, and safety checks cannot drift silently. The main,
verification, and repair entry points repeat the
signed-source check, so invoking a playbook directly cannot bypass the
controller workflow's source-integrity node.

Required workflow order:

1. validate the catalog and repository tests;
2. run `ansible-lint` and playbook syntax checks;
3. run staging check-mode/diff, product certification, and failure-domain tests;
4. verify backup and restore evidence, then run approved staging repair and
   rollback drills against a seeded staging installation;
5. index the resulting recovery records and score the exact release manifest;
6. require human approval for the separately authorized first-use Paperless RKE2
   bootstrap at 90/100, or score 100/100 for ordinary production apply;
7. run the mandatory post-apply verification, then verify health,
   dependencies, storage, and evidence;
8. retain signed logs and schedule the next restore/fixity/failure drill;
   failure-domain rehearsal must recur at least monthly unless service policy
   requires a shorter interval.

`workflow.yml` also declares `depends_on` for every node. The controller
implementation must require each listed predecessor to complete successfully;
the list is an execution dependency, not merely display order. The
`production-post-apply-verify` node is mandatory after an initial apply, while
scheduled `production-verify` remains an independent read-only path so an
hourly check cannot trigger a deployment. Scheduled verification, repair, and
rollback paths depend on the signed readiness stage and their own approval
node, so an on-demand recovery action cannot skip the same source and release
gates.

The `staging-repair-drill` and `staging-rollback-drill` nodes break the recovery
evidence dependency before the final readiness score. They use only the
approved staging inventory, staging change credentials, human approval, and
serial execution. The runner rejects `archiveweaver_recovery_drill=true` for
production or restore inventories and for any playbook other than `repair.yml`
or `rollback.yml`; controller and managed-host preflight repeat the staging
inventory check. The drill flag skips only the final 100/100 score check.
Signed source verification, the protected SHA-256 manifest bytes, production
solution/release/source identity, reviewed provider-bundle digest, and pinned
execution-environment image all remain required. The selected staging manifest
must describe the **production release being certified** and match the
controller-protected digest. Drill evidence records `environment: production`
as its target and `execution_environment: staging` as the actual execution
site. Index those passing records in the production target manifest before
running `readiness`; a staging preview or a planned/check-mode run is not
passing recovery evidence. A real, separately provisioned staging installation
and approved rollback artifact are required to run these drills.

The ordinary production apply still requires 100/100. An on-demand
`production-bootstrap-approval` and `production-bootstrap-apply` branch can
install Paperless-ngx on RKE2 for the first time. This branch requires a
controller-protected `ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256` distinct
from the protected full-manifest digest. The approved manifest contains a
`bootstrap_authorization` object with exactly the fields shown in
`release-manifest.example.json`. The independent approver must differ from the
change operator; `governance.approved_at` must precede issuance; the authorization
must expire within 24 hours and before `governance.valid_until`. Its digest is
SHA-256 over UTF-8 JSON produced with sorted keys, no whitespace separators,
and preserved Unicode (`json.dumps(record, sort_keys=True,
separators=(',', ':'), ensure_ascii=False)`). Protect that digest in a separate
controller approval credential or policy binding; a job submitter must not be
able to alter it or the approved readiness-manifest digest. The object binds
the exact release, source repository and commit, controller image, signed
provider bundle, Kustomize bytes, kubeconfig digest, protected production
inventory digest, cluster context, target namespace, change ticket, approval
ticket, and approving identity.
The authorization verifier also rehashes the stable full-manifest bytes against
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` on its own read.

Bootstrap accepts only an otherwise valid **90/100** report with `control`,
`release`, `product`, `resilience`, `data_protection`, `security`, `recovery`,
`governance`, and `support` passing. Only `observability` may be pending; the
bootstrap report remains `status: fail` and is never presented as 100/100.
This floor requires a real staging installation and isolated staging/restore
evidence. For an empty staging estate, the separate on-demand
`staging-seed-approval` and `staging-seed-apply` nodes first install the pinned
Paperless release into an empty three-node RKE2 staging target. The protected
manifest must identify `service.environment: staging`, score at least 40 and
below 100 with no validation errors, and pass `control`, `release`,
`governance`, and `support`. The separate `staging_seed_authorization` object
uses the exact fields in `staging-seed-authorization.example.json` with
`purpose: first-staging-apply`. Its canonical JSON SHA-256 belongs in
`ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256`, protected independently of
the full staging manifest, protected staging inventory digest, and production
bootstrap digests. It expires within
24 hours, stays inside the governance window, and requires an approver other
than the operator. The seed uses the same signed source, protected manifest,
immutable release and image proof, empty-host and absent-namespace checks,
atomic namespace claim, forced verification, and evidence seal. Its evidence
environment remains `staging`. Run certification and recovery drills only
after reviewing a successful seed; never treat the seed as production proof.

The runner confines bootstrap to an explicit non-check `site.yml` apply using
the complete production inventory. Controller and managed preflight repeat
the signed-checkout, protected-manifest, image, approval, backup, and 90-point
checks. Before any managed mutation, every host must lack its release record,
data root, and log root; the designated RKE2 control host must prove that the
dedicated namespace is absent using the approved kubeconfig and context.
Every rendered Kustomize document must be the one approved Namespace object
or an allowlisted namespaced API object explicitly bound to that namespace;
cluster-scoped and other-namespace objects are refused. The provider rechecks
namespace absence and atomically creates it before applying the already
validated rendered bytes. The control-host verification record includes the
new namespace UID. The `site.yml` play then forces post-apply verification and
evidence sealing. If a run mutates the target and
then fails, the first-use branch cannot be retried against that populated
target; handle it under a separately approved incident and recovery procedure.
After successful bootstrap, publish and review the new production observations,
update the protected manifest and evidence index, and reach 100/100 before
using the ordinary production jobs.

Ordinary Paperless/RKE2 production apply and verify jobs require the protected
manifest's complete `deployment_target` with the approved context, kubeconfig
and production inventory digests, application namespace, and live `kube-system`
and application Namespace UIDs. Set the separately protected
`ARCHIVEWEAVER_PRODUCTION_INVENTORY_SHA256` to the digest of the exact
root-owned production inventory supplied to the job. Controller preflight
compares those inventory bytes and the control-host kubeconfig with the
manifest, then queries both Namespace UIDs through the approved kubeconfig and
context before accepting the 100-point score. A changed cluster or recreated
Namespace requires new approval, manifest, and evidence.

Do not paste credentials into extra variables. Use controller credential
bindings, Ansible Vault, or an approved external secret manager.

The controller must inject the non-secret `archiveweaver_operator` and
`archiveweaver_fixture_set` identities into verification, restore, and failure
jobs, and the certification-specific identities into the product-certification
job. It must also inject the pinned `archiveweaver_release`, per-drill change
IDs, the five certification argv hooks, the four failure-domain argv hooks, and
the reviewed restore source/restore/fixity argv hooks, plus separate reviewed
rollback and post-rollback verification argv hooks. Bind
`archiveweaver_evidence_environment` to the release target (normally
`production`); the roles separately record the isolated execution environment.
Each reviewed hook binding must include the SHA-256 digest of its executable
and a separate digest of the complete canonical argv. Generate both values on
the controller with `archiveweaver hook-digest --json -- /absolute/hook arg`.
Certification and failure-drill rows carry `sha256` and `argv_sha256` beside
their argv; restore, rollback, observation, and evidence-publication hooks use
their corresponding `*_command_sha256` and `*_command_argv_sha256` variables.
The shared hook preflight rejects relative, symlinked, missing, non-regular, or
byte-changed executables and rejects any argument change before execution.
Inject `archiveweaver_execution_environment_digest` from the approved
controller image and keep it equal to the signed execution-environment digest
in the readiness manifest; applied workflows are rejected on a mismatch. Every
Ansible evidence record must repeat that digest so an audit can identify the
exact controller image that produced it. Additionally set the controller job
environment variable `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST` from the
controller's trusted execution-environment metadata; applied playbooks require
that value to match the injected variable and the manifest.
The workflow contract lists these required bindings explicitly so empty or
placeholder example defaults cannot look like completed evidence. Production
apply, verification, repair, and rollback jobs must also inject the selected
provider-content digests, health endpoint, and explicit Kubernetes kubeconfig,
kubeconfig SHA-256, and context bindings; preflight rejects missing values for
Kubernetes-family operations. The context must name the reviewed cluster in
the approved kubeconfig bytes.

The staging-preview node carries a runtime-specific binding map as well as its
common inputs. A raw preview requires the reviewed `ExecStart` and raw bundle
digest; Quadlet requires its immutable image and rendered-unit digest; Docker
and Swarm require the staged Compose path and product-stack digest; and each
Kubernetes-family preview requires the Kustomize path, deterministic bundle
digest, explicit kubeconfig and SHA-256 binding, and reviewed context. The generic preview marks Pacemaker
unsupported because this edition deliberately does not invent cluster
resources; use the separately reviewed Pacemaker procedure for that runtime.
