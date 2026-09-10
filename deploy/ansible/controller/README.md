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
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` binding before it scores the
operator manifest, so the score used for promotion is the same manifest that
the later operational preflight will accept.
Every source-gated certification, drill, apply, verification, repair, and
rollback job must inherit both source-integrity environment bindings so a
direct playbook invocation cannot run without the immutable-ref and trusted-
signer context. It must also inherit the controller-protected
`ARCHIVEWEAVER_READINESS_MANIFEST_SHA256` binding; preflight runs
`scripts/verify-readiness-manifest.py` against the actual selected manifest
bytes before any non-check-mode operational job, so changing an operator-owned
manifest cannot bypass source verification. This also permits staging and
restore jobs to use their own approved manifest path.
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
explicit `archiveweaver_*` key/value bindings. Extra-vars files, raw YAML/JSON
documents, protected controller identity/parallelism values, and
`ansible_*` connection or privilege values are rejected. The
controller job template must not expose an alternate raw `ansible-playbook`
command for these workflows. After the approved playbook, the runner accepts
only check/diff/syntax-check flags, the single approved inventory binding, and
explicit `archiveweaver_*` extra variables; extra positional playbooks,
`--`, and all other unreviewed options are rejected.

The playbook verifies the controller's `ansible-playbook --version` and
`ansible-lint --version` outputs against the pinned Core and Lint versions
before verification, repair, or mutation. A controller with a different
toolchain is rejected so module behavior, lint policy, and safety checks cannot
drift silently. The main, verification, and repair entry points repeat the
signed-source check, so invoking a playbook directly cannot bypass the
controller workflow's source-integrity node.

Required workflow order:

1. validate the catalog and repository tests;
2. run `ansible-lint` and playbook syntax checks;
3. run staging check-mode/diff, product certification, and failure-domain tests;
4. verify backup and restore evidence plus a tested rollback point;
5. score the exact release manifest at 100/100;
6. require human approval for serial production apply, repair, or rollback;
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
Each reviewed hook binding must also include the SHA-256 digest of its
executable. Certification and failure-drill rows carry `sha256` beside their
argv; restore, rollback, and evidence-publication hooks use their corresponding
`*_command_sha256` variables. The shared hook preflight rejects relative,
symlinked, missing, non-regular, or byte-changed executables before execution.
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
provider-content digests, health endpoint, and explicit Kubernetes kubeconfig
binding; the provider preflight rejects a missing or mismatched value.

The staging-preview node carries a runtime-specific binding map as well as its
common inputs. A raw preview requires the reviewed `ExecStart` and raw bundle
digest; Quadlet requires its immutable image and rendered-unit digest; Docker
and Swarm require the staged Compose path and product-stack digest; and each
Kubernetes-family preview requires the Kustomize path, deterministic bundle
digest, and explicit kubeconfig. The generic preview marks Pacemaker
unsupported because this edition deliberately does not invent cluster
resources; use the separately reviewed Pacemaker procedure for that runtime.
