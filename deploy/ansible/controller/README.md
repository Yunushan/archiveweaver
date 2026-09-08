# Controller operating contract

`workflow.yml` is a controller-neutral operating contract for AWX, Red Hat
Ansible Automation Platform, or another approved automation controller. It is
not a credential export and contains no controller secrets.

The platform owner must create a project pinned to an immutable Git commit,
build or approve an execution-environment image pinned by digest, bind
RBAC-separated credentials, and enable immutable job/evidence retention. The
production apply node must be a manual approval step; scheduled verification
and restore drills must use separate read-only credentials and targets.

The playbook verifies the controller's `ansible-playbook --version` output
against `archiveweaver_ansible_core_version` before verification, repair, or
mutation. A controller with a different Core version is rejected so module
behavior and safety checks cannot drift silently.

Required workflow order:

1. validate the catalog and repository tests;
2. run `ansible-lint` and playbook syntax checks;
3. run staging check-mode/diff, product certification, and failure-domain tests;
4. verify backup and restore evidence plus a tested rollback point;
5. score the exact release manifest at 100/100;
6. require human approval for serial production apply;
7. verify health, dependencies, storage, and evidence;
8. retain signed logs and schedule the next restore/fixity/failure drill;
   failure-domain rehearsal must recur at least monthly unless service policy
   requires a shorter interval.

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
Inject `archiveweaver_execution_environment_digest` from the approved
controller image and keep it equal to the signed execution-environment digest
in the readiness manifest; applied workflows are rejected on a mismatch. Every
Ansible evidence record must repeat that digest so an audit can identify the
exact controller image that produced it. Additionally set the controller job
environment variable `ARCHIVEWEAVER_EXECUTION_ENVIRONMENT_DIGEST` from the
controller's trusted execution-environment metadata; applied playbooks require
that value to match the injected variable and the manifest.
The workflow contract lists these required bindings explicitly so empty or
placeholder example defaults cannot look like completed evidence.
