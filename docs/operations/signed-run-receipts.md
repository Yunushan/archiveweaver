# Signed operational run receipts

For Paperless-ngx on production RKE2, the readiness scorer now requires an
indexed schema-2 run receipt with a Sigstore signature for every passing
operational claim. The receipt must match the claim, release, source, execution
environment, deployment target, approved command digests, and exact evidence
bytes. Operational JSON outcomes without a trusted receipt cannot earn points.

## Trust boundary

1. Before execution, the controller protects a `deployment-declaration.json`
   and its SHA-256 digest. It names the immutable source, release, provider
   bundle, execution-environment and product image digests; approved inventory
   and kubeconfig digests; kube context; target namespace; live `kube-system`
   Namespace UID; and each allowed hook executable and canonical argument
   digest. The job submitter cannot replace this declaration after approval.
2. A separate trusted runner observes each actual command, its exit status,
   result artifact, and the Kubernetes API target. It signs the exact receipt
   bytes with an operational-evidence identity fixed in controller policy. A
   generic sign-arbitrary-JSON command available to the job submitter is not
   sufficient.
3. Each claim uses a distinct schema-2 receipt with exactly these fields:
   `schema_version`, `claim`, `status`, `service`, `release_version`,
   `source_revision`, `execution_environment_digest`, `deployment_target`,
   `run_id`, `started_at`, `completed_at`, `hook`, `returncode`,
   `evidence_sha256`, and `runner`. `hook` contains the executable and argv
   SHA-256 digests pinned in the corresponding manifest record. `runner`
   contains its approved name, immutable image, and image digest. The evidence
   digest covers the exact indexed JSON outcome. The receipt binds the release
   and deployment target directly, so it does not depend on a circular digest
   of the final manifest. An adjacent Sigstore bundle signs the exact receipt
   bytes. Build the evidence index and final readiness manifest only **after**
   receipts and signatures are sealed.
4. The readiness scorer verifies every indexed receipt signature against the
   protected `operational-evidence` signer policy, then checks the exact claim,
   input digests, target, hook, return code, and freshness. Each passing
   manifest evidence record must name `run_receipt.path`,
   `run_receipt.signature`, `run_receipt.signer`, and both `run_hook` digests.
   Controller preflight
   independently fetches the live `kube-system` and application Namespace UIDs
   and compares them to the protected declaration and receipts. For first use,
   the pre-run receipt records the absent application Namespace and its
   approved name; a post-apply receipt records its created UID.

## Required rejection tests

- Self-declared `status: pass` without a signed receipt.
- A valid receipt replayed for another cluster, namespace, release, source
  revision, provider bundle, execution environment, or approved command.
- A changed result artifact, nonzero return code, missing run history, stale
  timestamp, duplicate claim, or unapproved signer identity.
- A receipt signed by the job submitter instead of the independent runner.
- A target UID that differs from the live Kubernetes API during preflight.

An offline CLI verifies a signed, time-bound snapshot; it cannot by itself
prove the current cluster state. The independent live preflight is required
when that snapshot authorizes a production mutation. The trusted-runner
integration that observes commands and signs receipts is an external control;
the repository verifies its receipt format and signature but cannot prove the
runner was operated independently. Protect that runner identity and policy
outside the job submitter's control.
