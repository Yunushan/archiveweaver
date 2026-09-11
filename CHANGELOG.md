# Changelog

All notable changes will be documented here. The project follows semantic
versioning once a release is published; until then, the package remains alpha.

## Unreleased

- Harden packaging, release provenance, dependency locking, health semantics,
  immutable image handling, Ansible controller boundaries, and the evidence-
  backed production readiness gate.
- Add strict duplicate-key YAML validation and raise enforced branch coverage
  to 90%, with explicit malformed-evidence and release-gate tests.
- Add a deterministic, SPDX-validated Ansible controller SBOM and a complete
  wheel-only hash lock for the 51-package release validation toolchain.
- Reject skeletal or subject-confused SBOM/provenance evidence by enforcing
  production SPDX 2.3, CycloneDX 1.6/1.7, in-toto v1, and SLSA v1 profiles.
- Harden evidence sealing against concurrent file replacement, ambiguous index
  types, Windows junctions, and other link-like filesystem reparse points.
- Bind the exact evidence-index bytes into the protected readiness manifest so
  an index and its evidence cannot be replaced together without detection.
- Reject future-dated passing evidence instead of accepting a syntactically
  valid timestamp as proof of an event that has not occurred.
- Bind every manifest-side passing claim into its indexed JSON evidence record
  so a boolean or operational value cannot be changed independently of proof.
- Reject execution-environment images that lack exact locked Ansible Core,
  Ansible Runner, and ansible-lint versions, required source/transport tools,
  rootless readability, functional localhost execution, a named non-root
  `/runner` identity, an Ansible EE marker, a signal-forwarding init, or
  source/release/base OCI label bindings;
  release automation now scans, inventories, signs, attests, publishes, and
  emits a signed immutable-digest record for that controller image, with safe
  retry only when an existing registry tag contains the exact validated image.
- Make provider-tree digests collision-resistant by rejecting delimiter-
  ambiguous/nonportable filenames in both the CLI and Ansible verification.
- Publish GitHub Releases through an immutable-setting-gated draft state
  machine that re-verifies the signed tag, reuses only exact server-digested
  assets, never clobbers evidence, and verifies the final immutable release;
  bind and re-exercise the Ansible image's complete runtime defaults after its
  credential-separated transfer, and bound every GitHub CLI publication call
  so a stalled API cannot leave the credentialed job waiting indefinitely.
- Bound release publication to 64 regular, single-link assets, 1 GiB per asset,
  and 2 GiB in aggregate; reject link-like or changing paths and malformed,
  duplicate-key, or non-finite GitHub API JSON before any publication mutation.
- Restrict privileged release jobs to tag-push events and require an
  environment-controlled allowlist for both the original push actor and any
  rerun actor.
- Add a read-only, fail-closed audit for twelve hosted GitHub production
  controls, including rulesets, Actions policy, security features, immutable
  releases, and the protected release environment; bind its exact-schema,
  repository-ID-, commit-, and time-bound certificate, exact digest, Sigstore
  v0.3 keyless bundle, identity-verification record, and provenance subject
  into the 100-point release-integrity evidence so a stale, skeletal, unsigned,
  nonexistent-source, unmerged-side-branch, or mismatched hosted-control claim
  cannot score.
- Extend strict mypy enforcement across every Python automation script and add
  hash-locked PyYAML type stubs instead of suppressing validator types.
- Pin every GitHub Actions job to the Ubuntu 24.04 runner family and enforce
  that policy in the workflow contract tests, avoiding silent OS-family drift.
- Make the Ansible lock generator resolve the complete Linux target dependency
  closure, explicitly pin `ruamel-yaml-clib`, and reject host-dependent lock
  omissions before they can break a clean controller or image build.
- Add a weekly, OIDC-authenticated OpenSSF Scorecard workflow with immutable
  action pins, read-only defaults, retained SARIF, code-scanning publication,
  and Actions-allowlist coverage in the hosted-control audit while keeping the
  scheduled signal outside pull-request required checks.
- Write rendered deployment output through a flushed atomic replacement so a
  final-component symlink swap cannot redirect or partially truncate output.
- Enforce domain-specific evidence freshness, including RPO-bounded backup
  proof, weekly vulnerability scans, monthly security and observability proof,
  quarterly operational drills, and annual penetration-test evidence.
- Bound provider digest file, tree-entry, file-count, path, and aggregate-byte
  consumption; reject hard links, special files, case collisions, and trees
  that change across the complete measurement window.
- Reject hard-linked manifests, indexes, and evidence files at the stable
  file-descriptor boundary so an alias outside the sealed bundle cannot mutate
  trusted bytes or let one physical file impersonate independent proof.
- Bound manifest, structured-evidence, index-size, index-entry, JSON-depth, and
  JSON-node resource use; reject duplicate keys and non-standard/non-finite
  numbers, and translate decoder recursion exhaustion into controlled failures
  so hostile evidence fails closed rather than crashing the gate.
- Seal generated repair plans with a process-local capability, authenticate an
  isolated execution snapshot, reject forged or modified dictionaries, and
  discard child-process output at the operating-system boundary.
