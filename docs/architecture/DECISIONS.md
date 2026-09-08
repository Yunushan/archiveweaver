# Architecture decision records

## ADR-001: Python standard library CLI

**Decision:** Use Python 3.9+ and the standard library for the core planner, checker, renderer, and repair engine.

**Reason:** The tool must run on a wide set of Ubuntu, Debian, Rocky, RHEL, and AlmaLinux baselines without forcing an application-specific dependency stack. Optional Ansible, Helm, and cloud SDK integrations can be added around the stable JSON contract.

## ADR-002: Catalog facts are generated but reviewable

**Decision:** Keep human-maintained facts in `catalog_source.py`, generate committed JSON, and validate both in CI.

**Reason:** Operators need a simple runtime artifact while reviewers need a readable source-of-truth diff. The validator prevents missing mode coverage and broken links from becoming silent gaps.

## ADR-003: Two-node consensus is not the default HA answer

**Decision:** Block two-node embedded-consensus plans unless an external datastore/quorum design is explicitly declared; require STONITH for Pacemaker two-node repair plans.

**Reason:** A two-node cluster has no spare vote when one node fails. Fencing is required to prevent split-brain and concurrent writes to shared state.

## ADR-004: Envelope rendering instead of fake universal charts

**Decision:** Render provider envelopes and keep product dependency stacks upstream-owned.

**Reason:** InvenioRDM, Islandora, Hyrax, Archivematica, Alfresco, and other products are multi-component platforms with release-specific dependencies. A generic chart that guesses those versions would be unsafe.

## ADR-005: Extension inventory is family-based

**Decision:** Maintain a broad extension/MIME catalog but do not equate an extension with preview, OCR, indexing, or preservation support.

**Reason:** Most repository/DMS products can store arbitrary binary objects, while transformation and browser support depends on converters, plugins, and release configuration.

## ADR-006: Ansible is an orchestration adapter, not a runtime

**Decision:** Support Ansible as a first-class orchestration edition layered
over the existing raw, container, Kubernetes, Swarm, and Pacemaker envelopes.

**Reason:** Ansible improves repeatability, idempotent host configuration,
check-mode review, rolling execution, secret boundaries, and evidence capture,
but it does not provide a scheduler, quorum, fencing, database replication, or
application-level HA. Modeling it separately keeps the support matrix honest
and lets the underlying runtime retain its real topology policy.

