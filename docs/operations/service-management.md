# Premium service management

This runbook is the operating contract around the repository. It becomes a
real SLA only after the service owner, platform owner, preservation owner, and
on-call organization approve the values in the release readiness manifest.

## Minimum service objectives

Record these values per service and collection:

| Objective | Required record |
| --- | --- |
| Availability | Monthly target, measurement window, exclusions, and health endpoint |
| RPO | Maximum acceptable data loss in minutes, including queued workflow state |
| RTO | Maximum time to restore service and validate content/fixity |
| Incident response | Severity levels, acknowledgement target, update cadence, and escalation |
| Maintenance | Approval window, rollback point, customer communication, and evidence owner |
| Support | Service owner, primary/secondary on-call rotations, and vendor escalation |

## Incident sequence

1. Acknowledge the alert and open an incident record.
2. Freeze unrelated changes and preserve controller, application, cluster, and
   backup evidence.
3. Check the latest restorable backup and current fixity state before repair.
4. Run the plan-only ArchiveWeaver or Ansible repair workflow.
5. Obtain incident-commander approval for any explicit apply or rollback.
6. Verify dependencies, authorization, representative formats, and fixity.
7. Record observed impact, RPO/RTO, commands, evidence hashes, and root cause.
8. Complete a blameless review with corrective actions and an owner/date.

## Change and release lifecycle

No production release is complete until the controller has a signed immutable
source reference, pinned execution environment, 100/100 readiness report,
staging result, backup/restore result, approval record, and post-deployment
verification. Schedule read-only verification at least hourly and a clean
restore/fixity drill at least weekly unless the approved service policy is
stricter.

## Evidence retention

Retain plans, manifests, controller job records, deployment output, health
checks, backup/restore evidence, fixity summaries, approvals, and incident
records in immutable storage for the approved retention period. Keep secrets,
private keys, tokens, and raw archive documents out of the evidence bundle.
Verification runs must also bind a non-secret operator identity and reviewed
fixture-set identifier so the resulting evidence can be matched to the exact
release and environment.
