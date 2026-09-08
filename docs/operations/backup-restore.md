# Backup and restore

## Protected set

Back up all of the following, not just the database:

- PostgreSQL/MySQL database and grants;
- original bitstreams and derivatives;
- object-store buckets, versioning, lifecycle, and retention policy;
- application configuration and secret references;
- search schema, aliases, and rebuild instructions;
- queue/workflow state when it affects preservation processing;
- fixity manifests, PREMIS/OAIS events, audit trails, and logs;
- Kubernetes/RKE2/K3s/k0s/MicroK8s datastore snapshots;
- Pacemaker/Corosync configuration and fencing device configuration;
- deployment manifests, image digests, package locks, and catalog version.

## Restore order

1. Provision clean infrastructure and verify DNS, TLS, NTP, and network policy.
2. Restore database and grants.
3. Restore original content/object storage and verify checksums.
4. Restore application configuration and secret bindings.
5. Rebuild or restore search indexes using the product procedure.
6. Restore queue/workflow state only according to the product's documented consistency model.
7. Start the application and run read-only checks.
8. Run representative upload, download, metadata, preview/OCR, search, export, and fixity tests.
9. Compare record counts, checksums, audit events, and user-visible behavior.

## Restore acceptance

An acceptable restore has a recorded:

- backup timestamp and source;
- restore duration;
- RPO and RTO result;
- checksum/fixity result;
- database migration/version result;
- search/index reconciliation result;
- representative format fixture result;
- operator and change-ticket sign-off.

For a production release, attach these records to the readiness manifest and
run the 100-point gate before accepting traffic. A backup flag without a
successful clean-environment restore and fixity record is not sufficient.

