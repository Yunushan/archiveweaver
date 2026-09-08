# Product release certification

The 100-point gate is applied to one exact product release and one target
environment. A catalog entry is not a product certification. The release owner
must attach evidence for the actual dependency graph and application behavior.

The Ansible edition provides `deploy/ansible/product-certification.yml` for
the executable part of this contract. Run it only against the isolated
`archiveweaver_certification` inventory group. It remains plan-only by default
and accepts five reviewed argument-vector hooks named `dependencies`, `smoke`,
`migration`, `formats`, and `api`; it never accepts a shell string and never
writes hook stdout to evidence.

## Catalog-bound coverage

The readiness evaluator binds certification to the selected catalog entry. Add
`product_certification.dependency_coverage` and
`product_certification.format_coverage` and
`product_certification.component_coverage` to the manifest. List every
dependency, format profile, and architecture component declared by that
solution, using the catalog spellings. A passing five-row test matrix with
incomplete coverage does not qualify for 100/100. This prevents an Ansible
deployment from silently omitting a worker, converter, queue, storage
integration, or supported preservation profile.

## Required test matrix

Every `product_certification.test_matrix` entry in the readiness manifest must
cover at least these five areas:

1. **Dependencies:** database, search, queue, object storage, converters, and
   ingress versions and connectivity.
2. **Application smoke:** login, authorization, upload/import, metadata,
   retrieval/download, preview/OCR, API, and export.
3. **Migration:** clean install, upgrade from the previous pinned release,
   rollback decision, and database/schema compatibility.
4. **Formats and preservation:** representative documents, images, audio,
   video, email, structured data, archives, and fixity/PREMIS behavior for the
   profiles the product claims to support.
5. **API and integration:** authentication, webhooks/workflows, external
   storage, backup hooks, and the supported client/API contract.

For workflow products, add intake, queue retry, worker isolation, normalization,
virus scanning, packaging, and audit-event tests. For frameworks such as Hyrax
or Islandora, certify the complete application composition rather than the
framework repository alone.

## Evidence requirements

Each test record must contain a stable name, `status: pass`, the exact release
and target environment, test timestamp, operator or CI job, fixture-set
identifier, and a relative evidence path. If certification executes in
staging, record that as `execution_environment` while keeping the target
environment bound to the release manifest. Evidence should include sanitized logs, counts,
checksums, and failure details without credentials or archive content.

Do not mark a product certified because a container starts or an HTTP endpoint
returns 200. Certification requires the dependency, data, authorization,
preservation, failure, and restore behavior to be demonstrated together.
