## Purpose

Describe the operational problem and the intended behavior. Link the issue or
change record when one exists.

## Verification

- [ ] `make test` passes on Linux or the equivalent CI jobs are green.
- [ ] `make quality` passes.
- [ ] Generated catalog and reference files have been regenerated and checked for drift.
- [ ] New behavior has positive, negative, and fail-closed tests where applicable.
- [ ] Deployment, recovery, security, and operator documentation is updated where applicable.
- [ ] No credentials, private data, mutable production image tags, or fabricated readiness evidence is included.
- [ ] Trust-boundary changes identify their threat model and rollback path.

## Production impact

State the affected runtimes, upgrade or rollback implications, and whether a
real environment certification or drill must be repeated before promotion.
