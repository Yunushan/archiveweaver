# Operating-system matrix

The matrix describes the ArchiveWeaver host baseline. It does not override product-specific support policies. Always test the exact application release, dependency versions, kernel, SELinux/AppArmor policy, storage driver, and CPU architecture.

| Operating system | Family | ArchiveWeaver baseline |
| --- | --- | --- |
| Ubuntu 22.04 LTS | debian | validated-base |
| Ubuntu 24.04 LTS | debian | preferred |
| Ubuntu 26.04 LTS | debian | forward-validate |
| Rocky Linux 8 | el | legacy-conditional |
| Rocky Linux 9 | el | preferred |
| Rocky Linux 10 | el | forward-validate |
| Red Hat Enterprise Linux 8 | el | legacy-conditional |
| Red Hat Enterprise Linux 9 | el | validated-base |
| Red Hat Enterprise Linux 10 | el | forward-validate |
| AlmaLinux 8 | el | legacy-conditional |
| AlmaLinux 9 | el | validated-base |
| AlmaLinux 10 | el | forward-validate |
| Debian 12 | debian | validated-base |
| Debian 13 | debian | validated-base |

## Tiers

- **preferred:** default target for new production automation.
- **validated-base:** supported host baseline; application release validation is still required.
- **forward-validate:** included for early validation and future-proofing; do not silently promote to production without a release test.
- **legacy-conditional:** usable when a pinned product requires it, but avoid introducing new workloads.
