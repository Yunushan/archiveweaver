# STONITH checklist

- [ ] Every cluster node can be fenced by an independent management plane.
- [ ] The fence agent and version are supported by the target OS and hardware.
- [ ] Credentials are stored outside Git and are least-privilege.
- [ ] Fencing one node cannot fence the surviving node accidentally.
- [ ] Fence operations were tested during a maintenance window.
- [ ] Quorum/qdevice/witness behavior is documented.
- [ ] Shared or replicated storage behavior during a partition is documented.
- [ ] The application cannot run on both sides of a network partition.
- [ ] Recovery of a fenced node includes stale-data and fixity checks.
- [ ] The change ticket includes observed fencing time and RTO.

