# Pacemaker / Corosync + STONITH

Pacemaker is supported as an active/passive infrastructure pattern. It is not a substitute for product-native clustering, a distributed database, or shared storage.

## Safety requirements

- tested fencing device per node;
- quorum policy and, for two-node designs, a qdevice/witness or an explicitly reviewed two-node policy;
- redundant Corosync links where practical;
- deterministic node names and time synchronization;
- resource ordering, colocation, monitor intervals, and failure timeouts;
- a maintenance/runbook procedure that places resources in standby before planned work.

The template under `deploy/pacemaker/` is plan-oriented and requires environment-specific values. It does not disable fencing.

## Example review sequence

```bash
pcs status --full
pcs quorum status
pcs stonith status
pcs constraint config
pcs resource config
```

Only after the above is understood should a resource cleanup or failover action be considered. Use `archiveweaver repair --mode pacemaker --allow-fencing-actions` to make that review visible in the evidence bundle.

