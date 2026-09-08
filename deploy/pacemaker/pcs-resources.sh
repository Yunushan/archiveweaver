#!/usr/bin/env bash
set -euo pipefail

# Plan-only by default. This example intentionally refuses to guess a fence
# agent, shared filesystem, VIP, or application unit.
apply=0
for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    --plan) apply=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

cat <<'PLAN'
Pacemaker resource review plan:
  1. pcs status --full
  2. pcs quorum status
  3. pcs stonith status
  4. pcs constraint config
  5. define and test a STONITH device for each node
  6. define shared/replicated storage and mount resources
  7. define a VIP resource
  8. define the application or Quadlet systemd resource
  9. add ordering/colocation/monitor operations
 10. test failure and fencing before accepting traffic

No resources are created by this template.
PLAN

if ((apply == 1)); then
  echo "Refusing to create environment-specific Pacemaker resources from placeholders." >&2
  echo "Copy the reviewed commands into a change-controlled runbook after selecting a real fence agent and storage design." >&2
  exit 3
fi

