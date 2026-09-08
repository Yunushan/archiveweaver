#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
export PYTHONPATH="${repo_root}/src${PYTHONPATH:+:${PYTHONPATH}}"

solution=""
mode=""
nodes="1"
os_id="ubuntu-24.04"
plan_only=1
allow_conditional=0
while (($#)); do
  case "$1" in
    --solution) solution="${2:?missing solution id}"; shift 2 ;;
    --mode) mode="${2:?missing mode}"; shift 2 ;;
    --nodes) nodes="${2:?missing node count}"; shift 2 ;;
    --os) os_id="${2:?missing OS id}"; shift 2 ;;
    --plan-only) plan_only=1; shift ;;
    --allow-conditional) allow_conditional=1; shift ;;
    --apply) plan_only=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${solution}" || -z "${mode}" ]]; then
  echo "usage: $0 --solution ID --mode MODE [--nodes 1|2|3|3+] [--os OS_ID] [--plan-only]" >&2
  exit 2
fi

args=(plan --solution "${solution}" --mode "${mode}" --nodes "${nodes}" --os "${os_id}")
if ((allow_conditional)); then
  args+=(--allow-conditional)
fi
python3 -m archiveweaver "${args[@]}"

if ((plan_only == 1)); then
  echo
  echo "Plan-only mode complete. No application, database, volume, firewall, or cluster state was changed."
  exit 0
fi

echo "No universal product installer is executed by this command." >&2
echo "Use the generated plan and the product-specific upstream recipe after staging validation." >&2
exit 3

