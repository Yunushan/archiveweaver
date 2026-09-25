#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
runner="${repo_root}/scripts/run-ansible-operational.sh"
temporary_root="$(mktemp -d)"
operator_inventory="${repo_root}/deploy/ansible/inventory/production/hosts.yml"
staging_inventory="${repo_root}/deploy/ansible/inventory/staging/hosts.yml"
created_operator_inventory=0
created_staging_inventory=0
if [[ ! -e "${operator_inventory}" && ! -L "${operator_inventory}" ]]; then
  cp -- "${operator_inventory}.example" "${operator_inventory}"
  created_operator_inventory=1
fi
if [[ ! -e "${staging_inventory}" && ! -L "${staging_inventory}" ]]; then
  cp -- "${staging_inventory}.example" "${staging_inventory}"
  created_staging_inventory=1
fi

cleanup() {
  rm -rf -- "${temporary_root}"
  if (( created_operator_inventory == 1 )); then
    rm -f -- "${operator_inventory}"
  fi
  if (( created_staging_inventory == 1 )); then
    rm -f -- "${staging_inventory}"
  fi
}
trap cleanup EXIT

mkdir -p "${temporary_root}/bin"
fake_ansible="${temporary_root}/bin/ansible-playbook"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' 'printf "ANSIBLE_CONFIG=%s\\n" "${ANSIBLE_CONFIG:-}"'
  printf '%s\n' 'printf "ANSIBLE_ROLES_PATH=%s\\n" "${ANSIBLE_ROLES_PATH:-}"'
  printf '%s\n' 'printf "ANSIBLE_INVENTORY=%s\\n" "${ANSIBLE_INVENTORY:-}"'
  printf '%s\n' 'printf "ANSIBLE_LIBRARY=%s\\n" "${ANSIBLE_LIBRARY:-}"'
  printf '%s\n' 'printf "ANSIBLE_FILTER_PLUGINS=%s\\n" "${ANSIBLE_FILTER_PLUGINS:-}"'
  printf '%s\n' 'printf "ANSIBLE_CONNECTION=%s\\n" "${ANSIBLE_CONNECTION:-}"'
  printf '%s\n' 'printf "PYTHONPATH=%s\\n" "${PYTHONPATH:-}"'
  printf '%s\n' 'printf "PYTHONHOME=%s\\n" "${PYTHONHOME:-}"'
  printf '%s\n' 'printf "PYTHONDONTWRITEBYTECODE=%s\\n" "${PYTHONDONTWRITEBYTECODE:-}"'
  printf '%s\n' 'printf "ARGS="'
  printf '%s\n' 'printf " <%s>" "$@"'
  printf '%s\n' 'printf "\\n"'
} > "${fake_ansible}"
chmod 0755 "${fake_ansible}"

output="$(
  ANSIBLE_CONFIG=/tmp/untrusted-ansible.cfg \
  ANSIBLE_ROLES_PATH=/tmp/untrusted-ansible-roles \
  ANSIBLE_INVENTORY=/tmp/untrusted-inventory \
  ANSIBLE_LIBRARY=/tmp/untrusted-modules \
  ANSIBLE_FILTER_PLUGINS=/tmp/untrusted-filters \
  ANSIBLE_CONNECTION=local \
  PYTHONPATH=/tmp/untrusted-python \
  PYTHONHOME=/tmp/untrusted-pythonhome \
  PYTHONDONTWRITEBYTECODE=0 \
  PATH="${temporary_root}/bin:${PATH}" \
  bash "${runner}" site.yml -i inventory/production/hosts.yml --check --diff
)"
expected_ansible_root="${repo_root}/deploy/ansible"
[[ "${output}" == *"ANSIBLE_CONFIG=${expected_ansible_root}/ansible.cfg"* ]]
[[ "${output}" == *"ANSIBLE_ROLES_PATH=${expected_ansible_root}/roles"* ]]
[[ "${output}" == *"ANSIBLE_INVENTORY="* ]]
[[ "${output}" == *"ANSIBLE_LIBRARY="* ]]
[[ "${output}" == *"ANSIBLE_FILTER_PLUGINS="* ]]
[[ "${output}" == *"ANSIBLE_CONNECTION="* ]]
[[ "${output}" == *"PYTHONPATH="* ]]
[[ "${output}" == *"PYTHONHOME="* ]]
[[ "${output}" == *"PYTHONDONTWRITEBYTECODE=1"* ]]
[[ "${output}" == *"ARGS= <-i> <inventory/production/hosts.yml> <--check> <--diff> <site.yml>"* ]]

if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" unapproved.yml >/dev/null 2>&1; then
  printf 'runner accepted an unapproved playbook\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml --step=true >/dev/null 2>&1; then
  printf 'runner accepted a task-selection override\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml --connection=local >/dev/null 2>&1; then
  printf 'runner accepted a transport override\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -k >/dev/null 2>&1; then
  printf 'runner accepted an SSH password prompt\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -K >/dev/null 2>&1; then
  printf 'runner accepted a become password prompt\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -b >/dev/null 2>&1; then
  printf 'runner accepted a become override\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml --ask-pass=true >/dev/null 2>&1; then
  printf 'runner accepted an attached SSH password prompt\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml --key-file=/tmp/untrusted-key >/dev/null 2>&1; then
  printf 'runner accepted an alternate key-file override\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml --playbook-dir /tmp >/dev/null 2>&1; then
  printf 'runner accepted an unapproved code-loading option\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -- ../unapproved.yml >/dev/null 2>&1; then
  printf 'runner accepted an extra positional playbook\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml --unapproved-option >/dev/null 2>&1; then
  printf 'runner accepted an unapproved option\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml --check >/dev/null 2>&1; then
  printf 'runner accepted an implicit inventory\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i /tmp/untrusted-inventory >/dev/null 2>&1; then
  printf 'runner accepted an unapproved inventory\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e @vars.yml >/dev/null 2>&1; then
  printf 'runner accepted an extra-vars file\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e ansible_connection=local >/dev/null 2>&1; then
  printf 'runner accepted an Ansible connection extra-var\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_unreviewed_variable=true >/dev/null 2>&1; then
  printf 'runner accepted an ArchiveWeaver key outside the exact allowlist\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_serial=20 >/dev/null 2>&1; then
  printf 'runner accepted a protected controller extra-var\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_ansible_runner_version=0.0.0 >/dev/null 2>&1; then
  printf 'runner accepted an Ansible Runner identity override\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true,untrusted_key=value >/dev/null 2>&1; then
  printf 'runner accepted a second unapproved extra-var binding\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" repair.yml -i inventory/production/hosts.yml -e archiveweaver_recovery_drill=true >/dev/null 2>&1; then
  printf 'runner accepted a recovery drill against production inventory\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/staging/hosts.yml -e archiveweaver_recovery_drill=true >/dev/null 2>&1; then
  printf 'runner accepted a recovery drill with the deployment playbook\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" repair.yml -i inventory/staging/hosts.yml -e archiveweaver_recovery_drill=false >/dev/null 2>&1; then
  printf 'runner accepted a false recovery-drill override\n' >&2
  exit 1
fi
drill_output="$(PATH="${temporary_root}/bin:${PATH}" bash "${runner}" repair.yml -i inventory/staging/hosts.yml -e archiveweaver_recovery_drill=true)"
[[ "${drill_output}" == *"ARGS= <-i> <inventory/staging/hosts.yml> <-e> <archiveweaver_recovery_drill=true> <repair.yml>"* ]]

bootstrap_digest="$(printf '%064d' 0)"
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true -e archiveweaver_bootstrap_apply=true >/dev/null 2>&1; then
  printf 'runner accepted bootstrap without an independently protected authorization digest\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/staging/hosts.yml -e archiveweaver_apply=true -e archiveweaver_bootstrap_apply=true >/dev/null 2>&1; then
  printf 'runner accepted bootstrap against staging inventory\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml --check -e archiveweaver_apply=true -e archiveweaver_bootstrap_apply=true >/dev/null 2>&1; then
  printf 'runner accepted bootstrap in check mode\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_bootstrap_apply=true >/dev/null 2>&1; then
  printf 'runner accepted bootstrap without explicit apply intent\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true -e archiveweaver_bootstrap_apply=false >/dev/null 2>&1; then
  printf 'runner accepted a false bootstrap override\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true -e archiveweaver_bootstrap_apply=true >/dev/null 2>&1; then
  printf 'runner accepted bootstrap without a protected production inventory digest\n' >&2
  exit 1
fi
bootstrap_output="$(ARCHIVEWEAVER_BOOTSTRAP_AUTHORIZATION_SHA256="${bootstrap_digest}" ARCHIVEWEAVER_PRODUCTION_INVENTORY_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true -e archiveweaver_bootstrap_apply=true)"
[[ "${bootstrap_output}" == *"ARGS= <-i> <inventory/production/hosts.yml> <-e> <archiveweaver_apply=true> <-e> <archiveweaver_bootstrap_apply=true> <site.yml>"* ]]

if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/staging/hosts.yml -e archiveweaver_apply=true -e archiveweaver_staging_seed_apply=true >/dev/null 2>&1; then
  printf 'runner accepted staging seed without independent authorization\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/staging/hosts.yml -e archiveweaver_apply=true -e archiveweaver_staging_seed_apply=true >/dev/null 2>&1; then
  printf 'runner accepted staging seed without protected inventory digest\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256="${bootstrap_digest}" ARCHIVEWEAVER_STAGING_INVENTORY_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true -e archiveweaver_staging_seed_apply=true >/dev/null 2>&1; then
  printf 'runner accepted staging seed against production inventory\n' >&2
  exit 1
fi
if ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256="${bootstrap_digest}" ARCHIVEWEAVER_STAGING_INVENTORY_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/staging/hosts.yml --check -e archiveweaver_apply=true -e archiveweaver_staging_seed_apply=true >/dev/null 2>&1; then
  printf 'runner accepted staging seed in check mode\n' >&2
  exit 1
fi
seed_output="$(ARCHIVEWEAVER_STAGING_SEED_AUTHORIZATION_SHA256="${bootstrap_digest}" ARCHIVEWEAVER_STAGING_INVENTORY_SHA256="${bootstrap_digest}" PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/staging/hosts.yml -e archiveweaver_apply=true -e archiveweaver_staging_seed_apply=true)"
[[ "${seed_output}" == *"ARGS= <-i> <inventory/staging/hosts.yml> <-e> <archiveweaver_apply=true> <-e> <archiveweaver_staging_seed_apply=true> <site.yml>"* ]]

if (( created_operator_inventory == 1 )); then
  rm -f -- "${operator_inventory}"
  if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml --check >/dev/null 2>&1; then
    printf 'runner accepted a missing approved inventory\n' >&2
    exit 1
  fi
  # Some Windows/MSYS environments emulate `ln -s` with a regular-file copy
  # when native symlink creation is unavailable. Exercise the boundary only
  # when the resulting path is actually a symlink.
  if ln -s -- "${operator_inventory}.example" "${operator_inventory}" 2>/dev/null \
    && [[ -L "${operator_inventory}" ]]; then
    if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml --check >/dev/null 2>&1; then
      printf 'runner accepted a symlinked approved inventory\n' >&2
      exit 1
    fi
  fi
fi

printf 'operational runner tests: PASS\n'
