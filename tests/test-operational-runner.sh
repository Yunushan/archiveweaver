#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
runner="${repo_root}/scripts/run-ansible-operational.sh"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

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
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_serial=20 >/dev/null 2>&1; then
  printf 'runner accepted a protected controller extra-var\n' >&2
  exit 1
fi
if PATH="${temporary_root}/bin:${PATH}" bash "${runner}" site.yml -i inventory/production/hosts.yml -e archiveweaver_apply=true,untrusted_key=value >/dev/null 2>&1; then
  printf 'runner accepted a second unapproved extra-var binding\n' >&2
  exit 1
fi

printf 'operational runner tests: PASS\n'
