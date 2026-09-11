#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  printf 'usage: %s <approved-playbook> --inventory <approved-inventory> [approved options]\n' "$0" >&2
  exit 64
fi

playbook="$1"
shift

case "${playbook}" in
  site.yml|verify.yml|repair.yml|product-certification.yml|restore-drill.yml|failure-drill.yml|rollback.yml)
    ;;
  *)
    printf 'operational runner rejects unapproved playbook: %s\n' "${playbook}" >&2
    exit 64
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if ! ansible_root="$(cd -- "${script_dir}/../deploy/ansible" && pwd -P)"; then
  printf 'operational runner cannot locate the reviewed Ansible bundle\n' >&2
  exit 78
fi
if [[ ! -f "${ansible_root}/ansible.cfg" || -L "${ansible_root}/ansible.cfg" || ! -d "${ansible_root}/roles" || -L "${ansible_root}/roles" ]]; then
  printf 'operational runner cannot establish the reviewed Ansible bundle\n' >&2
  exit 78
fi
extra_vars_allowlist="${ansible_root}/controller/allowed-extra-vars.txt"
if [[ ! -f "${extra_vars_allowlist}" || -L "${extra_vars_allowlist}" ]]; then
  printf 'operational runner cannot establish the reviewed extra-vars allowlist\n' >&2
  exit 78
fi

reject_option() {
  printf 'operational runner rejects task-selection, credential, transport, code-loading, or controller-boundary override: %s\n' "$1" >&2
  exit 64
}

reject_extra_vars() {
  # Do not echo the payload: an operator may accidentally place a sensitive
  # value in a rejected binding, and runner diagnostics must not disclose it.
  printf 'operational runner rejects an extra-vars source or key outside the approved binding policy\n' >&2
  exit 64
}

reject_unapproved_argument() {
  # Do not echo an unknown value: it may contain a secret or an untrusted
  # filesystem path. The runner accepts only the options enumerated below;
  # all positional arguments are rejected because the approved playbook is
  # appended by this script.
  printf 'operational runner rejects an unapproved option or positional playbook argument\n' >&2
  exit 64
}

approved_inventory_path() {
  case "$1" in
    inventory/production/hosts.yml|inventory/staging/hosts.yml|inventory/restore/hosts.yml)
      printf '%s/%s\n' "${ansible_root}" "$1"
      ;;
    "${ansible_root}/inventory/production/hosts.yml"|"${ansible_root}/inventory/staging/hosts.yml"|"${ansible_root}/inventory/restore/hosts.yml")
      printf '%s\n' "$1"
      ;;
    *)
      return 1
      ;;
  esac
}

validate_inventory() {
  local value="$1"
  local candidate
  local parent
  local physical_parent
  if ! candidate="$(approved_inventory_path "${value}")"; then
    printf 'operational runner rejects inventory outside the three approved operator inventories: %s\n' "${value}" >&2
    exit 64
  fi
  parent="$(dirname -- "${candidate}")"
  if [[ ! -f "${candidate}" || -L "${candidate}" || -L "${ansible_root}/inventory" || -L "${parent}" ]]; then
    printf 'operational runner requires an approved inventory to be a regular file without symlinked path components\n' >&2
    exit 78
  fi
  if ! physical_parent="$(cd -- "${parent}" && pwd -P)"; then
    printf 'operational runner cannot resolve the approved inventory directory\n' >&2
    exit 78
  fi
  if [[ "${physical_parent}/$(basename -- "${candidate}")" != "${candidate}" ]]; then
    printf 'operational runner rejects an inventory that escapes its approved physical directory\n' >&2
    exit 78
  fi
}

validate_extra_vars() {
  local payload="$1"
  local allowed_key
  local approved=0
  local key

  # Extra-vars files and raw YAML/JSON documents are an uncontrolled code and
  # configuration-loading boundary. Controller inputs must be explicit
  # ArchiveWeaver key=value bindings instead.
  if [[ "${payload}" == @* || "${payload}" == \{* || "${payload}" == \[* || "${payload}" != *=* || "${payload}" == *$'\n'* || "${payload}" == *$'\r'* ]]; then
    reject_extra_vars
  fi
  key="${payload%%=*}"
  if [[ ! "${key}" =~ ^archiveweaver_[A-Za-z0-9_]+$ ]]; then
    reject_extra_vars
  fi
  while IFS= read -r allowed_key || [[ -n "${allowed_key}" ]]; do
    allowed_key="${allowed_key%$'\r'}"
    if [[ -z "${allowed_key}" || "${allowed_key}" == \#* ]]; then
      continue
    fi
    if [[ "${key}" == "${allowed_key}" ]]; then
      approved=1
      break
    fi
  done < "${extra_vars_allowlist}"
  if (( approved != 1 )); then
    reject_extra_vars
  fi
  # Require one binding per -e option. Commas inside a quoted/list value are
  # fine; a bare comma-separated assignment would otherwise smuggle an
  # unrelated Ansible variable past the prefix check.
  if [[ ",${payload}" =~ ,[[:space:]]*[A-Za-z_][A-Za-z0-9_]*= ]]; then
    reject_extra_vars
  fi

  # These values are derived from the reviewed bundle or control-plane
  # binding. Allowing them as extra-vars would let a caller change the
  # controller identity, target environment, or execution parallelism.
  if [[ ",${payload}" =~ ,[[:space:]]*(archiveweaver_(serial|environment|ansible_core_version|ansible_lint_version|ansible_runner_version|bundle_root|readiness_python|readiness_pythonpath|evidence_root|evidence_dir|data_root|log_root|release_record|service_name|resource_name|namespace|health_validate_certs|controller_target_group|evidence_seal_enabled)|ansible_(connection|user|become|become_method|become_user|host|port|private_key_file|python_interpreter|ssh_common_args|ssh_extra_args|sftp_extra_args|scp_extra_args))= ]]; then
    reject_extra_vars
  fi
}

inventory_count=0
args=("$@")
for ((index = 0; index < ${#args[@]}; index++)); do
  arg="${args[index]}"
  case "${arg}" in
    --ask-vault-pass=*|--ask-pass|--ask-pass=*|-k|-k?*|--ask-become-pass=*|-K|-K?*|--become=*|-b|-b?*|--key-file|--key-file=*)
      reject_option "${arg}"
      ;;
  esac
  case "${arg}" in
    --limit|--limit=*|--tags|--tags=*|--skip-tags|--skip-tags=*|--start-at-task|--start-at-task=*|--step|--step=*|-l|-l?*|-t|-t?*|--ask-vault-pass|--vault-password-file|--vault-password-file=*|--vault-id|--vault-id=*|--ask-become-pass|--become-password-file|--become-password-file=*|--become|--become-method|--become-method=*|--become-user|--become-user=*|--private-key|--private-key=*|--user|--user=*|-u|-u?*|--connection|--connection=*|-c|-c?*|--module-path|--module-path=*|--ssh-common-args|--ssh-common-args=*|--ssh-extra-args|--ssh-extra-args=*|--sftp-extra-args|--sftp-extra-args=*|--scp-extra-args|--scp-extra-args=*|--forks|--forks=*|-f|-f?*|--timeout|--timeout=*|--inventory-file|--inventory-file=*)
      reject_option "${arg}"
      ;;
    --inventory|-i)
      inventory_count=$((inventory_count + 1))
      if (( index + 1 >= ${#args[@]} )); then
        reject_option "${arg} (missing value)"
      fi
      index=$((index + 1))
      validate_inventory "${args[index]}"
      ;;
    --inventory=*)
      inventory_count=$((inventory_count + 1))
      validate_inventory "${arg#--inventory=}"
      ;;
    -i?*)
      inventory_count=$((inventory_count + 1))
      validate_inventory "${arg#-i}"
      ;;
    --extra-vars|-e)
      if (( index + 1 >= ${#args[@]} )); then
        reject_option "${arg} (missing value)"
      fi
      index=$((index + 1))
      validate_extra_vars "${args[index]}"
      ;;
    --extra-vars=*)
      validate_extra_vars "${arg#--extra-vars=}"
      ;;
    -e?*)
      validate_extra_vars "${arg#-e}"
      ;;
    --check|-C|--diff|-D|--syntax-check)
      ;;
    *)
      reject_unapproved_argument
      ;;
  esac
done

if (( inventory_count != 1 )); then
  printf 'operational runner requires exactly one approved operator inventory (-i/--inventory)\n' >&2
  exit 64
fi

cd -- "${ansible_root}"

# Do not allow ambient controller settings to redirect the reviewed config,
# role tree, plugin/module search path, transport, credentials, or Python
# import path. Credentials remain controller-bound; these values must arrive
# through the approved controller credential and inventory/Vault bindings.
clear_ambient_overrides() {
  local variable
  for variable in \
    ANSIBLE_CONFIG \
    ANSIBLE_INVENTORY \
    ANSIBLE_LIBRARY \
    ANSIBLE_MODULE_PATH \
    ANSIBLE_MODULE_UTILS \
    ANSIBLE_COLLECTIONS_PATH \
    ANSIBLE_COLLECTIONS_PATHS \
    ANSIBLE_ROLES_PATH \
    ANSIBLE_INVENTORY_ENABLED \
    ANSIBLE_ACTION_PLUGINS \
    ANSIBLE_CACHE_PLUGINS \
    ANSIBLE_CALLBACK_PLUGINS \
    ANSIBLE_CONNECTION_PLUGINS \
    ANSIBLE_FILTER_PLUGINS \
    ANSIBLE_HTTPAPI_PLUGINS \
    ANSIBLE_LOOKUP_PLUGINS \
    ANSIBLE_NETCONF_PLUGIN_PATH \
    ANSIBLE_STRATEGY_PLUGINS \
    ANSIBLE_TERMINAL_PLUGIN_PATH \
    ANSIBLE_TEST_PLUGINS \
    ANSIBLE_VARS_PLUGINS \
    ANSIBLE_VAULT_PASSWORD_FILE \
    ANSIBLE_VAULT_IDENTITY_LIST \
    ANSIBLE_PRIVATE_KEY_FILE \
    ANSIBLE_REMOTE_USER \
    ANSIBLE_USER \
    ANSIBLE_PASSWORD \
    ANSIBLE_CONNECTION \
    ANSIBLE_BECOME \
    ANSIBLE_BECOME_METHOD \
    ANSIBLE_BECOME_USER \
    ANSIBLE_BECOME_PASSWORD \
    ANSIBLE_BECOME_EXE \
    ANSIBLE_EXECUTABLE \
    ANSIBLE_PYTHON_INTERPRETER \
    ANSIBLE_PORT \
    ANSIBLE_SSH_COMMON_ARGS \
    ANSIBLE_SSH_EXTRA_ARGS \
    ANSIBLE_SFTP_EXTRA_ARGS \
    ANSIBLE_SCP_EXTRA_ARGS \
    ANSIBLE_FORKS \
    ANSIBLE_TIMEOUT \
    ANSIBLE_HOST_KEY_CHECKING \
    ANSIBLE_REMOTE_TMP \
    ANSIBLE_LOCAL_TMP \
    ANSIBLE_PIPELINING \
    ANSIBLE_SSH_PIPELINING \
    ANSIBLE_STDOUT_CALLBACK \
    ANSIBLE_STRATEGY \
    ANSIBLE_JINJA2_EXTENSIONS \
    PYTHONPATH \
    PYTHONHOME; do
    unset "${variable}"
  done
}

clear_ambient_overrides
export ANSIBLE_CONFIG="${ansible_root}/ansible.cfg"
export ANSIBLE_ROLES_PATH="${ansible_root}/roles"

exec ansible-playbook "$@" "${playbook}"
