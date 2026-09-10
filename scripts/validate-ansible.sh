#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
ansible_root="${repo_root}/deploy/ansible"

cd "${ansible_root}"
python3 "${repo_root}/scripts/validate-controller-contract.py"
if ! cmp -s requirements.txt execution-environment/requirements.txt; then
  echo "Ansible controller and execution-environment requirement locks differ" >&2
  exit 1
fi
ansible-galaxy collection install -r requirements.yml
ansible-lint --offline site.yml verify.yml repair.yml product-certification.yml restore-drill.yml failure-drill.yml rollback.yml

validation_inventory_dir="$(mktemp -d)"
trap 'rm -rf -- "${validation_inventory_dir}"' EXIT
mkdir -p "${validation_inventory_dir}/production" "${validation_inventory_dir}/staging" "${validation_inventory_dir}/restore"
cp inventory/production/hosts.yml.example "${validation_inventory_dir}/production/hosts.yml"
cp inventory/staging/hosts.yml.example "${validation_inventory_dir}/staging/hosts.yml"
cp inventory/restore/hosts.yml.example "${validation_inventory_dir}/restore/hosts.yml"

ansible-playbook -i "${validation_inventory_dir}/production/hosts.yml" site.yml --syntax-check
ansible-playbook -i "${validation_inventory_dir}/production/hosts.yml" verify.yml --syntax-check
ansible-playbook -i "${validation_inventory_dir}/production/hosts.yml" repair.yml --syntax-check
ansible-playbook -i "${validation_inventory_dir}/staging/hosts.yml" product-certification.yml --syntax-check
ansible-playbook -i "${validation_inventory_dir}/restore/hosts.yml" restore-drill.yml --syntax-check
ansible-playbook -i "${validation_inventory_dir}/staging/hosts.yml" failure-drill.yml --syntax-check
ansible-playbook -i "${validation_inventory_dir}/production/hosts.yml" rollback.yml --syntax-check

echo "Ansible lint and syntax validation: PASS"
