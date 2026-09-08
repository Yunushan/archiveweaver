#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
ansible_root="${repo_root}/deploy/ansible"

cd "${ansible_root}"
ansible-galaxy collection install -r requirements.yml
ansible-lint --offline site.yml verify.yml repair.yml product-certification.yml restore-drill.yml failure-drill.yml rollback.yml

ansible-playbook -i inventory/production/hosts.yml.example site.yml --syntax-check
ansible-playbook -i inventory/production/hosts.yml.example verify.yml --syntax-check
ansible-playbook -i inventory/production/hosts.yml.example repair.yml --syntax-check
ansible-playbook -i inventory/staging/hosts.yml.example product-certification.yml --syntax-check
ansible-playbook -i inventory/restore/hosts.yml.example restore-drill.yml --syntax-check
ansible-playbook -i inventory/staging/hosts.yml.example failure-drill.yml --syntax-check
ansible-playbook -i inventory/production/hosts.yml.example rollback.yml --syntax-check

echo "Ansible lint and syntax validation: PASS"
