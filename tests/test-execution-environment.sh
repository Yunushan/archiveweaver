#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
builder="${repo_root}/scripts/build-ansible-execution-environment.sh"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

mkdir -p "${temporary_root}/bin"
fake_engine="${temporary_root}/bin/podman"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' 'printf "ENGINE=%s\\n" "${0##*/}"'
  printf '%s\n' 'printf "ARGS="'
  printf '%s\n' 'printf " <%s>" "$@"'
  printf '%s\n' 'printf "\\n"'
} > "${fake_engine}"
chmod 0755 "${fake_engine}"

base_image="registry.example.org/approved-ansible-ee@sha256:$(printf '%064d' 0)"
output="$(PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --engine podman)"

expected_context="${repo_root}/deploy/ansible/execution-environment"
[[ "${output}" == *"ENGINE=podman"* ]]
[[ "${output}" == *"<build>"* ]]
[[ "${output}" == *"<--file> <${expected_context}/Containerfile>"* ]]
[[ "${output}" == *"<--build-arg> <BASE_IMAGE=${base_image}>"* ]]
[[ "${output}" == *"<--tag> <registry.example.org/archiveweaver-ee:2026.09.10>"* ]]
[[ "${output}" == *"<${expected_context}>"* ]]

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image registry.example.org/approved-ansible-ee:latest \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a tag-only base image\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image registry.example.org/approved-ansible-ee@sha256:not-a-digest \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a malformed digest\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:latest \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a latest output tag\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --engine nerdctl >/dev/null 2>&1; then
  printf 'execution-environment builder accepted an unapproved engine\n' >&2
  exit 1
fi

printf 'execution-environment builder tests: PASS\n'
