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
  printf '%s\n' 'case "${1:-}" in'
  printf '%s\n' '  build)'
  printf '%s\n' '    [[ "${FAKE_BUILD_FAIL:-false}" != true ]] || exit 7'
  printf '%s\n' '    printf "ENGINE=%s\\nARGS=" "${0##*/}"'
  printf '%s\n' '    printf " <%s>" "$@"'
  printf '%s\n' '    printf "\\n"'
  printf '%s\n' '    ;;'
  printf '%s\n' '  run)'
  printf '%s\n' '    [[ "${FAKE_RUN_FAIL:-false}" != true ]] || exit 8'
  printf '%s\n' '    printf "ENGINE_RUN=%s\\nRUN_ARGS=" "${0##*/}"'
  printf '%s\n' '    printf " <%s>" "$@"'
  printf '%s\n' '    printf "\\n"'
  printf '%s\n' '    ;;'
  printf '%s\n' '  image)'
  printf '%s\n' '    [[ "${2:-}" == inspect && "${3:-}" == --format ]] || exit 9'
  printf '%s\n' '    case "${4:-}" in'
  printf '%s\n' '      *".Id"*) if [[ -n "${FAKE_IMAGE_ID:-}" ]]; then printf "%s\\n" "${FAKE_IMAGE_ID}"; elif [[ "${0##*/}" == podman ]]; then printf "%064d\\n" 0; else printf "sha256:%064d\\n" 0; fi ;;'
  printf '%s\n' '      *".User"*) printf "%s\\n" "${FAKE_DEFAULT_USER:-65532:65532}" ;;'
  printf '%s\n' '      *"image.revision"*) printf "%s\\n" "${FAKE_SOURCE_REVISION:?}" ;;'
  printf '%s\n' '      *"image.version"*) printf "%s\\n" "${FAKE_RELEASE_VERSION:?}" ;;'
  printf '%s\n' '      *"image.base.name"*) printf "%s\\n" "${FAKE_BASE_IMAGE:?}" ;;'
  printf '%s\n' '      *"ansible-execution-environment"*) printf "%s\\n" "${FAKE_EE_MARKER:-true}" ;;'
  printf '%s\n' '      *) exit 10 ;;'
  printf '%s\n' '    esac'
  printf '%s\n' '    ;;'
  printf '%s\n' '  *) exit 11 ;;'
  printf '%s\n' 'esac'
} > "${fake_engine}"
chmod 0755 "${fake_engine}"
cp "${fake_engine}" "${temporary_root}/bin/docker"

base_image="registry.example.org/approved-ansible-ee@sha256:$(printf '%064d' 0)"
source_revision="$(printf '1%.0s' {1..40})"
release_version="2026.09.10"
output="$(FAKE_BASE_IMAGE="$base_image" \
  FAKE_SOURCE_REVISION="$source_revision" \
  FAKE_RELEASE_VERSION="$release_version" \
  PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag "registry.example.org/archiveweaver-ee:${release_version}" \
  --source-revision "${source_revision}" \
  --engine podman)"

expected_context="${repo_root}/deploy/ansible/execution-environment"
[[ "${output}" == *"ENGINE=podman"* ]]
[[ "${output}" == *"<build>"* ]]
[[ "${output}" == *"<--file> <${expected_context}/Containerfile>"* ]]
[[ "${output}" == *"<--build-arg> <BASE_IMAGE=${base_image}>"* ]]
[[ "${output}" == *"<--build-arg> <RELEASE_VERSION=${release_version}>"* ]]
[[ "${output}" == *"<--build-arg> <SOURCE_REVISION=${source_revision}>"* ]]
[[ "${output}" == *"<--tag> <registry.example.org/archiveweaver-ee:${release_version}>"* ]]
[[ "${output}" == *"<${expected_context}>"* ]]
[[ "${output}" == *"ENGINE_RUN=podman"* ]]
[[ "${output}" == *"<--user> <65532:65532>"* ]]
[[ "${output}" == *"<ansible-core=2.21.4>"* ]]
[[ "${output}" == *"<ansible-lint=26.8.0>"* ]]
[[ "${output}" == *"<ansible-runner=2.4.3>"* ]]
[[ "${output}" == *"<dumb-init=1.2.5.post1>"* ]]
[[ "${output}" == *"execution-environment validated:"* ]]
[[ "${output}" == *"image_id=sha256:$(printf '%064d' 0)"* ]]
[[ "${output}" == *"source_revision=${source_revision}"* ]]

docker_output="$(FAKE_BASE_IMAGE="$base_image" \
  FAKE_SOURCE_REVISION="$source_revision" \
  FAKE_RELEASE_VERSION="$release_version" \
  PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag "registry.example.org/archiveweaver-ee:${release_version}" \
  --source-revision "${source_revision}" \
  --engine docker)"
[[ "${docker_output}" == *"ENGINE=docker"* ]]
[[ "${docker_output}" == *"image_id=sha256:$(printf '%064d' 0)"* ]]

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image registry.example.org/approved-ansible-ee:latest \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a tag-only base image\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:RePlAcE_WiTh_release \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a mixed-case placeholder tag\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image registry.example.org/approved-ansible-ee@sha256:not-a-digest \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a malformed digest\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "registry.example.org/approved-ansible-ee:tag@${base_image##*@}" \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted an ambiguous tag-plus-digest base\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:latest \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a latest output tag\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --source-revision "${source_revision}" \
  --engine nerdctl >/dev/null 2>&1; then
  printf 'execution-environment builder accepted an unapproved engine\n' >&2
  exit 1
fi

if PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag registry.example.org/archiveweaver-ee:2026.09.10 \
  --source-revision abc123 \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted an abbreviated source revision\n' >&2
  exit 1
fi

if FAKE_BASE_IMAGE="$base_image" \
  FAKE_SOURCE_REVISION="$source_revision" \
  FAKE_RELEASE_VERSION="$release_version" \
  FAKE_RUN_FAIL=true \
  PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag "registry.example.org/archiveweaver-ee:${release_version}" \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted an image that failed runtime validation\n' >&2
  exit 1
fi

if FAKE_BASE_IMAGE="$base_image" \
  FAKE_SOURCE_REVISION="$source_revision" \
  FAKE_RELEASE_VERSION="$release_version" \
  FAKE_DEFAULT_USER=root \
  PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag "registry.example.org/archiveweaver-ee:${release_version}" \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a root-default image\n' >&2
  exit 1
fi

if FAKE_BASE_IMAGE="$base_image" \
  FAKE_SOURCE_REVISION="$(printf '2%.0s' {1..40})" \
  FAKE_RELEASE_VERSION="$release_version" \
  PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag "registry.example.org/archiveweaver-ee:${release_version}" \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a mismatched source-revision label\n' >&2
  exit 1
fi

if FAKE_BASE_IMAGE="$base_image" \
  FAKE_SOURCE_REVISION="$source_revision" \
  FAKE_RELEASE_VERSION="$release_version" \
  FAKE_EE_MARKER=false \
  PATH="${temporary_root}/bin:${PATH}" bash "${builder}" \
  --base-image "${base_image}" \
  --tag "registry.example.org/archiveweaver-ee:${release_version}" \
  --source-revision "${source_revision}" \
  --engine podman >/dev/null 2>&1; then
  printf 'execution-environment builder accepted a missing EE marker\n' >&2
  exit 1
fi

printf 'execution-environment builder tests: PASS\n'
