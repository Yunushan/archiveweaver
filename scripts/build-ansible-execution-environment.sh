#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-ansible-execution-environment.sh \
  --base-image <registry/repository@sha256:64-hex-digest> \
  --tag <local-image:release> [--engine podman|docker]
EOF
}

fail() {
  printf 'execution-environment build rejected: %s\n' "$1" >&2
  exit 64
}

base_image=""
image_tag=""
engine="podman"

while (( $# > 0 )); do
  case "$1" in
    --base-image)
      (( $# >= 2 )) || fail "--base-image requires a value"
      base_image="$2"
      shift 2
      ;;
    --tag)
      (( $# >= 2 )) || fail "--tag requires a value"
      image_tag="$2"
      shift 2
      ;;
    --engine)
      (( $# >= 2 )) || fail "--engine requires podman or docker"
      engine="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      fail "unknown option: $1"
      ;;
  esac
done

[[ -n "$base_image" ]] || fail "--base-image is required"
[[ -n "$image_tag" ]] || fail "--tag is required"
[[ "$engine" == "podman" || "$engine" == "docker" ]] || fail "--engine must be podman or docker"

# Validate before invoking the engine. A Containerfile RUN check is useful as
# defense in depth, but a builder has already resolved FROM by that point.
if [[ ! "$base_image" =~ ^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[0-9a-f]{64}$ ]]; then
  fail "--base-image must be an OCI reference with a 64-character SHA-256 digest"
fi

# The tag is only a local build label; the release manifest must record the
# immutable RepoDigest after the image is built. Never create an ambiguous
# latest tag or pass an image digest as a tag value.
if [[ ! "$image_tag" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*$ || "$image_tag" == *"@"* ]]; then
  fail "--tag must be a registry/repository:release reference"
fi
tag_name="${image_tag##*:}"
if [[ "${tag_name,,}" == "latest" || "$tag_name" == *REPLACE_WITH* || "$tag_name" == *replace_with* ]]; then
  fail "--tag must not be latest or a placeholder"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
context_root="${repo_root}/deploy/ansible/execution-environment"
containerfile="${context_root}/Containerfile"
requirements_lock="${context_root}/requirements.txt"

for required_file in "$containerfile" "$requirements_lock"; do
  [[ -f "$required_file" && ! -L "$required_file" ]] || fail "required build input is missing or symlinked: $required_file"
done

command -v "$engine" >/dev/null 2>&1 || fail "container engine is not available: $engine"

exec "$engine" build \
  --file "$containerfile" \
  --build-arg "BASE_IMAGE=$base_image" \
  --tag "$image_tag" \
  "$context_root"
