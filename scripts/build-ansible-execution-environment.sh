#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-ansible-execution-environment.sh \
  --base-image <registry/repository@sha256:64-hex-digest> \
  --tag <local-image:release> \
  --source-revision <full-commit-sha> [--engine podman|docker]
EOF
}

fail() {
  printf 'execution-environment build rejected: %s\n' "$1" >&2
  exit 64
}

base_image=""
image_tag=""
source_revision=""
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
    --source-revision)
      (( $# >= 2 )) || fail "--source-revision requires a value"
      source_revision="$2"
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
[[ -n "$source_revision" ]] || fail "--source-revision is required"
[[ "$engine" == "podman" || "$engine" == "docker" ]] || fail "--engine must be podman or docker"

# Validate before invoking the engine. A Containerfile RUN check is useful as
# defense in depth, but a builder has already resolved FROM by that point.
if [[ ! "$base_image" =~ ^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*)+@sha256:[0-9a-f]{64}$ ]]; then
  fail "--base-image must be a fully qualified lowercase OCI repository with a 64-character SHA-256 digest"
fi

# The tag is only a local build label; the release manifest must record the
# immutable RepoDigest after the image is built. Never create an ambiguous
# latest tag or pass an image digest as a tag value.
if [[ ! "$image_tag" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*$ || "$image_tag" == *"@"* ]]; then
  fail "--tag must be a registry/repository:release reference"
fi
tag_name="${image_tag##*:}"
tag_name_lower="${tag_name,,}"
if [[ "$tag_name_lower" == "latest" || "$tag_name_lower" == *replace_with* ]]; then
  fail "--tag must not be latest or a placeholder"
fi
if [[ ! "$source_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  fail "--source-revision must be a full lowercase 40- or 64-character commit SHA"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
context_root="${repo_root}/deploy/ansible/execution-environment"
containerfile="${context_root}/Containerfile"
requirements_lock="${context_root}/requirements.txt"

for required_file in "$containerfile" "$requirements_lock"; do
  [[ -f "$required_file" && ! -L "$required_file" ]] || fail "required build input is missing or symlinked: $required_file"
done

locked_version() {
  local package_name="$1"
  local version
  version="$(sed -n "s/^${package_name}==\\([^[:space:]\\\\]*\\)[[:space:]]*\\\\$/\\1/p" "$requirements_lock")"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(\.post[0-9]+)?$ ]] || fail "could not derive one exact ${package_name} version from the controller lock"
  printf '%s\n' "$version"
}

ansible_core_version="$(locked_version ansible-core)"
ansible_lint_version="$(locked_version ansible-lint)"
ansible_runner_version="$(locked_version ansible-runner)"
dumb_init_version="$(locked_version dumb-init)"

command -v "$engine" >/dev/null 2>&1 || fail "container engine is not available: $engine"

"$engine" build \
  --file "$containerfile" \
  --build-arg "BASE_IMAGE=$base_image" \
  --build-arg "RELEASE_VERSION=$tag_name" \
  --build-arg "SOURCE_REVISION=$source_revision" \
  --tag "$image_tag" \
  "$context_root"

# A successful image build is not controller proof. Exercise the exact image
# as an unprivileged numeric UID, verify the locked Python packages, require
# every local tool used by the source-integrity and transport boundaries, and
# run an Ansible localhost smoke test before reporting the image as usable.
"$engine" run --rm \
  --user 65532:65532 \
  --env HOME=/tmp \
  --env USER=archiveweaver \
  --env LOGNAME=archiveweaver \
  --entrypoint python3 \
  "$image_tag" \
  -c 'from importlib.metadata import version; import platform,sys; expected=dict(item.split("=",1) for item in sys.argv[1:]); actual={"ansible-core":version("ansible-core"),"ansible-lint":version("ansible-lint"),"ansible-runner":version("ansible-runner"),"dumb-init":version("dumb-init")}; errors=[f"{name}: expected {wanted}, got {actual.get(name)!r}" for name,wanted in expected.items() if actual.get(name) != wanted]; errors += [] if sys.version_info[:2] in ((3,13),(3,14)) and platform.system() == "Linux" and platform.machine() == "x86_64" else ["unsupported Python/platform"]; raise SystemExit("; ".join(errors) if errors else 0)' \
  "ansible-core=$ansible_core_version" \
  "ansible-lint=$ansible_lint_version" \
  "ansible-runner=$ansible_runner_version" \
  "dumb-init=$dumb_init_version"

"$engine" run --rm \
  --user 65532:65532 \
  --env HOME=/tmp \
  --env USER=archiveweaver \
  --env LOGNAME=archiveweaver \
  --entrypoint /bin/sh \
  "$image_tag" \
  -ec 'for required in bash git gpg ssh sed head tr grep python3 ansible ansible-playbook ansible-lint ansible-runner dumb-init; do command -v "$required" >/dev/null || { echo "missing required controller command: $required" >&2; exit 1; }; done; ansible-playbook --version >/dev/null; ansible-lint --version >/dev/null; ansible-runner --version >/dev/null; dumb-init --version >/dev/null; ansible localhost --connection local --inventory localhost, --module-name ping >/dev/null'

# Exercise the image's actual ENTRYPOINT, CMD override behavior, default numeric
# identity, passwd/group records, HOME, and working directory. The earlier
# checks deliberately override these settings to isolate package/tool failures.
"$engine" run --rm \
  "$image_tag" \
  python3 -c 'import grp,os,pwd; user=pwd.getpwuid(os.getuid()); group=grp.getgrgid(os.getgid()); errors=[]; errors += [] if (os.getuid(),os.getgid()) == (65532,65532) else ["unexpected runtime uid/gid"]; errors += [] if user.pw_name == "archiveweaver" and user.pw_dir == "/runner" else ["invalid passwd identity"]; errors += [] if group.gr_name == "archiveweaver" else ["invalid group identity"]; errors += [] if os.environ.get("HOME") == "/runner" and os.environ.get("USER") == "archiveweaver" and os.environ.get("LOGNAME") == "archiveweaver" and os.getcwd() == "/runner" else ["invalid runtime environment"]; raise SystemExit("; ".join(errors) if errors else 0)'

inspect_label() {
  local label_name="$1"
  if [[ "$engine" == "podman" ]]; then
    "$engine" image inspect \
      --format "{{ index .Labels \"${label_name}\" }}" \
      "$image_tag"
  else
    "$engine" image inspect \
      --format "{{ index .Config.Labels \"${label_name}\" }}" \
      "$image_tag"
  fi
}

raw_image_id="$("$engine" image inspect --format '{{.Id}}' "$image_tag")"
if [[ "$raw_image_id" =~ ^[0-9a-f]{64}$ ]]; then
  # Podman returns a bare 64-character ID; Docker prefixes the same value.
  image_id="sha256:${raw_image_id}"
elif [[ "$raw_image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  image_id="$raw_image_id"
else
  fail "built image did not expose an immutable local SHA-256 image ID"
fi

if [[ "$engine" == "podman" ]]; then
  default_user="$("$engine" image inspect --format '{{.User}}' "$image_tag")"
else
  default_user="$("$engine" image inspect --format '{{.Config.User}}' "$image_tag")"
fi
[[ "$default_user" == "65532:65532" ]] || fail "built image default user must be 65532:65532"
[[ "$(inspect_label org.opencontainers.image.revision)" == "$source_revision" ]] || fail "built image source-revision label does not match the requested commit"
[[ "$(inspect_label org.opencontainers.image.version)" == "$tag_name" ]] || fail "built image version label does not match the requested release"
[[ "$(inspect_label org.opencontainers.image.base.name)" == "$base_image" ]] || fail "built image base-image label does not match the approved digest"
[[ "$(inspect_label ansible-execution-environment)" == "true" ]] || fail "built image is missing the Ansible execution-environment marker"

printf 'execution-environment validated: tag=%s image_id=%s source_revision=%s\n' \
  "$image_tag" "$image_id" "$source_revision"
