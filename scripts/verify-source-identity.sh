#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: verify-source-identity.sh <full-commit-sha> [repository]" >&2
  exit 2
fi

immutable_ref="$1"
repository="${2:-.}"

if [[ ! "$immutable_ref" =~ ^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$ ]]; then
  echo "source identity must be a full 40- or 64-character commit SHA" >&2
  exit 2
fi

if ! git -C "$repository" rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "repository is not a Git worktree: $repository" >&2
  exit 2
fi

cd -P -- "$repository"
expected_commit="$(git rev-parse --verify "${immutable_ref}^{commit}")"
actual_commit="$(git rev-parse HEAD)"

if [[ "${expected_commit,,}" != "${immutable_ref,,}" ]]; then
  echo "requested source reference is not the resolved commit: $immutable_ref" >&2
  exit 1
fi

if [[ "${actual_commit,,}" != "${expected_commit,,}" ]]; then
  echo "checked-out commit does not match the approved source reference" >&2
  exit 1
fi

if ! git diff --quiet HEAD -- || ! git diff --cached --quiet; then
  echo "tracked worktree changes are not permitted for a production source checkout" >&2
  exit 1
fi

is_allowed_operator_path() {
  case "$1" in
    deploy/ansible/inventory/production/hosts.yml \
      |deploy/ansible/inventory/staging/hosts.yml \
      |deploy/ansible/inventory/restore/hosts.yml \
      |deploy/ansible/group_vars/all/vault.yml \
      |deploy/ansible/release-manifest.json \
      |deploy/ansible/release-manifest-staging.json \
      |deploy/ansible/release-manifest-restore.json \
      |deploy/ansible/evidence/*)
      return 0
      ;;
  esac
  return 1
}

operator_path_is_safe() {
  local operator_path="$1"
  [[ "$operator_path" != *$'\n'* && "$operator_path" != *$'\r'* ]] || return 1
  [[ -f "$operator_path" && ! -L "$operator_path" ]] || return 1

  local current="$PWD"
  local part
  local -a path_parts
  IFS='/' read -r -a path_parts <<< "$operator_path"
  for part in "${path_parts[@]}"; do
    [[ -n "$part" ]] || continue
    current="$current/$part"
    [[ ! -L "$current" ]] || return 1
  done
  return 0
}

# The operator manifest, inventory, encrypted Vault, and evidence bundle are
# intentionally ignored by Git. Reject every other non-ignored untracked path.
while IFS= read -r -d '' untracked_path; do
  echo "untracked path is not an approved operator input: $untracked_path" >&2
  exit 1
done < <(GIT_OPTIONAL_LOCKS=0 git ls-files --others --exclude-standard -z)

# Permit only the explicitly documented ignored operator inputs. This keeps
# ignored controller code, generated playbooks, and tooling caches outside the
# production trust boundary.
while IFS= read -r -d '' ignored_path; do
  if ! is_allowed_operator_path "$ignored_path"; then
    echo "ignored untracked path is not an approved operator input: $ignored_path" >&2
    exit 1
  fi
  if ! operator_path_is_safe "$ignored_path"; then
    echo "ignored operator input must be a regular file without symlinked path components: $ignored_path" >&2
    exit 1
  fi
done < <(GIT_OPTIONAL_LOCKS=0 git ls-files --others --ignored --exclude-standard -z)

verification_output=""
if ! verification_output=$(git verify-commit --raw "$expected_commit" 2>&1); then
  echo "approved source commit has no valid Git signature" >&2
  exit 1
fi

trusted_signers=$(printenv ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS 2>/dev/null || true)
if [[ ! "$trusted_signers" =~ ^(([0-9a-fA-F]{40}|[0-9a-fA-F]{64})([,[:space:]]+([0-9a-fA-F]{40}|[0-9a-fA-F]{64}))*)$ ]]; then
  echo "ARCHIVEWEAVER_TRUSTED_SIGNER_FINGERPRINTS must contain one or more full trusted signer fingerprints" >&2
  exit 2
fi

signer_fingerprint=$(printf '%s\n' "$verification_output" | sed -n 's/^\[GNUPG:\] VALIDSIG \([^ ]*\).*$/\1/p' | head -n 1)
if [[ -z "$signer_fingerprint" ]]; then
  echo "approved source commit signature did not expose a valid signer fingerprint" >&2
  exit 1
fi

trusted_signers=$(printf '%s\n' "$trusted_signers" | tr ',' ' ')
signer_matches=false
for trusted_signer in $trusted_signers; do
  trusted_signer_upper=$(printf '%s' "$trusted_signer" | tr '[:lower:]' '[:upper:]')
  signer_fingerprint_upper=$(printf '%s' "$signer_fingerprint" | tr '[:lower:]' '[:upper:]')
  if [[ "$trusted_signer_upper" == "$signer_fingerprint_upper" ]]; then
    signer_matches=true
    break
  fi
done
if [[ "$signer_matches" != true ]]; then
  echo "approved source commit was signed by an untrusted signer" >&2
  exit 1
fi

printf 'source identity verified: %s\n' "$expected_commit"
