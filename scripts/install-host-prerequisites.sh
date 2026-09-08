#!/usr/bin/env bash
set -euo pipefail

apply=0
for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    --check-only) apply=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

required=(ca-certificates curl git jq openssl tar unzip rsync)
missing=()
for command_name in "${required[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
done

if ((${#missing[@]} == 0)); then
  echo "Host prerequisite check: PASS"
  exit 0
fi

echo "Missing common host packages: ${missing[*]}"
if ((apply == 0)); then
  echo "No changes made. Review the package-manager command and rerun with --apply if approved."
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "--apply requires root (or an approved sudo wrapper)." >&2
  exit 2
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y "${missing[@]}"
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y "${missing[@]}"
elif command -v yum >/dev/null 2>&1; then
  yum install -y "${missing[@]}"
else
  echo "No supported apt-get/dnf/yum package manager found." >&2
  exit 2
fi

echo "Host prerequisite installation: PASS"

