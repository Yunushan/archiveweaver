#!/usr/bin/env bash
set -euo pipefail

readonly TOOL_DIR="${ARCHIVEWEAVER_LINT_TOOL_DIR:-${HOME}/.cache/archiveweaver-lint}"
readonly SHELLCHECK_VERSION="0.11.0"
readonly SHELLCHECK_URL="https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz"
readonly SHELLCHECK_SHA256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
readonly ACTIONLINT_VERSION="1.7.7"
readonly ACTIONLINT_URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
readonly ACTIONLINT_SHA256="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
readonly HADOLINT_VERSION="2.12.0"
readonly HADOLINT_URL="https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64"
readonly HADOLINT_SHA256="56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010"

fetch_verified() {
  local url="$1" expected="$2" destination="$3"
  curl --fail --location --silent --show-error --output "${destination}" "${url}"
  printf '%s  %s\n' "${expected}" "${destination}" | sha256sum --check --status || {
    echo "checksum mismatch for ${url}" >&2
    rm -f "${destination}"
    exit 1
  }
}

mkdir -p "${TOOL_DIR}/bin"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fetch_verified "${SHELLCHECK_URL}" "${SHELLCHECK_SHA256}" "${work}/shellcheck.tar.xz"
tar -xJf "${work}/shellcheck.tar.xz" -C "${work}"
install -m 0755 "${work}/shellcheck-v${SHELLCHECK_VERSION}/shellcheck" "${TOOL_DIR}/bin/shellcheck"

fetch_verified "${ACTIONLINT_URL}" "${ACTIONLINT_SHA256}" "${work}/actionlint.tar.gz"
tar -xzf "${work}/actionlint.tar.gz" -C "${work}" actionlint
install -m 0755 "${work}/actionlint" "${TOOL_DIR}/bin/actionlint"

fetch_verified "${HADOLINT_URL}" "${HADOLINT_SHA256}" "${TOOL_DIR}/bin/hadolint"
chmod 0755 "${TOOL_DIR}/bin/hadolint"

"${TOOL_DIR}/bin/shellcheck" --version | sed -n '2p'
"${TOOL_DIR}/bin/actionlint" -version | sed -n '1p'
"${TOOL_DIR}/bin/hadolint" --version
