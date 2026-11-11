#!/usr/bin/env bash
# Shared helpers for the asdf / mise plugin for NullWire-MCP.
set -euo pipefail

REPO="VoxNode-ux/nullwire-mcp"
TOOL_NAME="nullwire-mcp"

fail() { printf 'asdf-%s: %s\n' "$TOOL_NAME" "$*" >&2; exit 1; }

base_url() {
  printf '%s' "${NULLWIRE_BASE_URL:-https://github.com/$REPO/releases/download}"
}

curl_opts=(-fsSL --proto '=https,http' --tlsv1.2)

# Prints stable versions (1.2.3, no "v"), oldest first.
list_versions() {
  git ls-remote --tags --refs "https://github.com/$REPO.git" \
    | awk -F/ '{ print $NF }' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | sed 's/^v//' \
    | sort -t. -k1,1n -k2,2n -k3,3n
}

asset_name() {
  local os arch
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail "unsupported CPU: $(uname -m)" ;;
  esac
  printf 'nullwire-%s-%s' "$os" "$arch"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

# download_release VERSION DEST_DIR: fetches the binary and checks it.
download_release() {
  local version="$1" dest="$2" asset want got
  asset="$(asset_name)"
  mkdir -p "$dest"
  curl "${curl_opts[@]}" -o "$dest/$asset" "$(base_url)/v$version/$asset" \
    || fail "could not download $asset for v$version"
  curl "${curl_opts[@]}" -o "$dest/SHA256SUMS.txt" "$(base_url)/v$version/SHA256SUMS.txt" \
    || fail "could not download SHA256SUMS.txt for v$version"
  want="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$dest/SHA256SUMS.txt")"
  [ -n "$want" ] || fail "SHA256SUMS.txt has no entry for $asset"
  got="$(sha256_of "$dest/$asset")"
  [ "$got" = "$want" ] || fail "checksum mismatch for $asset (expected $want, got $got); nothing was installed"
}
