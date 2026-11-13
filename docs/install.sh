#!/bin/sh
# NullWire-MCP installer for macOS, Linux and Termux. No Node.js needed.
#
#   curl -fsSL https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.sh | sh -s -- --setup
#
# Options:
#   --setup      also register NullWire with the MCP clients found on this machine
#   --uninstall  remove NullWire (and its entries from MCP client configs)
#   -h, --help   show this help
#
# Environment:
#   NULLWIRE_VERSION      release tag to install (default: latest)
#   NULLWIRE_INSTALL_DIR  where to put the binary (default: ~/.local/bin, or $PREFIX/bin on Termux)
#   NULLWIRE_BASE_URL     download base URL (for mirrors and tests)
#
# The download is checked against the SHA256SUMS.txt published with the release,
# and nothing is installed if the checksum does not match.

set -eu

REPO="VoxNode-ux/nullwire-mcp"
VERSION="${NULLWIRE_VERSION:-latest}"
BASE_URL="${NULLWIRE_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"

if [ -n "${NULLWIRE_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$NULLWIRE_INSTALL_DIR"
else
  INSTALL_DIR="${HOME:-.}/.local/bin"
  case "${PREFIX:-}" in
    *com.termux*) [ -d "$PREFIX/bin" ] && INSTALL_DIR="$PREFIX/bin" ;;
  esac
fi

SETUP=0
UNINSTALL=0

say() { printf '%s\n' "$*"; }
die() { printf 'nullwire install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'USAGE'
NullWire-MCP installer for macOS, Linux and Termux (no Node.js needed).

  curl -fsSL https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/VoxNode-ux/nullwire-mcp/main/scripts/install.sh | sh -s -- --setup

Options:
  --setup      also register NullWire with the MCP clients found on this machine
  --uninstall  remove NullWire and its entries from MCP client configs
  -h, --help   show this help

Environment:
  NULLWIRE_VERSION      release tag to install (default: latest)
  NULLWIRE_INSTALL_DIR  where to put the binary (default: ~/.local/bin, or $PREFIX/bin on Termux)
  NULLWIRE_BASE_URL     download base URL (for mirrors and tests)
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --setup) SETUP=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'nullwire install: unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

BIN="$INSTALL_DIR/nullwire-mcp"

if [ "$UNINSTALL" = 1 ]; then
  if [ -x "$BIN" ]; then
    "$BIN" install --uninstall --client all || true
    rm -f "$BIN"
    say "Removed $BIN"
  else
    say "Nothing to remove: $BIN does not exist."
  fi
  exit 0
fi

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported operating system: $os (on Windows use scripts/install.ps1)" ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported CPU: $arch" ;;
esac
asset="nullwire-$os-$arch"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t nullwire)
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() { # fetch URL DEST
  case "$1" in
    https://*) proto="--proto =https --tlsv1.2" ;;
    *) proto="" ;;
  esac
  if have curl; then
    # shellcheck disable=SC2086
    curl -fsSL $proto -o "$2" "$1" || die "download failed: $1"
  elif have wget; then
    wget -q -O "$2" "$1" || die "download failed: $1"
  else
    die "need curl or wget to download NullWire"
  fi
}

say "Installing NullWire-MCP ($asset, release: $VERSION)"
fetch "$BASE_URL/$asset" "$tmp/$asset"
fetch "$BASE_URL/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt"

expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS.txt")
[ -n "$expected" ] || die "SHA256SUMS.txt has no entry for $asset"
if have sha256sum; then
  actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
elif have shasum; then
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')
else
  die "need sha256sum or shasum to check the download"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $asset (expected $expected, got $actual); nothing was installed"
say "Checksum OK."

mkdir -p "$INSTALL_DIR"
cp "$tmp/$asset" "$BIN.new"
chmod 755 "$BIN.new"
mv -f "$BIN.new" "$BIN"
say "Installed $BIN"

case ":${PATH:-}:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "Note: $INSTALL_DIR is not on your PATH. Add it, for example:"
     say "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

if [ "$SETUP" = 1 ]; then
  say "Registering with MCP clients..."
  "$BIN" install --client all
else
  say "Next: register it with your MCP clients:"
  say "  $BIN install --client all"
fi
