#!/bin/sh
# Render the Homebrew formula and the Scoop manifest from the templates in this
# folder, using the SHA256SUMS.txt of a published release.
#
#   sh packaging/render.sh                       # tag from npm/package.json, sums downloaded
#   sh packaging/render.sh -v v1.2.0 -o out      # choose the tag and output folder
#   sh packaging/render.sh -v v1.2.0 -s dist/SHA256SUMS.txt   # offline, from a local file
#
# Output: <out>/nullwire-mcp.rb (Homebrew) and <out>/nullwire-mcp.json (Scoop).
# It stops if any checksum is missing or is not 64 hex characters, and if any
# @@PLACEHOLDER@@ is left over.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
tag=""
sums=""
out="$here/out"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }
die() { printf 'render: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    -v|--version) [ $# -ge 2 ] || die "$1 needs a value"; tag=$2; shift 2 ;;
    -s|--sums)    [ $# -ge 2 ] || die "$1 needs a value"; sums=$2; shift 2 ;;
    -o|--out)     [ $# -ge 2 ] || die "$1 needs a value"; out=$2; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if [ -z "$tag" ]; then
  tag=$(sed -n 's/.*"nullwireRelease"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$root/npm/package.json" | head -n 1)
  [ -n "$tag" ] || die "no -v given and npm/package.json has no nullwireRelease"
fi
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "tag must look like v1.2.0 (got: $tag)" ;;
esac
version=${tag#v}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -z "$sums" ]; then
  url="https://github.com/VoxNode-ux/nullwire-mcp/releases/download/$tag/SHA256SUMS.txt"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp/SHA256SUMS.txt" || die "could not download $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$tmp/SHA256SUMS.txt" || die "could not download $url"
  else
    die "need curl or wget, or pass a local file with -s"
  fi
  sums="$tmp/SHA256SUMS.txt"
fi
[ -f "$sums" ] || die "no such file: $sums"

# Print the checksum for one release asset, or stop.
sha_for() {
  h=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1; exit }' "$sums")
  [ -n "$h" ] || die "SHA256SUMS has no entry for $1"
  printf '%s' "$h" | grep -Eq '^[0-9a-fA-F]{64}$' || die "bad checksum for $1: $h"
  printf '%s' "$h" | tr 'A-F' 'a-f'
}

d_arm=$(sha_for nullwire-darwin-arm64)
d_amd=$(sha_for nullwire-darwin-amd64)
l_arm=$(sha_for nullwire-linux-arm64)
l_amd=$(sha_for nullwire-linux-amd64)
w_amd=$(sha_for nullwire-windows-amd64.exe)
w_arm=$(sha_for nullwire-windows-arm64.exe)

mkdir -p "$out"
render() {
  sed \
    -e "s|@@VERSION@@|$version|g" \
    -e "s|@@TAG@@|$tag|g" \
    -e "s|@@SHA_DARWIN_ARM64@@|$d_arm|g" \
    -e "s|@@SHA_DARWIN_AMD64@@|$d_amd|g" \
    -e "s|@@SHA_LINUX_ARM64@@|$l_arm|g" \
    -e "s|@@SHA_LINUX_AMD64@@|$l_amd|g" \
    -e "s|@@SHA_WINDOWS_AMD64@@|$w_amd|g" \
    -e "s|@@SHA_WINDOWS_ARM64@@|$w_arm|g" \
    "$1" > "$2"
  if grep -n '@@' "$2" >/dev/null; then
    grep -n '@@' "$2" >&2
    die "unreplaced placeholder in $2"
  fi
}

render "$here/homebrew/nullwire-mcp.rb.tmpl"   "$out/nullwire-mcp.rb"
render "$here/scoop/nullwire-mcp.json.tmpl" "$out/nullwire-mcp.json"

printf 'Rendered %s for %s:\n  %s\n  %s\n' "$version" "$tag" "$out/nullwire-mcp.rb" "$out/nullwire-mcp.json"
