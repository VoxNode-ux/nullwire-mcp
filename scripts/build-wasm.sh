#!/bin/sh
# Builds the browser demo files for the project page:
#   docs/redactor.wasm  the real scrubber, compiled for the browser
#   docs/wasm_exec.js   Go's small loader for it
# Run it from anywhere:  sh scripts/build-wasm.sh
set -eu
cd "$(dirname "$0")/.."

GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o docs/redactor.wasm ./internal/wasm

root=$(go env GOROOT)
rm -f docs/wasm_exec.js
for p in "$root/lib/wasm/wasm_exec.js" "$root/misc/wasm/wasm_exec.js"; do
  if [ -f "$p" ]; then
    cp "$p" docs/wasm_exec.js
    break
  fi
done
if [ ! -f docs/wasm_exec.js ]; then
  echo "could not find wasm_exec.js under $root" >&2
  exit 1
fi

ls -lh docs/redactor.wasm docs/wasm_exec.js