#!/data/data/com.termux/files/usr/bin/sh
# Build, test and install nullwire-mcp v1.2.0 on Termux.
# Run from the project folder:  sh termux-install.sh
set -eu

pkg install -y ca-certificates golang git >/dev/null

echo "== go vet =="
go vet ./...
echo "== go test (this is the check that was not possible off-device) =="
go test ./...

echo "== build =="
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o nullwire-mcp .
install -m 755 nullwire-mcp "$PREFIX/bin/nullwire-mcp"

echo
echo "Installed: $(command -v nullwire-mcp)"
echo "Try it in one session:   nullwire-mcp -target https://httpbin.org"
echo "and from a SECOND session:  curl http://127.0.0.1:8080/get"
