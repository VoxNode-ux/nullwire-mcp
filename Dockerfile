# Build on the runner's own architecture and cross-compile for the target, so
# multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/nullwire-mcp .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/nullwire-mcp /usr/local/bin/nullwire-mcp
USER nonroot:nonroot
# This is an MCP server on stdio: run it with `docker run -i`. The diagnostic
# proxy listens on the container's loopback only, by design, so a published
# port (-p) cannot reach it. On Linux use `--network host` to reach it from
# the host's own 127.0.0.1.
ENTRYPOINT ["/usr/local/bin/nullwire-mcp"]