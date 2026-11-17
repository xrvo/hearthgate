# The Hearthgate image. One image runs every container in both stacks and the
# ctl tool; image/hearthgate, its entrypoint, picks the role.
#
# Everything from upstream is pinned here, by tag and digest, and nowhere else:
# the Go toolchain, Caddy, and the nginx image the result is built on.

# The build stage runs on the builder's own architecture and cross-compiles,
# so multi-platform releases do not compile under emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ctl ./cmd/ctl

# Caddy is a single static binary, taken from its official image.
FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0 AS caddy

# The official nginx image is the base: Alpine, with nginx and its stream module.
FROM nginx:1.30.6-alpine@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a
# wg and iptables set up the tunnel and its firewall; ssh is how ctl reaches the edge.
RUN apk add --no-cache wireguard-tools-wg iptables openssh-client
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY --from=build /out/ctl /usr/local/bin/ctl
COPY --chmod=755 image/hearthgate /usr/local/bin/hearthgate

# Where Caddy keeps certificates and their keys; the home stack mounts a volume here.
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
WORKDIR /work
# The nginx base stops with SIGQUIT; every role here handles SIGTERM.
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=5s --timeout=3s --retries=12 --start-period=10s CMD ["hearthgate", "healthy"]
ENTRYPOINT ["hearthgate"]
