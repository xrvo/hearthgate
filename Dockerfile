# The Hearthgate image: ctl, the one-shot configuration tool. The stacks
# themselves run ready-made images named in docker-compose.yml.
#
# Upstream images are pinned by version tag, never by digest, at the level
# where upstream ships only fixes, so each build picks up their bug and
# security fixes without breaking changes. See "Upstream versions" in
# CONTRIBUTING.md for when to move each one.

# The build stage runs on the builder's own architecture and cross-compiles,
# so multi-platform releases do not compile under emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ctl ./cmd/ctl

# A stable Alpine branch: its patch releases arrive with each build, while
# package versions stay within the branch.
FROM alpine:3.24
# ssh is how ctl reaches the edge. The version is not pinned: Alpine drops
# superseded versions from its repository, so a pinned build would stop working.
RUN apk add --no-cache openssh-client
COPY --from=build /out/ctl /usr/local/bin/ctl

WORKDIR /work
ENTRYPOINT ["ctl"]
