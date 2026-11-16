# Image for `ctl`, the one-shot tool that renders and deploys the configuration.
# It is not part of the running tunnel and never listens on the network.

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

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# ssh is used by `ctl push` and `ctl check` to reach the edge.
RUN apk add --no-cache openssh-client
COPY --from=build /out/ctl /usr/local/bin/ctl
WORKDIR /work
ENTRYPOINT ["ctl"]
