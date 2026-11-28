# mailctl: one static binary. Build context is the repository root:
#   docker build -f images/admin/Dockerfile .
# The build stage always runs on the builder's own platform and cross-compiles, so a
# multi-platform build never runs the Go toolchain under emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
# CGO off: the result needs no libc, which is what lets the final image be distroless.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mailctl ./cmd/mailctl

# Distroless publishes no version tags, so the digest is the pin. This variant runs as root
# (not the :nonroot one) because the state directory is root-owned and mailctl must write
# it. Mail belongs to the mail user, so reading or purging it also takes DAC_OVERRIDE.
FROM gcr.io/distroless/static-debian13:latest@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
COPY --from=build /out/mailctl /usr/local/bin/mailctl
ENTRYPOINT ["mailctl"]
