# syntax=docker/dockerfile:1.7

# Multi-stage build: tiny runtime image (scratch + ca-certs + tzdata).

ARG GO_VERSION=1.23

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

RUN apk add --no-cache git ca-certificates tzdata

# Cache modules separately from sources so source-only edits don't bust
# the dependency download layer.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.date=${DATE}" \
      -o /out/prometheus_pihole_exporter \
      ./cmd/prometheus_pihole_exporter

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/prometheus_pihole_exporter /usr/local/bin/prometheus_pihole_exporter

USER 65534:65534
EXPOSE 9617

ENTRYPOINT ["/usr/local/bin/prometheus_pihole_exporter"]
