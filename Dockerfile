# syntax=docker/dockerfile:1
# Go version: keep in sync with the toolchain line in go.mod and the CI
# workflow (.github/workflows/image.yml).
FROM golang:1.27.1-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN short=$(printf '%s' "$VERSION" | cut -c1-12) \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X github.com/j-a-r-n-i-s/honeypot/internal/jarnis.Version=${short}" \
    -o /out/jarnis-honeypot ./cmd/jarnis-honeypot

FROM alpine:3.24
# /var/lib/jarnis-honeypot: state volume (SSH host key + config.json cache).
# root:root 0700 — the sensor runs as root with all capabilities dropped, so
# it can write here only as the owner. A new named volume inherits this.
RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/jarnis-honeypot \
    && chmod 700 /var/lib/jarnis-honeypot
COPY --from=build /out/jarnis-honeypot /jarnis-honeypot
RUN chmod 755 /jarnis-honeypot \
    && ln -sf /jarnis-honeypot /usr/local/bin/jarnis-honeypot \
    && printf '%s\n' '#!/bin/sh' 'exec /jarnis-honeypot "$@"' > /start.sh \
    && chmod 755 /start.sh
EXPOSE 22 23 8080
USER root
# start command empty, or /start.sh / /jarnis-honeypot
ENTRYPOINT ["/jarnis-honeypot"]
CMD []
