# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN short=$(printf '%s' "$VERSION" | cut -c1-12) \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X github.com/j-a-r-n-i-s/honeypot/internal/jarnis.Version=${short}" \
    -o /out/jarnis-honeypot ./cmd/jarnis-honeypot

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/jarnis-honeypot
COPY --from=build /out/jarnis-honeypot /jarnis-honeypot
RUN chmod 755 /jarnis-honeypot \
    && ln -sf /jarnis-honeypot /usr/local/bin/jarnis-honeypot \
    && printf '%s\n' '#!/bin/sh' 'exec /jarnis-honeypot "$@"' > /start.sh \
    && chmod 755 /start.sh
EXPOSE 9022 9023 9080
USER root
# start command empty, or /start.sh / /jarnis-honeypot
ENTRYPOINT ["/jarnis-honeypot"]
CMD []
