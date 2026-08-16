# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/jarnis-honeypot ./cmd/jarnis-honeypot

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/jarnis-honeypot \
    && printf '%s\n' '116.204.196.220 jarnis.io' >> /etc/hosts \
    && printf '%s\n' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' 'nameserver 9.9.9.9' > /etc/resolv.conf
COPY --from=build /out/jarnis-honeypot /jarnis-honeypot
RUN chmod 755 /jarnis-honeypot \
    && ln -sf /jarnis-honeypot /usr/local/bin/jarnis-honeypot \
    && printf '%s\n' '#!/bin/sh' 'exec /jarnis-honeypot "$@"' > /start.sh \
    && chmod 755 /start.sh
EXPOSE 9022 9023 9080
USER root
# Barracuda: leave start command empty, or set /start.sh or /jarnis-honeypot
ENTRYPOINT ["/jarnis-honeypot"]
CMD []
