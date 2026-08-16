# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/jarnis-honeypot ./cmd/jarnis-honeypot

# Alpine, not scratch: Barracuda Edge/containerd is happier with a real OS
# (shell, CA store). Run as root so :22/:23/:80 bind inside -p 9022:22 mappings.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 65532 honeypot \
    && mkdir -p /var/lib/jarnis-honeypot
COPY --from=build /out/jarnis-honeypot /usr/local/bin/jarnis-honeypot
EXPOSE 22 23 80
# root: must bind privileged ports when the firewall maps 9022->22.
USER root
ENTRYPOINT ["/usr/local/bin/jarnis-honeypot"]
