# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/jarnis-honeypot ./cmd/jarnis-honeypot

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/jarnis-honeypot /jarnis-honeypot
EXPOSE 22 23 80
USER 65532:65532
VOLUME ["/var/lib/jarnis-honeypot"]
ENTRYPOINT ["/jarnis-honeypot"]
