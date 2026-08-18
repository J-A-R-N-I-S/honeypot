# JARNIS honeypot
#
# Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
# Credentials go to https://jarnis.io over HTTPS.
#
#     docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest

## Quick start

1. In [jarnis.io](https://jarnis.io) → **Honeypots** create a sensor and copy the `hpt_…` token **once**.
2. Run:

```bash
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  ghcr.io/j-a-r-n-i-s/honeypot:latest
```

3. Check: `ssh user@HOST` fails, `curl http://HOST:8080/` shows the login page, the attempt appears on the dashboard.

Only **one** environment variable is required.

## Install guides

### Docker

```bash
docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  ghcr.io/j-a-r-n-i-s/honeypot:latest
```

Leave the start command empty. The image entrypoint is `/jarnis-honeypot`.

### Docker Compose

```bash
cp examples/env.example .env   # set HONEYPOT_TOKEN
docker compose up -d
```

### Barracuda CloudGen Edge

1. Edge Computing → add image `ghcr.io/j-a-r-n-i-s/honeypot:latest` (force-pull after updates).
2. Start command: **empty**.
3. Environment: `HONEYPOT_TOKEN` = the `hpt_…` secret (no quotes).
4. Publish **22→22**, **23→23**, **8080→8080**.
5. Access-Rule: WAN TCP 22, 23, 8080.
6. Outbound: HTTPS to `jarnis.io` (TCP 443). DNS is optional — the sensor dials a pinned API address.

128 MB RAM is enough. Do not run privileged.

### Binary (no Docker)

```bash
go build -o jarnis-honeypot ./cmd/jarnis-honeypot
HONEYPOT_TOKEN=hpt_… ./jarnis-honeypot
```

Needs bind rights for :22 / :23 (root or `cap_net_bind_service`).

## Environment

| Variable | Required | Default |
|----------|----------|---------|
| `HONEYPOT_TOKEN` | **yes** | full `hpt_…` from create/rotate |
| `SSH_CONTAINER_PORT` | no | `22` |
| `TELNET_CONTAINER_PORT` | no | `23` |
| `HTTP_CONTAINER_PORT` | no | `8080` |

`${HONEYPOT_TOKEN}` in the app is a placeholder, not a secret. API, ID and poll interval come from JARNIS — do not set them on the container.

Port changes need a recreate. Banner and design changes apply on the next poll (default 5 minutes).

## Security

- Password and public-key auth are **always denied**. No shell, no TTY, no HTTP cookie.
- Captured credentials are sent to JARNIS over TLS only. They are not written to stdout.
- Source IP is the TCP peer — `X-Forwarded-For` is ignored.
- At most 64 concurrent SSH/Telnet sessions; extra connections are dropped.
- Control-plane client follows **no** HTTP redirects and uses no HTTP proxy.

Report issues via GitHub Security Advisories on this repository.

## License

MIT — see [LICENSE](LICENSE).
