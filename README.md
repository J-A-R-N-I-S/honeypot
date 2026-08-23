# JARNIS honeypot

Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
Credentials go to [jarnis.io](https://jarnis.io) over HTTPS.

**Full install guide:** https://jarnis.io/guides/self-hosted-honeypot.html

## Quick start (Docker Hub)

1. In [jarnis.io](https://jarnis.io) → **Honeypots** create a sensor and copy the full `hpt_…` token **once** (~52 characters from the create/rotate modal — not a truncated prefix).
2. Run:

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

3. Check: `ssh user@HOST` fails, `curl http://HOST:8080/` shows the login page, the attempt appears on the dashboard.

Only **one** environment variable is required. In the app, `${HONEYPOT_TOKEN}` is a placeholder — paste the real secret into `-e HONEYPOT_TOKEN=…`.

Image on Docker Hub: https://hub.docker.com/r/jarnis/honeypot

## Install guides

### Docker (Hub)

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Leave the start command empty. The image entrypoint is `/jarnis-honeypot`.

### Docker (GHCR alternative)

```bash
docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  ghcr.io/j-a-r-n-i-s/honeypot:latest
```

### Docker Compose

```bash
cp examples/env.example .env   # set HONEYPOT_TOKEN
docker compose up -d
```

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

API URL, honeypot ID and poll interval come from JARNIS — do not set them on the container.

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
