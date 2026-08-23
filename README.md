# JARNIS honeypot
#
# Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
# Credentials go to https://jarnis.io over HTTPS.
#
#     docker pull jarnis/honeypot:latest

**Docs:** [Self-hosted honeypot guide](https://jarnis.io/guides/self-hosted-honeypot.html)

## Quick start

1. In [jarnis.io](https://jarnis.io) → **Honeypots** create (or rotate) a sensor and copy the full `hpt_…` token **once** from the modal (~52 characters). You will not see it again.
2. Run:

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

3. Check: `ssh user@HOST` fails, `curl http://HOST:8080/` shows the login page, the attempt appears on the dashboard.

Only **one** environment variable is required. `${HONEYPOT_TOKEN}` in the app UI is a placeholder, not a secret — paste the real `hpt_…` value into the container env.

## Install guides

**Docs:** https://jarnis.io/guides/self-hosted-honeypot.html

### Docker (Docker Hub)

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Leave the start command empty. The image entrypoint is `/jarnis-honeypot`.

### Docker (GitHub Container Registry)

Alternative registry if you prefer GHCR:

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

## Docker Hub

Customer-facing install uses **`jarnis/honeypot:latest`** on [Docker Hub](https://hub.docker.com/r/jarnis/honeypot). Prefer that tag for docs, Jones/E2E, and copy-paste run commands. GHCR (`ghcr.io/j-a-r-n-i-s/honeypot`) remains an alternative registry.

The short summary meant for the Hub **Full description** lives in [`docs/dockerhub-description.md`](docs/dockerhub-description.md). Updating this README alone does **not** update Docker Hub — Hub text must be set separately (or via a future dockerhub-description Action).

## Environment

| Variable | Required | Default |
|----------|----------|---------|
| `HONEYPOT_TOKEN` | **yes** | full `hpt_…` from create/rotate modal (~52 chars) |
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