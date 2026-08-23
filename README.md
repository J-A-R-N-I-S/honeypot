# JARNIS honeypot

Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
Credentials go to [jarnis.io](https://jarnis.io) over HTTPS.

**Full install guide:** https://jarnis.io/guides/self-hosted-honeypot.html

**Customer image:** Docker Hub [`jarnis/honeypot`](https://hub.docker.com/r/jarnis/honeypot) (`:latest` and `:<sha12>`).  
**GHCR** (`ghcr.io/j-a-r-n-i-s/honeypot`) is an **internal CI artifact only** — not the customer source of truth.

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

## Auto-update (systemd timer)

Hosts can poll Hub every minute and recreate the container only when the image digest changes (`scripts/jarnis-honeypot-update.sh`). The script never prints secret values.

Enable (from a clone of this repo):

```bash
sudo install -m 755 scripts/jarnis-honeypot-update.sh /usr/local/bin/jarnis-honeypot-update.sh && \
sudo cp deploy/systemd/jarnis-honeypot-update.service deploy/systemd/jarnis-honeypot-update.timer /etc/systemd/system/ && \
sudo systemctl daemon-reload && sudo systemctl enable --now jarnis-honeypot-update.timer
```

Check: `systemctl list-timers jarnis-honeypot-update.timer` and `journalctl -u jarnis-honeypot-update.service`.

Override image/name with drop-in env if needed (`IMAGE`, `NAME`). Default `IMAGE=jarnis/honeypot:latest`.

## Install guides

### Docker (Hub) — preferred

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Leave the start command empty. The image entrypoint is `/jarnis-honeypot`.

### Docker Compose

```bash
cp examples/env.example .env   # set HONEYPOT_TOKEN
docker compose up -d
```

Compose uses `jarnis/honeypot:latest` from Hub.

### Binary (no Docker)

```bash
go build -o jarnis-honeypot ./cmd/jarnis-honeypot
HONEYPOT_TOKEN=hpt_… ./jarnis-honeypot
```

Needs bind rights for :22 / :23 (root or `cap_net_bind_service`).

## CI images

Target workflow (tests → GHCR + Hub in parallel) is checked in as [`deploy/ci/image.yml`](deploy/ci/image.yml):

1. Runs tests.
2. Pushes **GHCR** (internal CI artifact only): `ghcr.io/j-a-r-n-i-s/honeypot:latest` and `:<sha12>`.
3. Pushes **Docker Hub** (customer SoT): `jarnis/honeypot:latest` and `:<sha12>`.

**Apply once:** copy `deploy/ci/image.yml` → `.github/workflows/image.yml` in the GitHub UI (or with a token that has **`workflow`** scope). Until that lands, CI still publishes GHCR only.

Hub publish needs repository secrets **`DOCKERHUB_USERNAME`** and **`DOCKERHUB_TOKEN`**. If either is empty, the Hub job emits a notice and skips the push (workflow still succeeds).

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
