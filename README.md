# JARNIS honeypot

Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
Credentials go to [jarnis.io](https://jarnis.io) over HTTPS.

**Full install guide:** https://jarnis.io/guides/self-hosted-honeypot.html

## Quick start (Docker Hub)

1. In [jarnis.io](https://jarnis.io) → **Honeypots** create a sensor and copy the full `hpt_…` token **once** (~52 characters from the create/rotate modal — not a truncated prefix).
2. Run:

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 64m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Live sensor uses ~6 MB RAM. A 64 MB limit leaves room for other services without a 20× over-reserve.

3. Check: `ssh user@HOST` fails, `curl http://HOST:8080/` shows the login page, the attempt appears on the dashboard.

Only **one** environment variable is required. In the app, `${HONEYPOT_TOKEN}` is a placeholder — paste the real secret into `-e HONEYPOT_TOKEN=…`.

Image on Docker Hub: https://hub.docker.com/r/jarnis/honeypot

## Install guides

### Docker (Hub)

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 64m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Leave the start command empty. The image entrypoint is `/jarnis-honeypot`.

### Docker (GHCR — CI artifact only, not customer SoT)

```bash
docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 64m \
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



## Release pointer (Sensor veraltet)

After each successful Hub publish, CI updates [`deploy/release.json`](deploy/release.json) with the 12-char build id baked into the image (`VERSION=$GITHUB_SHA`). The JARNIS website reads this file so **SENSOR VERALTET** tracks Docker Hub, not a stale GHCR `/etc` pin.

## Auto-update (Docker Hub)

Customer images are published to **Docker Hub** (`jarnis/honeypot:latest`) by CI when repository secrets are set. GHCR builds remain an internal CI artifact.

### VPS (systemd, preferred)

```bash
# update script (Hub default IMAGE=jarnis/honeypot:latest)
curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.sh -o /usr/local/sbin/jarnis-honeypot-update
chmod 755 /usr/local/sbin/jarnis-honeypot-update

# units from this repo
curl -fsSL https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/systemd/jarnis-honeypot-update.service -o /etc/systemd/system/jarnis-honeypot-update.service
curl -fsSL https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/systemd/jarnis-honeypot-update.timer -o /etc/systemd/system/jarnis-honeypot-update.timer
systemctl daemon-reload
systemctl enable --now jarnis-honeypot-update.timer
```

Optional `/etc/jarnis-honeypot-update.conf`: `NAME`, `IMAGE` (default `jarnis/honeypot:latest`), `ENV_FILE` (default `/root/jarnis-honeypot.env`). The script never prints the env file or token.

### CI secrets (Hub publish)

On the GitHub repo **Settings → Secrets and variables → Actions**, add:

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub username that can push `jarnis/honeypot` |
| `DOCKERHUB_TOKEN` | Docker Hub access token (read/write) |

When both are set, the `dockerhub` job on `main` pushes `jarnis/honeypot:latest` and `jarnis/honeypot:<sha12>`. If either secret is missing, that job is skipped (GHCR job still runs).

## License

MIT — see [LICENSE](LICENSE).
