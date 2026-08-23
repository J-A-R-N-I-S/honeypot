# JARNIS honeypot

Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
Credentials go to [jarnis.io](https://jarnis.io) over HTTPS.

**Full install guide:** https://jarnis.io/guides/self-hosted-honeypot.html

**Customer source of truth:** Docker Hub image [`jarnis/honeypot`](https://hub.docker.com/r/jarnis/honeypot) (`jarnis/honeypot:latest`). GHCR builds are internal CI only — not the customer SoT.

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

Prefer an env file on the host (used by the auto-update script):

```bash
sudo mkdir -p /etc/jarnis
echo 'HONEYPOT_TOKEN=hpt_…' | sudo tee /etc/jarnis/honeypot.env >/dev/null
sudo chmod 600 /etc/jarnis/honeypot.env
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  --env-file /etc/jarnis/honeypot.env \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Image on Docker Hub: https://hub.docker.com/r/jarnis/honeypot

## Auto-update (systemd)

Pull Hub and recreate the container when `jarnis/honeypot:latest` changes (same name, ports, memory, restart policy; env via `--env-file` only):

```bash
sudo install -m 755 scripts/jarnis-honeypot-update.sh /usr/local/sbin/jarnis-honeypot-update
sudo install -m 644 deploy/systemd/jarnis-honeypot-update.service /etc/systemd/system/
sudo install -m 644 deploy/systemd/jarnis-honeypot-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jarnis-honeypot-update.timer
```

Defaults: `IMAGE=jarnis/honeypot:latest`, `NAME=jarnis-honeypot`, `ENV_FILE=/etc/jarnis/honeypot.env`.

## Install guides

### Docker (Hub — primary)

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  --env-file /etc/jarnis/honeypot.env \
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

## CI / image publish

On push to `main` (and tags / `workflow_dispatch`), GitHub Actions:

1. Runs tests.
2. Pushes **GHCR** (`ghcr.io/<owner>/honeypot`) — internal CI only.
3. Pushes **Docker Hub** (`jarnis/honeypot:latest` and `jarnis/honeypot:<sha12>`) when both repository secrets are set:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN`

If those secrets are missing, the Hub job is skipped and the workflow still succeeds. Customer deployments must keep using Hub.

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
- The update script never prints the env file or token.

Report issues via GitHub Security Advisories on this repository.

## License

MIT — see [LICENSE](LICENSE).
