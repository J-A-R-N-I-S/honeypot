# JARNIS honeypot

Capture-only SSH, Telnet and HTTP. Attackers never get a shell or a cookie.
Credentials go to [jarnis.io](https://jarnis.io) over HTTPS.

**Full install guide:** https://jarnis.io/guides/self-hosted-honeypot.html

## Quick start (Docker Hub)

1. In [jarnis.io](https://jarnis.io) → **Honeypots** create a sensor and copy the full `hpt_…` token **once** (~52 characters from the create/rotate modal — not a truncated prefix).
2. Run:

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped \
  --memory 64m --cpus 0.25 --pids-limit 64 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=8m,mode=1777 \
  -v jarnis-honeypot-state:/var/lib/jarnis-honeypot \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Live sensor uses ~6 MB RAM. A 64 MB limit leaves room for other services without a 20× over-reserve.

**Before you run it:** move the host's own sshd off port 22 (for example to 2222) and confirm a login on the new port — the decoy takes 22. Published ports bind on all interfaces (`0.0.0.0` / `[::]`) on purpose: the honeypot must be reachable from the internet. Docker-published ports **bypass ufw** (Docker writes its own iptables rules), so `ufw deny 22` does not hide the decoy — and do not publish anything else from this host you would not expose. See [Ports and firewall](#ports-and-firewall).

The named volume `jarnis-honeypot-state` holds the SSH host key (`/var/lib/jarnis-honeypot/ssh_host_ecdsa`). Without it the key is regenerated on every recreate (the root filesystem is read-only), and a changing fingerprint is an easy honeypot tell. Keep the volume when you recreate or update the container.

3. Check: `ssh user@HOST` fails, `curl http://HOST:8080/` shows the login page, the attempt appears on the dashboard.
4. Install the host auto-update timer (the container cannot pull Hub). See [Auto-update](#auto-update-docker-hub) or https://jarnis.io/guides/honeypot-auto-update.html

Only **one** environment variable is required. In the app, `${HONEYPOT_TOKEN}` is a placeholder — paste the real secret into `-e HONEYPOT_TOKEN=…`.

Image on Docker Hub: https://hub.docker.com/r/jarnis/honeypot

## Install guides

### Docker (Hub)

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped \
  --memory 64m --cpus 0.25 --pids-limit 64 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=8m,mode=1777 \
  -v jarnis-honeypot-state:/var/lib/jarnis-honeypot \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

Leave the start command empty. The image entrypoint is `/jarnis-honeypot`.

### Docker (GHCR — CI artifact only, not customer SoT)

```bash
docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped \
  --memory 64m --cpus 0.25 --pids-limit 64 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=8m,mode=1777 \
  -v jarnis-honeypot-state:/var/lib/jarnis-honeypot \
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

## Ports and firewall

- `-p 22:22 -p 23:23 -p 8080:8080` binds on `0.0.0.0` (and `[::]`). That is intended: scanners on the internet must reach the decoy. Do not bind to `127.0.0.1`.
- Move the host sshd off 22 **before** starting the container (keep the old port until a login on the new one works). On Ubuntu 24.04+ that means the `ssh.socket` drop-in, see the [install guide](https://jarnis.io/guides/self-hosted-honeypot.html).
- Docker-published ports bypass ufw. ufw rules on the host do not restrict them; filter in the provider firewall or the `DOCKER-USER` iptables chain if you need to.

## Container hardening

The recommended flags: `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--pids-limit 64`, `--cpus 0.25`, `--memory 64m`, `--tmpfs /tmp:size=8m,mode=1777`, plus the state volume on `/var/lib/jarnis-honeypot`. No capability is needed to bind 22/23 inside the container. `docker-compose.yml` uses the same settings; the host updater keeps them (and the container's mounts) on every recreate.

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

The sensor cannot pull Hub itself: it is `--read-only`, has no `docker.sock`, and drops all capabilities. **SENSOR OUTDATED** in the app is UI-only. The host timer is part of a **normal install**. Public guide: https://jarnis.io/guides/honeypot-auto-update.html

Do **not** mount `docker.sock` into the honeypot. Do **not** run Watchtower in or next to this image.

`jarnis-honeypot-update` pulls Hub `latest`, then recreates only JARNIS honeypot containers whose digest changed (label `com.jarnis.honeypot=1` or image `jarnis/honeypot`). Several containers on one host (for example 9022/9023/9080 and 9122/9123/9180) are updated independently. Token/env, published ports, volume and bind mounts, 64m, 0.25 CPU, and the security flags are kept. A container without a mount on `/var/lib/jarnis-honeypot` gets the named volume `jarnis-honeypot-state` (`jarnis-honeypot-state-<name>` for other container names) so its SSH host key persists from then on; a key found in an old writable container layer is copied over. Unrelated containers are never touched. Hub only — never GHCR.

Daily including weekends (sensors do not sleep). systemd timer at 04:20 host time; cron fallback if there is no systemd.

### VPS (systemd, preferred)

```bash
# update script (Hub default IMAGE=jarnis/honeypot:latest)
curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.sh -o /usr/local/sbin/jarnis-honeypot-update
chmod 755 /usr/local/sbin/jarnis-honeypot-update

# systemd units (public copies on jarnis.io/guides)
curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.service -o /etc/systemd/system/jarnis-honeypot-update.service
curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.timer -o /etc/systemd/system/jarnis-honeypot-update.timer
systemctl daemon-reload
systemctl enable --now jarnis-honeypot-update.timer
```

Cron fallback (no systemd):

```bash
echo '20 4 * * * root /usr/local/sbin/jarnis-honeypot-update' > /etc/cron.d/jarnis-honeypot-update
```

Disable: `systemctl disable --now jarnis-honeypot-update.timer` (and `rm -f /etc/cron.d/jarnis-honeypot-update` if you used cron).

Optional `/etc/jarnis-honeypot-update.conf`: `NAME` (pin one container; default is every matching honeypot on the host), `IMAGE` (default `jarnis/honeypot:latest`), `ENV_FILE` (used only when `NAME` is set; default `/root/jarnis-honeypot.env`). Without `NAME`, each container keeps its own env from inspect. The script never prints the env file or token.

### CI secrets (Hub publish)

On the GitHub repo **Settings → Secrets and variables → Actions**, add:

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub username that can push `jarnis/honeypot` |
| `DOCKERHUB_TOKEN` | Docker Hub access token (read/write) |

When both are set, the `dockerhub` job on `main` pushes `jarnis/honeypot:latest` and `jarnis/honeypot:<sha12>`. If either secret is missing, that job is skipped (GHCR job still runs).

## License

MIT — see [LICENSE](LICENSE).
