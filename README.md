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

The recommended flags: `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--pids-limit 64`, `--cpus 0.25`, `--memory 64m`, `--tmpfs /tmp:size=8m,mode=1777`, plus the state volume on `/var/lib/jarnis-honeypot`. The sensor binds 22/23 inside the container without `CAP_NET_BIND_SERVICE` only because Docker sets `net.ipv4.ip_unprivileged_port_start=0` in the container's network namespace (default for bridge networks since Docker 20.10). With `--network host`, or a runtime that does not set this sysctl, binding 22/23 fails under `--cap-drop ALL`. `docker-compose.yml` uses the same settings; the host updater enforces them on every recreate.

## Multiple instances on one host

Give every instance its own container name, host ports **and state volume** — two sensors sharing one volume would share one SSH host key (and race on first start):

```bash
docker run -d --name jarnis-honeypot-b --restart unless-stopped \
  --memory 64m --cpus 0.25 --pids-limit 64 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=8m,mode=1777 \
  -v jarnis-honeypot-state-b:/var/lib/jarnis-honeypot \
  -e HONEYPOT_TOKEN=hpt_…second_token… \
  -p 9122:22 -p 9123:23 -p 9180:8080 \
  jarnis/honeypot:latest
```

The host updater follows the same rule when it has to add a volume: `jarnis-honeypot-state` for the container named `jarnis-honeypot`, `jarnis-honeypot-state-<container name>` for any other.

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

`jarnis-honeypot-update` pulls Hub `latest`, then recreates only JARNIS honeypot containers whose digest changed (label `com.jarnis.honeypot=1` or image `jarnis/honeypot`). Several containers on one host (for example 9022/9023/9080 and 9122/9123/9180) are updated independently. Unrelated containers are never touched. Hub only — never GHCR.

- **Carried over** from the old container: env (token), published ports (tcp/udp, host IP incl. IPv6), volumes and bind mounts (ro/rw), network mode, labels, log driver/options, explicitly set hostname/domainname, `--dns`/`--dns-search`/`--dns-option`, `--add-host`.
- **Always reset to the hardened defaults**: `--restart unless-stopped`, `--memory 64m`, `--cpus 0.25`, `--pids-limit 64`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--tmpfs /tmp:size=8m,mode=1777`.
- **Not carried over**: additional networks, network aliases/static IPs, user, entrypoint/command, workdir, sysctls, ulimits, devices, other tmpfs mounts. Containers whose mount paths or options contain whitespace (or `,`/`:` in paths) are skipped and left running unchanged.
- A container without a mount on `/var/lib/jarnis-honeypot` gets a state volume (see [Multiple instances](#multiple-instances-on-one-host) for the name); a key found in an old writable container layer is copied over.
- **Safe replace**: one run at a time (`flock` on `/run/lock/jarnis-honeypot-update.lock`). The old container is removed only after the new one has run for `HEALTH_WAIT` seconds (default 8) with no restart. On any failure, or SIGINT/SIGTERM, the original container (tracked by ID) is renamed back and restarted.

Daily including weekends (sensors do not sleep). systemd timer at 04:20 host time; cron fallback if there is no systemd.

### VPS (systemd, preferred)

Download to a scratch dir, **verify the SHA-256 sums**, then install. The script runs daily as root — do not skip the check.

```bash
d=$(mktemp -d) && cd "$d"
for f in jarnis-honeypot-update.sh jarnis-honeypot-update.service jarnis-honeypot-update.timer; do
  curl -fsSL "https://jarnis.io/guides/$f" -o "$f"
done
cat > SHA256SUMS <<'EOF'
bba3c497b8ce8fc4bea3aa5542afb89f1d4ac84b4ccaa05fa99d637254e262e2  jarnis-honeypot-update.sh
d3d16961a46f16b432bd5f58e29a3f1bc50225e0a2ebb166a7c0bde73da56baa  jarnis-honeypot-update.service
04453fcb41355927022705b881f0ad145750f10cd3d8b4fb28103d8166e4e03c  jarnis-honeypot-update.timer
EOF
if sha256sum -c SHA256SUMS; then
  install -m 755 jarnis-honeypot-update.sh /usr/local/sbin/jarnis-honeypot-update
  install -m 644 jarnis-honeypot-update.service jarnis-honeypot-update.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now jarnis-honeypot-update.timer
else
  echo 'CHECKSUM MISMATCH — nothing installed'
fi
cd / && rm -rf "$d"
```

The sums are for the files in this repository (`scripts/jarnis-honeypot-update.sh`, `deploy/systemd/*`); jarnis.io serves byte-identical copies. Update the sums whenever one of these files changes.

Cron fallback (no systemd):

```bash
echo '20 4 * * * root /usr/local/sbin/jarnis-honeypot-update' > /etc/cron.d/jarnis-honeypot-update
```

Disable: `systemctl disable --now jarnis-honeypot-update.timer` (and `rm -f /etc/cron.d/jarnis-honeypot-update` if you used cron).

Optional `/etc/jarnis-honeypot-update.conf`: `NAME` (pin one container; default is every matching honeypot on the host), `IMAGE` (default `jarnis/honeypot:latest`), `ENV_FILE` (used only when `NAME` is set; default `/root/jarnis-honeypot.env`), `HEALTH_WAIT` (seconds the new container must stay up before the old one is removed; default `8`), `LOCK_FILE` (default `/run/lock/jarnis-honeypot-update.lock`). Without `NAME`, each container keeps its own env from inspect. The script never prints the env file or token.

### CI secrets (Hub publish)

On the GitHub repo **Settings → Secrets and variables → Actions**, add:

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub username that can push `jarnis/honeypot` |
| `DOCKERHUB_TOKEN` | Docker Hub access token (read/write) |

When both are set, the `dockerhub` job on `main` pushes `jarnis/honeypot:latest` and `jarnis/honeypot:<sha12>`. If either secret is missing, that job is skipped (GHCR job still runs).

## License

MIT — see [LICENSE](LICENSE).
