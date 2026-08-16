# JARNIS honeypot sensor

Capture-only SSH, Telnet and HTTP. Attackers **cannot** get a shell or a web session. Usernames, passwords and source IPs are sent to your JARNIS dashboard.

Image target (later): `ghcr.io/jarnis/honeypot:latest`  
Typical size: ~8–10 MB (static Go, no OS). Fits Barracuda CloudGen Edge Computing.

## 1. In the JARNIS app

1. Sign in at https://jarnis.io → **Honeypots**
2. Register a honeypot (name + public IP/DNS of the firewall)
3. **Save the API token once** (create or rotate). It starts with `hpt_` and is shown only once.
4. Open **Configure → Banners / Designs** and set what the sensor should show
5. Open **Installation** and copy the env values

The token placeholder `${HONEYPOT_TOKEN}` is **not** a real token. Rotate if you lost it.

## 2. Deploy (few clicks)

### Docker / compose

```bash
cp examples/env.example .env
# edit .env — paste HONEYPOT_ID + HONEYPOT_TOKEN + JARNIS_API
docker compose up -d
```

Or one shot (values from the Install tab):

```bash
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_ID=hp_… \
  -e HONEYPOT_TOKEN=hpt_… \
  -e JARNIS_API=https://jarnis.io/api \
  -e UPDATE_INTERVAL=300 \
  -p 9022:22 -p 9023:23 -p 9080:80 \
  ghcr.io/jarnis/honeypot:latest
```

Until the image is on GHCR, build locally:

```bash
docker build -t ghcr.io/jarnis/honeypot:latest .
```

### Binary (no Docker)

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o jarnis-honeypot ./cmd/jarnis-honeypot
sudo setcap 'cap_net_bind_service=+ep' ./jarnis-honeypot   # optional, for :22/:23/:80
HONEYPOT_ID=… HONEYPOT_TOKEN=… JARNIS_API=https://jarnis.io/api \
  SSH_CONTAINER_PORT=9022 TELNET_CONTAINER_PORT=9023 HTTP_CONTAINER_PORT=9080 \
  ./jarnis-honeypot
```

### Barracuda CloudGen — Edge Computing

1. Configuration → Edge Computing (or Secure Connector container engine) → enable Docker
2. Add container image `ghcr.io/jarnis/honeypot:latest` (or import the tar)
3. Environment: paste the Install-tab variables
4. Publish ports **9022/tcp → 22**, **9023/tcp → 23**, **9080/tcp → 80** (or your host ports)
5. Resources: **128 MB RAM**, 0.25 CPU is enough. No privileged mode. No host network.
6. Access rule: WAN → this firewall, services TCP 9022 / 9023 / 9080
7. Destination NAT those ports to the container if Edge Computing does not publish them itself

Keep the default host ports (9022/9023/9080) so the firewall’s own SSH/HTTP stay free.

## 3. Check it works

- Sensor log: `config ok` then `sensor up`
- From another host: `ssh -p 9022 anything@FIREWALL_IP` — login **fails**, dashboard shows the attempt
- `curl http://FIREWALL_IP:9080` — login page from your Designs tab
- Change a banner or design on jarnis.io — within **Config sync interval** (default 5 min) the sensor picks it up. No rebuild.

## What it does / does not

| Does | Does not |
|------|----------|
| Fake SSH / Telnet / HTTP :80 | Grant a shell, TTY, or cookie session |
| Backhaul user, password, IP, UA | Store loot on the firewall |
| Poll banners + HTML designs | Run attacker commands or download payloads |
| Queue events if JARNIS is briefly down | Need a public inbound path to JARNIS except HTTPS out |

Outbound required: **HTTPS to jarnis.io** (config poll + credential POST).

## Env

| Variable | Required | Default |
|----------|----------|---------|
| `HONEYPOT_ID` | yes | — |
| `HONEYPOT_TOKEN` | yes | full `hpt_…` secret |
| `JARNIS_API` | no | `https://jarnis.io/api` |
| `UPDATE_INTERVAL` | no | `300` (min 30) |
| `SSH_CONTAINER_PORT` | no | `22` |
| `TELNET_CONTAINER_PORT` | no | `23` |
| `HTTP_CONTAINER_PORT` | no | `80` |
| `SSH_HOST_KEY` | no | `/var/lib/jarnis-honeypot/ssh_host_ecdsa` |

Host publish ports are Docker/firewall mappings, not process env. Changing listen ports needs a container recreate; banners/designs do not.

## GitHub (when you are ready)

Repo is local at `/root/jarnis-honeypot`. Workflow `.github/workflows/image.yml` builds `ghcr.io/jarnis/honeypot`. Do not push until the org/repo exists.
