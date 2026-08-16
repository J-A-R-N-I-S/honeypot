# JARNIS honeypot sensor

Capture-only SSH, Telnet and HTTP. Attackers **cannot** get a shell or a web session. Usernames, passwords and source IPs are sent to your JARNIS dashboard.

Public image: `ghcr.io/j-a-r-n-i-s/honeypot:latest` (GitHub Container Registry, free)  
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
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 80:80 \
  ghcr.io/j-a-r-n-i-s/honeypot:latest
```

Until the package is public, build locally:

```bash
docker build -t ghcr.io/j-a-r-n-i-s/honeypot:latest .
```

### Binary (no Docker)

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o jarnis-honeypot ./cmd/jarnis-honeypot
sudo setcap 'cap_net_bind_service=+ep' ./jarnis-honeypot   # optional, for :22/:23/:80
HONEYPOT_TOKEN=… ./jarnis-honeypot
```

### Barracuda CloudGen — Edge Computing

1. Configuration → Edge Computing (or Secure Connector container engine) → enable Docker
2. Add container image `ghcr.io/j-a-r-n-i-s/honeypot:latest` (or import the tar)
3. Environment: paste the Install-tab variables
4. Publish ports **22 → 22**, **23 → 23**, **80 → 80**
5. Resources: **128 MB RAM**, 0.25 CPU is enough. No privileged mode. No host network.
6. Access rule: WAN → this firewall, TCP 22 / 23 / 80

## 3. Check it works

- Sensor log: `config ok` then `sensor up`
- From another host: `ssh anything@FIREWALL_IP` — login **fails**, dashboard shows the attempt
- `curl http://FIREWALL_IP/` — login page from your Designs tab
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
| `HONEYPOT_TOKEN` | **yes** | full `hpt_…` (only required value) |
| `JARNIS_API` | no | `https://jarnis.io/api` |
| `HONEYPOT_ID` | no | filled from config poll if omitted |
| `UPDATE_INTERVAL` | no | `300` (min 30) |
| `SSH_CONTAINER_PORT` | no | `22` |
| `TELNET_CONTAINER_PORT` | no | `23` |
| `HTTP_CONTAINER_PORT` | no | `80` |
| `SSH_HOST_KEY` | no | `/var/lib/jarnis-honeypot/ssh_host_ecdsa` |

Host publish ports are Docker/firewall mappings, not process env. Changing listen ports needs a container recreate; banners/designs do not.

## Container registry

Customers pull **without login** once the GHCR package is set to Public:

```bash
docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest
```

CI (`.github/workflows/image.yml`) rebuilds `:latest` on every `main` push. Docker Hub can wait. See `DOCKERHUB.md`.
