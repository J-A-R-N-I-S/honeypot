# JARNIS honeypot

Capture-only SSH, Telnet and HTTP sensor. Attackers never get a shell or a web session. Usernames, passwords and source IPs go to the [JARNIS](https://jarnis.io) dashboard over HTTPS.

Image: [`ghcr.io/j-a-r-n-i-s/honeypot:latest`](https://github.com/orgs/J-A-R-N-I-S/packages/container/package/honeypot) (~8 MB, linux/amd64). Fits Barracuda CloudGen Edge (128 MB, not privileged).

## Deploy

1. In https://jarnis.io → **Honeypots** register a sensor and **copy the `hpt_…` token once** (create or rotate).
2. Set banners and HTTP designs under Configure.
3. Start the container — only the token is required:

```bash
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  ghcr.io/j-a-r-n-i-s/honeypot:latest
```

Or `cp examples/env.example .env` and `docker compose up -d`.

### Barracuda CloudGen Edge

Leave the start command empty (image entrypoint `/jarnis-honeypot`). Environment: `HONEYPOT_TOKEN` only. Publish **22→22, 23→23, 8080→8080**. Access-Rule WAN TCP 22 / 23 / 8080. Outbound HTTPS to `jarnis.io` (TCP 443).

## Check

- Log: `config ok` then `sensor up`
- `ssh user@FIREWALL_IP` — login fails, dashboard shows the attempt
- `curl http://FIREWALL_IP:8080/` — login page from Designs
- Banner/design changes apply on the next config poll (default 5 min). Port changes need a recreate.

## Environment

| Variable | Required | Default |
|----------|----------|---------|
| `HONEYPOT_TOKEN` | **yes** | full `hpt_…` from create/rotate |
| `JARNIS_API` | no | `https://jarnis.io/api` |
| `HONEYPOT_ID` | no | learned from the first config poll |
| `UPDATE_INTERVAL` | no | `300` (minimum 30) |
| `SSH_CONTAINER_PORT` | no | `22` |
| `TELNET_CONTAINER_PORT` | no | `23` |
| `HTTP_CONTAINER_PORT` | no | `8080` |
| `SSH_HOST_KEY` | no | `/var/lib/jarnis-honeypot/ssh_host_ecdsa` |
| `JARNIS_API_IP` | no | `116.204.196.220` (TLS name stays `jarnis.io`) |

`${HONEYPOT_TOKEN}` in the Install tab is a placeholder, not a secret.

## Behaviour

| Does | Does not |
|------|----------|
| Fake SSH / Telnet / HTTP :8080 | Grant a shell, TTY, or cookie |
| HTTPS backhaul of user, password, IP, UA | Store loot on the firewall |
| Poll banners and HTML designs | Run attacker commands |

## Develop

```bash
go test ./...
go build -o dist/jarnis-honeypot ./cmd/jarnis-honeypot
```

CI on `main` runs tests and publishes `:latest` plus the short commit SHA to GHCR.

## License

MIT — see `LICENSE`.
