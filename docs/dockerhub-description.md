# jarnis/honeypot

Capture-only SSH, Telnet and HTTP honeypot for [JARNIS](https://jarnis.io). Attackers never get a shell or a cookie. Credentials go to jarnis.io over HTTPS.

**Full guide:** https://jarnis.io/guides/self-hosted-honeypot.html

## Quick start

1. In [jarnis.io](https://jarnis.io) → **Honeypots**, create or rotate a sensor and copy the full `hpt_…` token **once** from the modal (~52 characters). You will not see it again.
2. Run:

```bash
docker pull jarnis/honeypot:latest
docker run -d --name jarnis-honeypot --restart unless-stopped --memory 128m \
  -e HONEYPOT_TOKEN=hpt_… \
  -p 22:22 -p 23:23 -p 8080:8080 \
  jarnis/honeypot:latest
```

`${HONEYPOT_TOKEN}` in the app is a placeholder — paste the real token into `-e HONEYPOT_TOKEN=…`.

## Alternative registry

```bash
docker pull ghcr.io/j-a-r-n-i-s/honeypot:latest
```

Source and docs: https://github.com/J-A-R-N-I-S/honeypot