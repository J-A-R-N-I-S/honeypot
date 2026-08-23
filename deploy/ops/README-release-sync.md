# Hub release sync (API host)

Replaces the old **GHCR** `jarnis-honeypot-release-sync` that rewrote `/etc/jarnis/honeypot_release.php` from `ghcr.io/...`.

## After website #56
The API prefers `deploy/release.json` on the honeypot repo directly. This sync is **optional** (local `/etc` mirror for tags). Do **not** set `'force' => true` or you reintroduce a pin race.

## Install (Matrix)
```bash
install -m 0755 deploy/ops/jarnis-honeypot-release-sync.sh /usr/local/sbin/
install -m 0644 deploy/ops/jarnis-honeypot-release-sync.service /etc/systemd/system/
install -m 0644 deploy/ops/jarnis-honeypot-release-sync.timer /etc/systemd/system/
# Disable/remove the old GHCR unit/timer first
systemctl disable --now jarnis-honeypot-release-sync.timer 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now jarnis-honeypot-release-sync.timer
systemctl start jarnis-honeypot-release-sync.service
```
