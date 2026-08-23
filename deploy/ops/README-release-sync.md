# Hub release sync (API host)

Replaces the old **GHCR** sync that did `git ls-remote` on `main` and wrote
`image => ghcr.io/j-a-r-n-i-s/honeypot:latest`.

## Paths (match production)
| | |
|--|--|
| Script | `/usr/local/sbin/jarnis-honeypot-release-sync` |
| Cron | `/etc/cron.d/jarnis-honeypot-release` |
| Output | `/etc/jarnis/honeypot_release.php` |
| Log | `/var/log/jarnis/honeypot-release.log` |

## After website #56
API prefers Hub `deploy/release.json` directly. This sync is an optional `/etc`
mirror. **Never** set `'force' => true` in the written file.

## Install (Matrix)
```bash
# Keep GHCR cron paused until this is in place
install -m 0755 deploy/ops/jarnis-honeypot-release-sync /usr/local/sbin/
# dry-run
JARNIS_HONEYPOT_RELEASE_OUT=/tmp/honeypot_release.php /usr/local/sbin/jarnis-honeypot-release-sync
# swap cron (remove .off / .disabled*)
install -m 0644 deploy/ops/jarnis-honeypot-release.cron /etc/cron.d/jarnis-honeypot-release
# or: run once into real OUT
/usr/local/sbin/jarnis-honeypot-release-sync
```

Source of truth: `https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/release.json`
