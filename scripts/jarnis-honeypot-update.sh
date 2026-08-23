#!/bin/sh
# Pull jarnis/honeypot:latest and recreate the container only when
# the image digest changed. Keeps name, published ports, memory and restart
# policy. Token stays in ENV_FILE — never printed.
#
# Install (preferred — systemd timer, every ~1 min, no-op if digest unchanged):
#   install -m 755 scripts/jarnis-honeypot-update.sh /usr/local/sbin/jarnis-honeypot-update
#   # or: curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.sh -o /usr/local/sbin/jarnis-honeypot-update && chmod 755 $_
#   install -m 644 deploy/systemd/jarnis-honeypot-update.service /etc/systemd/system/
#   install -m 644 deploy/systemd/jarnis-honeypot-update.timer /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now jarnis-honeypot-update.timer
#
# Cron fallback (optional):
#   echo '20 4,16 * * * root /usr/local/sbin/jarnis-honeypot-update' > /etc/cron.d/jarnis-honeypot-update
#
# Optional /etc/jarnis-honeypot-update.conf:
#   NAME=jarnis-honeypot
#   IMAGE=jarnis/honeypot:latest
#   ENV_FILE=/root/jarnis-honeypot.env
set -eu

CONF=/etc/jarnis-honeypot-update.conf
if [ -f "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF"
fi
NAME=${NAME:-jarnis-honeypot}
IMAGE=${IMAGE:-jarnis/honeypot:latest}
ENV_FILE=${ENV_FILE:-/root/jarnis-honeypot.env}

log() { echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*"; }

if ! command -v docker >/dev/null 2>&1; then
    log "docker not found"
    exit 1
fi
if ! docker inspect "$NAME" >/dev/null 2>&1; then
    log "no container $NAME — skip"
    exit 0
fi
if [ ! -f "$ENV_FILE" ]; then
    log "missing env file $ENV_FILE"
    exit 1
fi

OLD=$(docker inspect --format '{{.Image}}' "$NAME")
if ! docker pull "$IMAGE" >/dev/null; then
    log "pull failed $IMAGE"
    exit 1
fi
NEW=$(docker inspect --format '{{.Id}}' "$IMAGE")
if [ "$OLD" = "$NEW" ]; then
    log "up to date $NAME"
    exit 0
fi

PORTS=$(docker inspect --format '{{range $p, $c := .HostConfig.PortBindings}}{{range $c}}-p {{if .HostIp}}{{.HostIp}}:{{end}}{{.HostPort}}:{{$p}} {{end}}{{end}}' "$NAME" | sed 's#/tcp##g; s#/udp##g')
MEM=$(docker inspect --format '{{.HostConfig.Memory}}' "$NAME")
RESTART=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$NAME")
[ -n "$RESTART" ] && [ "$RESTART" != "no" ] || RESTART=unless-stopped
MEM_ARG=""
if [ -n "$MEM" ] && [ "$MEM" != "0" ]; then
    MEM_ARG="--memory ${MEM}"
fi

log "updating $NAME $OLD -> $NEW"
docker stop "$NAME" >/dev/null
docker rm "$NAME" >/dev/null
# word-splitting of PORTS / MEM_ARG is intentional
# shellcheck disable=SC2086
docker run -d --name "$NAME" --restart "$RESTART" $MEM_ARG \
    --env-file "$ENV_FILE" \
    $PORTS \
    "$IMAGE" >/dev/null
log "recreated $NAME"
docker image prune -f >/dev/null 2>&1 || true
exit 0
