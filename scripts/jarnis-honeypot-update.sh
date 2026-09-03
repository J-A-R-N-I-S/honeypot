#!/bin/sh
# Host-side updater for JARNIS honeypot containers.
# Pulls Docker Hub jarnis/honeypot:latest and recreates only matching
# containers whose image digest changed. Runs on the VPS — never inside
# the honeypot (no docker.sock in the image, not Watchtower).
#
# Discover: label com.jarnis.honeypot=1, or Config.Image is Hub
# jarnis/honeypot[:tag]. Never GHCR. Never unrelated containers.
# Multiple containers on one host are updated independently (ports/env kept).
#
# Ubuntu install (systemd timer, daily including weekends):
#   curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.sh -o /usr/local/sbin/jarnis-honeypot-update
#   chmod 755 /usr/local/sbin/jarnis-honeypot-update
#   curl -fsSL https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/systemd/jarnis-honeypot-update.service \
#     -o /etc/systemd/system/jarnis-honeypot-update.service
#   curl -fsSL https://raw.githubusercontent.com/J-A-R-N-I-S/honeypot/main/deploy/systemd/jarnis-honeypot-update.timer \
#     -o /etc/systemd/system/jarnis-honeypot-update.timer
#   systemctl daemon-reload && systemctl enable --now jarnis-honeypot-update.timer
#
# Cron fallback (no systemd):
#   echo '20 4 * * * root /usr/local/sbin/jarnis-honeypot-update' > /etc/cron.d/jarnis-honeypot-update
#
# Disable: systemctl disable --now jarnis-honeypot-update.timer
#          rm -f /etc/cron.d/jarnis-honeypot-update
#
# Optional /etc/jarnis-honeypot-update.conf:
#   IMAGE=jarnis/honeypot:latest
#   NAME=jarnis-honeypot          # optional: only this container
#   ENV_FILE=/root/jarnis-honeypot.env  # used only when NAME is set
set -eu

CONF=/etc/jarnis-honeypot-update.conf
if [ -f "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF"
fi
IMAGE=${IMAGE:-jarnis/honeypot:latest}
NAME=${NAME:-}
ENV_FILE=${ENV_FILE:-/root/jarnis-honeypot.env}

log() { echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*"; }

hub_image() {
    img=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    case "$img" in
        *ghcr.io*) return 1 ;;
        jarnis/honeypot|jarnis/honeypot:*|jarnis/honeypot@*|docker.io/jarnis/honeypot|docker.io/jarnis/honeypot:*|docker.io/jarnis/honeypot@*) return 0 ;;
    esac
    return 1
}

is_jarnis_honeypot() {
    cid=$1
    lbl=$(docker inspect --format '{{index .Config.Labels "com.jarnis.honeypot"}}' "$cid" 2>/dev/null || true)
    case "$lbl" in
        1|true|yes) return 0 ;;
    esac
    cfg=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || true)
    hub_image "$cfg"
}

container_envfile() {
    cid=$1
    cname=$2
    tmp=$3
    if [ -n "$NAME" ] && [ "$cname" = "$NAME" ] && [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "$tmp"
        chmod 600 "$tmp"
        return 0
    fi
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" \
        | awk -F= '
            $1=="PATH" || $1=="HOME" || $1=="HOSTNAME" || $1=="TERM" { next }
            NF>=1 && $1!="" { print }
          ' > "$tmp"
    chmod 600 "$tmp"
    if ! grep -q '^HONEYPOT_TOKEN=' "$tmp" 2>/dev/null; then
        log "skip $cname — no HONEYPOT_TOKEN in container env"
        rm -f "$tmp"
        return 1
    fi
    return 0
}

published_ports() {
    cid=$1
    docker inspect --format '{{range $p, $c := .HostConfig.PortBindings}}{{range $c}}-p {{if .HostIp}}{{.HostIp}}:{{end}}{{.HostPort}}:{{$p}} {{end}}{{end}}' "$cid" \
        | sed 's#/tcp##g; s#/udp##g'
}

recreate() {
    cid=$1
    cname=$2
    new_id=$3

    ports=$(published_ports "$cid")
    if [ -z "$(printf '%s' "$ports" | tr -d '[:space:]')" ]; then
        log "skip $cname — no published ports"
        return 1
    fi
    tmpenv=$(mktemp /tmp/jarnis-hp-env.XXXXXX)
    chmod 600 "$tmpenv"
    if ! container_envfile "$cid" "$cname" "$tmpenv"; then
        rm -f "$tmpenv"
        return 1
    fi

    old="${cname}.jarnis-prev.$$"
    log "updating $cname"
    docker stop "$cname" >/dev/null
    docker rename "$cname" "$old"
    # word-splitting of ports is intentional (docker -p repeats)
    # shellcheck disable=SC2086
    if docker run -d --name "$cname" --restart unless-stopped \
        --memory 64m --cpus 0.25 \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --tmpfs /tmp:size=8m,mode=1777 \
        --label com.jarnis.honeypot=1 \
        --env-file "$tmpenv" \
        $ports \
        "$IMAGE" >/dev/null; then
        docker rm "$old" >/dev/null
        rm -f "$tmpenv"
        log "recreated $cname ($new_id)"
        return 0
    fi
    docker rm -f "$cname" >/dev/null 2>&1 || true
    docker rename "$old" "$cname" >/dev/null 2>&1 || true
    docker start "$cname" >/dev/null 2>&1 || true
    rm -f "$tmpenv"
    log "recreate failed $cname — previous container restored"
    return 1
}

if ! command -v docker >/dev/null 2>&1; then
    log "docker not found"
    exit 1
fi

case "$IMAGE" in
    *ghcr.io*)
        log "IMAGE must be Docker Hub jarnis/honeypot (got $IMAGE)"
        exit 1
        ;;
esac

if ! docker pull "$IMAGE" >/dev/null; then
    log "pull failed $IMAGE"
    exit 1
fi
NEW=$(docker inspect --format '{{.Id}}' "$IMAGE")

ids=$(docker ps -aq)
if [ -z "$ids" ]; then
    log "no containers — skip"
    exit 0
fi

found=0
updated=0
for cid in $ids; do
    cname=$(docker inspect --format '{{.Name}}' "$cid" | sed 's#^/##')
    if [ -n "$NAME" ] && [ "$cname" != "$NAME" ]; then
        continue
    fi
    if ! is_jarnis_honeypot "$cid"; then
        continue
    fi
    found=$((found + 1))
    old=$(docker inspect --format '{{.Image}}' "$cid")
    if [ "$old" = "$NEW" ]; then
        log "up to date $cname"
        continue
    fi
    if recreate "$cid" "$cname" "$NEW"; then
        updated=$((updated + 1))
    fi
done

if [ "$found" -eq 0 ]; then
    log "no JARNIS honeypot containers — skip"
    exit 0
fi
log "done found=$found updated=$updated"
exit 0
