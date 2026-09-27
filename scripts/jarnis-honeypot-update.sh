#!/bin/sh
# Host-side updater for JARNIS honeypot containers.
# Pulls Docker Hub jarnis/honeypot:latest and recreates only matching
# containers whose image digest changed. Runs on the VPS — never inside
# the honeypot (no docker.sock in the image, not Watchtower).
#
# Discover: label com.jarnis.honeypot=1, or Config.Image is Hub
# jarnis/honeypot[:tag]. Never GHCR. Never unrelated containers.
# Multiple containers on one host are updated independently (ports/env and
# mounts kept). The SSH host key lives in /var/lib/jarnis-honeypot; if the old
# container had no mount there, a named volume is added so the fingerprint
# survives future recreates (jarnis-honeypot-state for the container named
# jarnis-honeypot, jarnis-honeypot-state-<name> for any other container).
#
# Ubuntu install (systemd timer, daily including weekends):
#   curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.sh -o /usr/local/sbin/jarnis-honeypot-update
#   chmod 755 /usr/local/sbin/jarnis-honeypot-update
#   curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.service \
#     -o /etc/systemd/system/jarnis-honeypot-update.service
#   curl -fsSL https://jarnis.io/guides/jarnis-honeypot-update.timer \
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
# No globbing: mount paths and port specs are word-split on purpose below.
set -f

CONF=/etc/jarnis-honeypot-update.conf
if [ -f "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF"
fi
IMAGE=${IMAGE:-jarnis/honeypot:latest}
NAME=${NAME:-}
ENV_FILE=${ENV_FILE:-/root/jarnis-honeypot.env}
STATE_DIR=/var/lib/jarnis-honeypot

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

# Prints one "-v SRC:DST[:ro]" per mount of the old container (named volumes,
# anonymous volumes by their generated name, and bind mounts). tmpfs mounts
# are skipped (the fixed --tmpfs /tmp below replaces them). Returns 1 on a
# path that cannot be passed through -v safely (whitespace, comma, colon).
carried_mounts() {
    cid=$1
    docker inspect --format '{{range .Mounts}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}|{{.Destination}}|{{.RW}}{{println}}{{end}}' "$cid" \
        | awk -F'|' '
            NF == 0 || $0 == "" { next }
            $1 != "volume" && $1 != "bind" { next }
            $2 == "" || $3 == "" { bad = 1; next }
            $2 ~ /[[:space:],:]/ || $3 ~ /[[:space:],:]/ { bad = 1; next }
            { printf "-v %s:%s%s\n", $2, $3, ($4 == "false" ? ":ro" : "") }
            END { exit bad }
          '
}

default_state_volume() {
    cname=$1
    if [ "$cname" = "jarnis-honeypot" ]; then
        echo "jarnis-honeypot-state"
    else
        echo "jarnis-honeypot-state-$(printf '%s' "$cname" | tr -c 'A-Za-z0-9_.-' '-')"
    fi
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

    if ! mounts=$(carried_mounts "$cid"); then
        log "skip $cname — mount path not supported by the updater (whitespace, comma or colon)"
        rm -f "$tmpenv"
        return 1
    fi
    migrate_key=0
    if ! printf '%s\n' "$mounts" | grep -q ":${STATE_DIR}\(:ro\)\{0,1\}\$"; then
        vol=$(default_state_volume "$cname")
        mounts="$mounts -v ${vol}:${STATE_DIR}"
        migrate_key=1
        log "$cname has no mount on $STATE_DIR — adding volume $vol (keeps the SSH host key)"
    fi

    old="${cname}.jarnis-prev.$$"
    log "updating $cname"
    docker stop "$cname" >/dev/null
    docker rename "$cname" "$old"
    # word-splitting of ports and mounts is intentional (docker -p / -v repeat)
    # shellcheck disable=SC2086
    if docker create --name "$cname" --restart unless-stopped \
        --memory 64m --cpus 0.25 --pids-limit 64 \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --tmpfs /tmp:size=8m,mode=1777 \
        --label com.jarnis.honeypot=1 \
        --env-file "$tmpenv" \
        $ports \
        $mounts \
        "$IMAGE" >/dev/null; then
        if [ "$migrate_key" -eq 1 ]; then
            # Old container without a state mount: if it was not --read-only,
            # its host key sits in its writable layer. Seed the new volume so
            # the fingerprint does not change. Best effort; a fresh volume that
            # stays empty makes the sensor generate (and now persist) a key.
            keytar=$(mktemp /tmp/jarnis-hp-key.XXXXXX)
            chmod 600 "$keytar"
            if docker cp "$old:${STATE_DIR}/ssh_host_ecdsa" - >"$keytar" 2>/dev/null \
                && [ -s "$keytar" ] \
                && docker cp - "$cname:${STATE_DIR}/" <"$keytar" 2>/dev/null; then
                log "carried SSH host key from $cname into the state volume"
            else
                log "no persisted SSH host key in $cname — a new key is generated once and kept from now on"
            fi
            rm -f "$keytar"
        fi
        if docker start "$cname" >/dev/null; then
            docker rm "$old" >/dev/null
            rm -f "$tmpenv"
            log "recreated $cname ($new_id)"
            return 0
        fi
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
