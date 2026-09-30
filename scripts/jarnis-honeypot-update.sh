#!/bin/sh
# Host-side updater for JARNIS honeypot containers.
# Pulls Docker Hub jarnis/honeypot:latest and recreates only matching
# containers whose image digest changed. Runs on the VPS — never inside
# the honeypot (no docker.sock in the image, not Watchtower).
#
# Discover: label com.jarnis.honeypot=1, or Config.Image is Hub
# jarnis/honeypot[:tag]. Never GHCR. Never unrelated containers.
# Multiple containers on one host are updated independently.
#
# Carried over from the old container (docker inspect):
#   env (incl. HONEYPOT_TOKEN), published ports (tcp/udp, host IP incl. IPv6),
#   volumes and bind mounts (ro/rw), network mode, labels, log driver/options,
#   hostname/domainname (if set explicitly), --dns/--dns-search/--dns-option,
#   --add-host.
# Always set to the hardened defaults (not carried over):
#   --restart unless-stopped, --memory 64m, --cpus 0.25, --pids-limit 64,
#   --read-only, --cap-drop ALL, --security-opt no-new-privileges:true,
#   --tmpfs /tmp:size=8m,mode=1777.
# Not carried over: additional networks / aliases / static IPs, user,
#   entrypoint/cmd, workdir, sysctls, ulimits, devices, other tmpfs mounts.
#
# The SSH host key lives in /var/lib/jarnis-honeypot. If the old container had
# no mount there, a named volume is added so the fingerprint survives future
# recreates (jarnis-honeypot-state for the container named jarnis-honeypot,
# jarnis-honeypot-state-<name> for any other container).
#
# Safety: one run at a time (flock on $LOCK_FILE). The old container is only
# removed after the new one has been running for $HEALTH_WAIT seconds (min 3)
# without a restart; a sensor that was stopped is recreated but not started
# (no health gate). Otherwise, on any error, or on SIGHUP/SIGINT/SIGTERM, the
# old container (tracked by ID, never by name) is restarted by ID (if it was
# running) and renamed back where possible; the log and exit code say whether
# the restore fully succeeded.
# Exit status: 0 = every matching container is up to date and running,
# recreated or skipped by policy; 1 = at least one recreate failed, or a
# container with the current image is not running (see the log; set
# ALLOW_STOPPED=1 for sensors that are stopped on purpose).
# A container that a failed `docker create` left behind is recognised by the
# unique com.jarnis.update-run label of that attempt and removed on rollback.
# com.docker.compose.* labels are not carried over: after an update a
# compose-managed sensor is a plain container (see README).
#
# Ubuntu install (systemd timer, daily including weekends). Verify the
# SHA-256 sums published in the guide / README before installing:
#   https://jarnis.io/guides/honeypot-auto-update.html
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
#   HEALTH_WAIT=8                 # seconds the new container must stay up (min 3)
#   LOCK_FILE=/run/jarnis-honeypot-update.lock
#   ALLOW_STOPPED=0               # 1: a stopped sensor with the current image
#                                 # is only a warning (default: run fails)
#
# Running manually as a non-root member of the docker group: /run is not
# writable, so set a lock file you own, e.g.
#   LOCK_FILE=$XDG_RUNTIME_DIR/jarnis-honeypot-update.lock jarnis-honeypot-update
set -eu
# No globbing: port, mount and option lists are word-split on purpose below.
set -f
# Temp files hold the token / host key: owner-only.
umask 077

CONF=/etc/jarnis-honeypot-update.conf
if [ -f "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF"
fi
IMAGE=${IMAGE:-jarnis/honeypot:latest}
NAME=${NAME:-}
ENV_FILE=${ENV_FILE:-/root/jarnis-honeypot.env}
HEALTH_WAIT=${HEALTH_WAIT:-8}
LOCK_FILE=${LOCK_FILE:-/run/jarnis-honeypot-update.lock}
ALLOW_STOPPED=${ALLOW_STOPPED:-0}
STATE_DIR=/var/lib/jarnis-honeypot

log() { echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*"; }

case "$HEALTH_WAIT" in
    ''|*[!0-9]*) log "HEALTH_WAIT must be a number of seconds (got $HEALTH_WAIT)"; exit 1 ;;
esac
if [ "$HEALTH_WAIT" -lt 3 ]; then
    log "WARNING: HEALTH_WAIT=$HEALTH_WAIT is too short to catch a crash loop — using 3"
    HEALTH_WAIT=3
fi

# --- rollback state for the recreate in progress (IDs, never names) ---------
RB_NAME=""        # original container name
RB_OLD=""         # original container ID (set once it has been stopped)
RB_NEW=""         # ID of the container created by this run
RB_WAS_RUNNING=0
RB_TOKEN=""       # value of the com.jarnis.update-run label of this recreate
RUN_SEQ=0
WORKDIR=""

# Returns 0 only if the original container is back under its name (and
# running, if it was running before). If it was running, it is restarted by
# ID even when the rename back fails, so the sensor keeps capturing (under
# the wrong name) instead of staying silently stopped.
rollback() {
    rb_ok=0
    if [ -n "$RB_NEW" ]; then
        docker rm -f "$RB_NEW" >/dev/null 2>&1 || log "WARNING: could not remove new container $RB_NEW"
    elif [ -n "$RB_TOKEN" ]; then
        # docker create failed half-way: a container carrying this recreate's
        # unique label may still hold the name and block the rename back.
        for half in $(docker ps -aq --filter "label=com.jarnis.update-run=$RB_TOKEN" 2>/dev/null || true); do
            if [ "$half" != "$RB_OLD" ]; then
                if docker rm -f "$half" >/dev/null 2>&1; then
                    log "removed half-created container $half"
                else
                    log "WARNING: could not remove half-created container $half"
                fi
            fi
        done
    fi
    if [ -n "$RB_OLD" ]; then
        rb_exists=1
        cur=$(docker inspect --format '{{.Name}}' "$RB_OLD" 2>/dev/null | sed 's#^/##' || true)
        if [ -z "$cur" ]; then
            log "ERROR: previous container $RB_OLD no longer exists"
            rb_ok=1
            rb_exists=0
        elif [ "$cur" != "$RB_NAME" ]; then
            if ! docker rename "$RB_OLD" "$RB_NAME" >/dev/null 2>&1; then
                log "ERROR: could not rename $RB_OLD back to $RB_NAME (it keeps the name $cur)"
                rb_ok=1
            fi
        fi
        if [ "$rb_exists" -eq 1 ] && [ "$RB_WAS_RUNNING" = 1 ]; then
            if docker start "$RB_OLD" >/dev/null 2>&1; then
                if [ "$rb_ok" -ne 0 ]; then
                    log "previous container $RB_OLD restarted by ID under the name $cur"
                fi
            else
                log "ERROR: could not start previous container $RB_NAME ($RB_OLD)"
                rb_ok=1
            fi
        fi
    fi
    RB_NAME=""
    RB_OLD=""
    RB_NEW=""
    RB_TOKEN=""
    RB_WAS_RUNNING=0
    return "$rb_ok"
}

# rollback + log the actual outcome
restore_previous() {
    rname=$RB_NAME
    if rollback; then
        log "previous container $rname restored"
    else
        log "ERROR: previous container $rname NOT fully restored — check 'docker ps -a'"
    fi
}

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ -n "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}

# shellcheck disable=SC2329  # invoked via trap
on_signal() {
    trap - HUP INT TERM
    if [ -n "$RB_OLD" ] || [ -n "$RB_NEW" ]; then
        log "interrupted — restoring $RB_NAME"
        restore_previous
    else
        log "interrupted"
    fi
    exit 1
}

trap cleanup EXIT
trap on_signal HUP INT TERM

hub_image() {
    img=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
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
    if ! raw=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid"); then
        log "skip $cname — docker inspect (env) failed"
        return 1
    fi
    printf '%s\n' "$raw" | awk -F= '
            $1=="PATH" || $1=="HOME" || $1=="HOSTNAME" || $1=="TERM" { next }
            NF>=1 && $1!="" { print }
          ' > "$tmp"
    chmod 600 "$tmp"
    if ! grep -q '^HONEYPOT_TOKEN=' "$tmp" 2>/dev/null; then
        log "skip $cname — no HONEYPOT_TOKEN in container env"
        return 2
    fi
    return 0
}

# One "-p" per binding. Keeps the protocol (22/tcp, 53/udp) and the host IP;
# IPv6 host addresses are bracketed ([::]:22:22/tcp).
published_ports() {
    raw=$(docker inspect --format '{{range $p, $c := .HostConfig.PortBindings}}{{range $c}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{println}}{{end}}{{end}}' "$1") || return 1
    printf '%s\n' "$raw" | awk -F'|' '
        NF != 3 || $3 == "" { next }
        {
            ip = $1
            if (ip ~ /:/) ip = "[" ip "]"
            if (ip != "") printf "-p %s:%s:%s\n", ip, $2, $3
            else if ($2 != "") printf "-p %s:%s\n", $2, $3
            else printf "-p %s\n", $3
        }'
}

# One "-v SRC:DST[:ro]" per mount (named volumes, anonymous volumes by their
# generated name, bind mounts). tmpfs mounts are skipped (the fixed
# --tmpfs /tmp replaces them). Exit 2: inspect failed. Exit 1: a path that
# cannot be passed through -v safely (whitespace, comma, colon).
carried_mounts() {
    raw=$(docker inspect --format '{{range .Mounts}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}|{{.Destination}}|{{.RW}}{{println}}{{end}}' "$1") || return 2
    printf '%s\n' "$raw" | awk -F'|' '
        $0 == "" { next }
        $1 != "volume" && $1 != "bind" { next }
        $2 == "" || $3 == "" { bad = 1; next }
        $2 ~ /[[:space:],:]/ || $3 ~ /[[:space:],:]/ { bad = 1; next }
        { printf "-v %s:%s%s\n", $2, $3, ($4 == "false" ? ":ro" : "") }
        END { exit bad }
      '
}

# Network mode, hostname/domainname (only if set explicitly), log driver and
# options, DNS settings and extra hosts. Exit 2: inspect failed. Exit 1: a
# value with whitespace (cannot be word-split safely).
carried_options() {
    cid=$1
    daemon_log=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || true)
    raw=$(docker inspect --format 'net|{{.HostConfig.NetworkMode}}
host|{{.Config.Hostname}}
domain|{{.Config.Domainname}}
logdrv|{{.HostConfig.LogConfig.Type}}
{{range $k, $v := .HostConfig.LogConfig.Config}}logopt|{{$k}}={{$v}}
{{end}}{{range .HostConfig.Dns}}dns|{{.}}
{{end}}{{range .HostConfig.DnsSearch}}dnssearch|{{.}}
{{end}}{{range .HostConfig.DnsOptions}}dnsopt|{{.}}
{{end}}{{range .HostConfig.ExtraHosts}}addhost|{{.}}
{{end}}' "$cid") || return 2
    printf '%s\n' "$raw" | awk -F'|' -v short="$(printf '%.12s' "$cid")" -v dlog="$daemon_log" '
        $0 == "" { next }
        {
            k = $1; v = substr($0, length(k) + 2)
            if (v == "") next
            if (v ~ /[[:space:]]/) { bad = 1; next }
        }
        k == "net"      { if (v == "host" || v ~ /^container:/) sharedns = 1
                          if (v != "default" && v != "bridge") print "--network " v; next }
        k == "host"     { if (v != short && !sharedns) print "--hostname " v; next }
        k == "domain"   { if (!sharedns) print "--domainname " v; next }
        k == "logdrv"   { if (v != dlog) print "--log-driver " v; next }
        k == "logopt"   { print "--log-opt " v; next }
        k == "dns"      { print "--dns " v; next }
        k == "dnssearch"{ print "--dns-search " v; next }
        k == "dnsopt"   { print "--dns-option " v; next }
        k == "addhost"  { print "--add-host " v; next }
        END { exit bad }
      '
}

# Labels set on the container (not inherited from its image) as a label file.
# com.jarnis.honeypot is always set by recreate itself; com.docker.compose.*
# labels are dropped (the recreated container is not managed by compose).
container_labels() {
    cid=$1
    out=$2
    # shellcheck disable=SC2016  # Go template, not shell expansion
    fmt='{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{println}}{{end}}'
    img=$(docker inspect --format '{{.Image}}' "$cid") || return 1
    docker inspect --format "$fmt" "$cid" > "$out.c" || return 1
    docker image inspect --format "$fmt" "$img" > "$out.i" 2>/dev/null || : > "$out.i"
    grep -vxF -f "$out.i" "$out.c" | grep -v -e '^com\.jarnis\.honeypot=' -e '^com\.jarnis\.update-run=' -e '^com\.docker\.compose\.' -e '^$' > "$out" || true
    rm -f "$out.c" "$out.i"
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

    if ! ports=$(published_ports "$cid"); then
        log "skip $cname — docker inspect (ports) failed"
        return 1
    fi
    if [ -z "$(printf '%s' "$ports" | tr -d '[:space:]')" ]; then
        log "skip $cname — no published ports"
        return 2
    fi
    envf="$WORKDIR/env"
    rm -f "$envf"
    rc=0
    container_envfile "$cid" "$cname" "$envf" || rc=$?
    if [ "$rc" -ne 0 ]; then
        return "$rc"
    fi
    rc=0
    mounts=$(carried_mounts "$cid") || rc=$?
    if [ "$rc" -eq 2 ]; then
        log "skip $cname — docker inspect (mounts) failed"
        return 1
    elif [ "$rc" -ne 0 ]; then
        log "skip $cname — mount path not supported by the updater (whitespace, comma or colon)"
        return 2
    fi
    rc=0
    opts=$(carried_options "$cid") || rc=$?
    if [ "$rc" -eq 2 ]; then
        log "skip $cname — docker inspect (options) failed"
        return 1
    elif [ "$rc" -ne 0 ]; then
        log "skip $cname — network/log/DNS option with whitespace not supported by the updater"
        return 2
    fi
    labelf="$WORKDIR/labels"
    if ! container_labels "$cid" "$labelf"; then
        log "skip $cname — docker inspect (labels) failed"
        return 1
    fi
    if ! running=$(docker inspect --format '{{.State.Running}}' "$cid"); then
        log "skip $cname — docker inspect (state) failed"
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
    RB_NAME=$cname
    RUN_SEQ=$((RUN_SEQ + 1))
    RB_TOKEN="$(date +%s).$$.$RUN_SEQ"
    RB_WAS_RUNNING=0
    [ "$running" = "true" ] && RB_WAS_RUNNING=1
    if ! docker stop "$cid" >/dev/null; then
        log "abort $cname — docker stop failed, container left as is"
        if [ "$RB_WAS_RUNNING" = 1 ]; then
            docker start "$cid" >/dev/null 2>&1 || true
        fi
        RB_NAME=""
        RB_TOKEN=""
        return 1
    fi
    # From here on rollback() restores the original, addressed by its ID.
    RB_OLD=$cid
    if ! docker rename "$cid" "$old" >/dev/null; then
        log "abort $cname — docker rename failed"
        restore_previous
        return 1
    fi
    # word-splitting of ports/mounts/opts is intentional (repeated flags)
    # shellcheck disable=SC2086
    if ! new_cid=$(docker create --name "$cname" --restart unless-stopped \
        --memory 64m --cpus 0.25 --pids-limit 64 \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --tmpfs /tmp:size=8m,mode=1777 \
        --label-file "$labelf" \
        --label com.jarnis.honeypot=1 \
        --label "com.jarnis.update-run=$RB_TOKEN" \
        --env-file "$envf" \
        $opts \
        $ports \
        $mounts \
        "$IMAGE") || [ -z "$new_cid" ]; then
        log "recreate failed $cname — docker create failed"
        restore_previous
        return 1
    fi
    RB_NEW=$new_cid
    rm -f "$envf"

    if [ "$migrate_key" -eq 1 ]; then
        # Old container without a state mount: if it was not --read-only,
        # its host key sits in its writable layer. Seed the new volume so
        # the fingerprint does not change. Best effort; a fresh volume that
        # stays empty makes the sensor generate (and now persist) a key.
        keytar="$WORKDIR/key.tar"
        if docker cp "$cid:${STATE_DIR}/ssh_host_ecdsa" - >"$keytar" 2>/dev/null \
            && [ -s "$keytar" ] \
            && docker cp - "$new_cid:${STATE_DIR}/" <"$keytar" 2>/dev/null; then
            log "carried SSH host key from $cname into the state volume"
        else
            log "no persisted SSH host key in $cname — a new key is generated once and kept from now on"
        fi
        rm -f "$keytar"
    fi

    if [ "$RB_WAS_RUNNING" != 1 ]; then
        # The original was stopped: never start a stopped sensor. Keep the
        # new container created but stopped (no health gate — nothing runs)
        # and commit. The next run sees it with the current image and
        # applies the ALLOW_STOPPED check.
        RB_NAME=""
        RB_OLD=""
        RB_NEW=""
        RB_TOKEN=""
        if ! docker rm "$cid" >/dev/null; then
            log "WARNING: new $cname is created (stopped), but the previous container $cid could not be removed"
        fi
        log "recreated $cname ($new_id) — left stopped, as it was"
        return 0
    fi
    if ! docker start "$new_cid" >/dev/null; then
        log "recreate failed $cname — new container did not start"
        restore_previous
        return 1
    fi
    # Health gate: the new container must still be running, without a
    # restart, after HEALTH_WAIT seconds. Only then the old one is removed.
    sleep "$HEALTH_WAIT"
    st=$(docker inspect --format '{{.State.Running}} {{.RestartCount}}' "$new_cid" 2>/dev/null || true)
    if [ "$st" != "true 0" ]; then
        log "recreate failed $cname — new container not healthy after ${HEALTH_WAIT}s (running/restarts: ${st:-gone})"
        docker logs --tail 10 "$new_cid" 2>&1 | sed 's/^/  | /' || true
        restore_previous
        return 1
    fi
    # Healthy: commit. Clear the rollback state BEFORE touching the old
    # container, so a signal from here on never removes the new one.
    RB_NAME=""
    RB_OLD=""
    RB_NEW=""
    RB_TOKEN=""
    RB_WAS_RUNNING=0
    if ! docker rm "$cid" >/dev/null; then
        log "WARNING: new $cname is running, but the previous container $cid could not be removed"
    fi
    log "recreated $cname ($new_id)"
    return 0
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

# One run at a time (timer and manual run). Default lock in /run (root-owned
# 0755, same path under systemd and manually); not /tmp (the unit uses
# PrivateTmp=yes) and not /run/lock (world-writable: symlink/DoS by local
# users). Opened with <> (no truncation); symlinks are refused.
if command -v flock >/dev/null 2>&1; then
    if [ -L "$LOCK_FILE" ]; then
        log "refusing lock file $LOCK_FILE — it is a symlink"
        exit 1
    fi
    exec 9<>"$LOCK_FILE"
    if ! flock -n 9; then
        log "another jarnis-honeypot-update run holds $LOCK_FILE — exit"
        exit 0
    fi
else
    log "WARNING: flock not found — running without a lock"
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/jarnis-hp.XXXXXX")

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
failed=0
skipped=0
stopped=0
for cid in $ids; do
    cname=$(docker inspect --format '{{.Name}}' "$cid" | sed 's#^/##')
    case "$cname" in
        *.jarnis-prev.*)
            log "WARNING: leftover container $cname from an interrupted update — not touched. If it is running, it is the previous sensor restarted after a failed rename back: sort out the names by hand (docker ps -a)"
            continue
            ;;
    esac
    if [ -n "$NAME" ] && [ "$cname" != "$NAME" ]; then
        continue
    fi
    if ! is_jarnis_honeypot "$cid"; then
        continue
    fi
    found=$((found + 1))
    old=$(docker inspect --format '{{.Image}}' "$cid")
    if [ "$old" = "$NEW" ]; then
        # A stopped sensor under the name (e.g. left by a failed restore)
        # must not pass as "up to date": warn and fail the run.
        state=$(docker inspect --format '{{.State.Running}}' "$cid" 2>/dev/null || true)
        if [ "$state" != "true" ]; then
            if [ "$ALLOW_STOPPED" = 1 ]; then
                log "WARNING: $cname has the current image but is not running (ALLOW_STOPPED=1 — not failing)"
            else
                log "ERROR: $cname has the current image but is NOT running — check 'docker ps -a' and start it (docker start $cname); set ALLOW_STOPPED=1 if it is stopped on purpose"
                stopped=$((stopped + 1))
            fi
            continue
        fi
        log "up to date $cname"
        continue
    fi
    rc=0
    recreate "$cid" "$cname" "$NEW" || rc=$?
    case "$rc" in
        0) updated=$((updated + 1)) ;;
        2) skipped=$((skipped + 1)) ;;
        *) failed=$((failed + 1)) ;;
    esac
done

if [ "$found" -eq 0 ]; then
    log "no JARNIS honeypot containers — skip"
    exit 0
fi
log "done found=$found updated=$updated skipped=$skipped failed=$failed stopped=$stopped"
if [ "$failed" -gt 0 ] || [ "$stopped" -gt 0 ]; then
    exit 1
fi
exit 0
