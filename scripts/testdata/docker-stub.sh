#!/bin/sh
# Minimal stateful docker stand-in for update_script_test.go. State lives in
# $STUB_STATE/<id>/{name,image,running}. Only the commands and --format
# templates used by jarnis-honeypot-update.sh are implemented.
#   STUB_CREATE_FAIL_LEAVE=1  docker create registers a container under the
#                             target name, then fails (half-done create).
#   STUB_CREATE_FAIL=1        docker create fails cleanly.
#   STUB_RENAME_FAIL_TO=name  renaming any container to this name fails.
set -eu
S=$STUB_STATE
echo "$*" >> "$S/calls.log"

find_id() { # id or name -> id
    for d in "$S"/c/*; do
        [ -d "$d" ] || continue
        id=$(basename "$d")
        if [ "$id" = "$1" ] || [ "$(cat "$d/name")" = "$1" ]; then
            echo "$id"; return 0
        fi
    done
    return 1
}
name_taken() {
    for d in "$S"/c/*; do
        [ -d "$d" ] || continue
        [ "$(cat "$d/name")" = "$1" ] && return 0
    done
    return 1
}

cmd=$1; shift
case "$cmd" in
    pull) exit 0 ;;
    info) echo json-file; exit 0 ;;
    ps)
        want=""
        while [ $# -gt 0 ]; do
            case "$1" in --filter) want=${2#label=}; shift 2 ;; *) shift ;; esac
        done
        for d in "$S"/c/*; do
            [ -d "$d" ] || continue
            if [ -z "$want" ] || grep -qxF "$want" "$d/labels" 2>/dev/null; then
                basename "$d"
            fi
        done
        exit 0 ;;
    logs) exit 0 ;;
    image) exit 1 ;;  # image inspect: no image labels
    inspect)
        [ "$1" = "--format" ] || exit 1
        fmt=$2; ref=$3
        if [ "$ref" = "$STUB_IMAGE" ]; then echo "$STUB_NEW_ID"; exit 0; fi
        id=$(find_id "$ref") || { echo "no such container $ref" >&2; exit 1; }
        d="$S/c/$id"
        case "$fmt" in
            '{{.Name}}') echo "/$(cat "$d/name")" ;;
            '{{.Image}}') cat "$d/image" ;;
            '{{.State.Running}}') cat "$d/running" ;;
            '{{.State.Running}} {{.RestartCount}}') echo "$(cat "$d/running") 0" ;;
            *com.jarnis.honeypot*) sed -n 's/^com\.jarnis\.honeypot=//p' "$d/labels" ;;
            '{{.Config.Image}}') echo "other/image:latest" ;;
            *PortBindings*) echo "|2222|22/tcp" ;;
            *Config.Env*) printf 'HONEYPOT_TOKEN=hpt_stub\nPATH=/bin\n' ;;
            *Mounts*) echo "volume|jarnis-honeypot-state|/var/lib/jarnis-honeypot|true" ;;
            net*) printf 'net|bridge\nlogdrv|json-file\n' ;;
            *Config.Labels*) echo "com.jarnis.honeypot=1" ;;
            *) echo "stub: unknown format $fmt" >&2; exit 1 ;;
        esac
        exit 0 ;;
    stop)
        id=$(find_id "$1") || exit 1
        echo false > "$S/c/$id/running"; exit 0 ;;
    start)
        id=$(find_id "$1") || exit 1
        echo true > "$S/c/$id/running"; exit 0 ;;
    rename)
        id=$(find_id "$1") || exit 1
        if [ -n "${STUB_RENAME_FAIL_TO:-}" ] && [ "$2" = "$STUB_RENAME_FAIL_TO" ]; then
            echo "rename refused (stub)" >&2; exit 1
        fi
        if name_taken "$2"; then echo "name $2 in use" >&2; exit 1; fi
        echo "$2" > "$S/c/$id/name"; exit 0 ;;
    rm)
        [ "$1" = "-f" ] && shift
        id=$(find_id "$1") || exit 1
        rm -rf "${S:?}/c/$id"; exit 0 ;;
    create)
        name=""
        labels=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --name) name=$2; shift 2 ;;
                --label) labels="$labels$2
"; shift 2 ;;
                *) shift ;;
            esac
        done
        if name_taken "$name"; then echo "name $name in use" >&2; exit 1; fi
        if [ "${STUB_CREATE_FAIL:-0}" = 1 ]; then echo "create failed" >&2; exit 1; fi
        n=$(find "$S/c" -mindepth 1 -maxdepth 1 | wc -l | tr -d " ")
        id="new$n"
        mkdir -p "$S/c/$id"
        echo "$name" > "$S/c/$id/name"
        echo "$STUB_NEW_ID" > "$S/c/$id/image"
        echo false > "$S/c/$id/running"
        printf '%s' "$labels" > "$S/c/$id/labels"
        if [ "${STUB_CREATE_FAIL_LEAVE:-0}" = 1 ]; then
            echo "create failed half-way" >&2; exit 1
        fi
        echo "$id"; exit 0 ;;
    cp) exit 1 ;;
esac
echo "stub: unsupported docker $cmd" >&2
exit 1
