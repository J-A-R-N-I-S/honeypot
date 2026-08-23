#!/usr/bin/env bash
# Pull jarnis/honeypot:latest when the digest changed; recreate the running container.
# Never prints secret values (no set -x; env contents are not echoed).
set -euo pipefail

IMAGE="${IMAGE:-jarnis/honeypot:latest}"
NAME="${NAME:-jarnis-honeypot}"

log() { printf 'jarnis-honeypot-update: %s\n' "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required command: $1"
    exit 1
  }
}

need_cmd docker

before="$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)"
log "pulling $IMAGE"
docker pull "$IMAGE" >/dev/null
after="$(docker image inspect --format '{{.Id}}' "$IMAGE")"

if [[ -n "$before" && "$before" == "$after" ]]; then
  log "image unchanged"
  exit 0
fi

short="${after#sha256:}"
short="${short:0:12}"
log "new image id ${short}"

if ! docker container inspect "$NAME" >/dev/null 2>&1; then
  log "container $NAME not found — image pulled only"
  exit 0
fi

# Recreate preserving restart policy, memory limit, published ports, and env.
# Do not log env values.
restart="$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$NAME")"
memory="$(docker inspect --format '{{.HostConfig.Memory}}' "$NAME")"

run_args=(--name "$NAME" --detach)
if [[ -n "$restart" && "$restart" != "no" ]]; then
  run_args+=(--restart "$restart")
fi
if [[ -n "$memory" && "$memory" != "0" ]]; then
  run_args+=(--memory "$memory")
fi

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  # HostPort:containerPort[/proto] → strip /tcp (default)
  host="${line%%:*}"
  rest="${line#*:}"
  cport="${rest%%/*}"
  proto="${rest#*/}"
  if [[ "$proto" == "$rest" || "$proto" == "tcp" ]]; then
    run_args+=(-p "${host}:${cport}")
  else
    run_args+=(-p "${host}:${cport}/${proto}")
  fi
done < <(docker inspect --format '{{range $p, $conf := .HostConfig.PortBindings}}{{range $conf}}{{printf "%s:%s\n" .HostPort $p}}{{end}}{{end}}' "$NAME")

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  case "$line" in
    PATH=*|HOSTNAME=*|HOME=*|TERM=*) continue ;;
  esac
  run_args+=(-e "$line")
done < <(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$NAME")

bak="${NAME}.pre-update"
docker rename "$NAME" "$bak"
docker stop "$bak" >/dev/null

if ! docker run "${run_args[@]}" "$IMAGE"; then
  log "recreate failed — restoring previous container"
  docker rename "$bak" "$NAME" || true
  docker start "$NAME" || true
  exit 1
fi

docker rm "$bak" >/dev/null
log "recreated $NAME on $IMAGE"
