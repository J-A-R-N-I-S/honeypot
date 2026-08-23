#!/usr/bin/env bash
# Pull jarnis/honeypot:latest when the digest changed; recreate the running container.
# Secrets stay in an env-file only — never passed as docker -e (no argv / ps leakage).
# Never prints secret values (no set -x; env contents are not echoed).
set -euo pipefail

CONF=/etc/jarnis-honeypot-update.conf
if [[ -f "$CONF" ]]; then
  # shellcheck disable=SC1090
  . "$CONF"
fi

IMAGE="${IMAGE:-jarnis/honeypot:latest}"
NAME="${NAME:-jarnis-honeypot}"
# Preferred: durable env file used at install (token never on cmdline).
ENV_FILE="${ENV_FILE:-/root/jarnis-honeypot.env}"

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

# Env: prefer durable ENV_FILE; else write Config.Env to a 0600 temp and --env-file it.
# Never use docker -e KEY=value (token would appear on process argv).
env_tmp=""
cleanup_env_tmp() {
  if [[ -n "${env_tmp}" && -f "${env_tmp}" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u "${env_tmp}" 2>/dev/null || rm -f "${env_tmp}"
    else
      rm -f "${env_tmp}"
    fi
  fi
}
trap cleanup_env_tmp EXIT

if [[ -f "$ENV_FILE" && -r "$ENV_FILE" ]]; then
  run_args+=(--env-file "$ENV_FILE")
else
  env_tmp="$(mktemp)"
  chmod 600 "$env_tmp"
  # Write env lines only into the file — do not echo them.
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" >"$env_tmp"
  run_args+=(--env-file "$env_tmp")
fi

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
