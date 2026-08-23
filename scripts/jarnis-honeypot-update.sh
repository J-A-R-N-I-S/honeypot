#!/usr/bin/env bash
# Pull jarnis/honeypot:latest and recreate the container only when the image id changed.
# Preserves name, PortBindings, Memory, RestartPolicy; env via --env-file only.
# Never prints env file contents or tokens.
set -euo pipefail

IMAGE="${IMAGE:-jarnis/honeypot:latest}"
NAME="${NAME:-jarnis-honeypot}"
ENV_FILE="${ENV_FILE:-/etc/jarnis/honeypot.env}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "env file missing: ${ENV_FILE}" >&2
  exit 1
fi

docker pull "$IMAGE" >/dev/null

new_id="$(docker image inspect --format '{{.Id}}' "$IMAGE")"

if ! docker inspect "$NAME" >/dev/null 2>&1; then
  echo "container ${NAME} not found; pull only (image ready)" >&2
  exit 0
fi

cur_id="$(docker inspect --format '{{.Image}}' "$NAME")"
if [[ "$cur_id" == "$new_id" ]]; then
  exit 0
fi

memory="$(docker inspect --format '{{.HostConfig.Memory}}' "$NAME")"
restart_name="$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$NAME")"
restart_max="$(docker inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$NAME")"

run_args=( -d --name "$NAME" --env-file "$ENV_FILE" )

if [[ -n "$restart_name" && "$restart_name" != "no" ]]; then
  if [[ "$restart_name" == "on-failure" && "$restart_max" != "0" ]]; then
    run_args+=( --restart "${restart_name}:${restart_max}" )
  else
    run_args+=( --restart "$restart_name" )
  fi
fi

if [[ -n "$memory" && "$memory" != "0" ]]; then
  run_args+=( --memory "$memory" )
fi

# Preserve published ports: HostIp, HostPort, container port/proto
while IFS=$'\t' read -r host_ip host_port cport; do
  [[ -z "${cport:-}" ]] && continue
  if [[ -n "$host_ip" && "$host_ip" != "0.0.0.0" && "$host_ip" != "::" ]]; then
    run_args+=( -p "${host_ip}:${host_port}:${cport}" )
  else
    run_args+=( -p "${host_port}:${cport}" )
  fi
done < <(
  docker inspect --format '{{range $p, $binds := .HostConfig.PortBindings}}{{range $binds}}{{.HostIp}}{{"\t"}}{{.HostPort}}{{"\t"}}{{$p}}{{"\n"}}{{end}}{{end}}' "$NAME"
)

run_args+=( "$IMAGE" )

docker stop "$NAME" >/dev/null
docker rm "$NAME" >/dev/null
docker run "${run_args[@]}" >/dev/null
echo "updated ${NAME} -> ${IMAGE}"
