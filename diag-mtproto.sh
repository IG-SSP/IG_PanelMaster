#!/usr/bin/env bash
set -euo pipefail

echo "container"
docker ps --filter name=mtproto-space --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"

echo "listen"
ss -lntp | grep ':9443' || true

echo "clients"
ss -ntp state established '( sport = :9443 or dport = :9443 )' || true

echo "telegram_dc_from_host"
for ip in 149.154.167.50 149.154.175.50 91.108.56.130 149.154.166.110; do
  printf "%s " "$ip"
  timeout 5 bash -c "</dev/tcp/$ip/443" && echo ok || echo fail
done

echo "telegram_dc_from_container"
docker exec mtproto-space bash -lc '
for ip in 149.154.167.50 149.154.175.50 91.108.56.130 149.154.166.110; do
  printf "%s " "$ip"
  timeout 5 bash -c "</dev/tcp/$ip/443" && echo ok || echo fail
done
'

echo "mtproto_process_connections"
pids="$(pgrep -f mtproto-proxy | tr "\n" "," | sed "s/,$//")"
if [[ -n "$pids" ]]; then
  ss -ntp | grep -E "pid=($(echo "$pids" | tr "," "|"))," || true
fi

echo "logs"
docker logs --tail 120 mtproto-space 2>&1
