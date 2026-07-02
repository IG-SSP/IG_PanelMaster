#!/usr/bin/env bash
set -euo pipefail

docker exec wg-easy sh -c '
  for url in \
    https://api.ipify.org \
    https://ifconfig.me/ip \
    https://ya.ru \
    https://www.google.com/generate_204 \
    https://api.telegram.org
  do
    echo "URL=$url"
    curl -4sS --connect-timeout 5 --max-time 12 -o /tmp/out \
      -w "code=%{http_code} ip=%{remote_ip} time=%{time_total}\n" "$url" || true
    head -c 120 /tmp/out 2>/dev/null || true
    echo
  done
  echo dns
  nslookup ya.ru 1.1.1.1 || true
  nslookup api.telegram.org 1.1.1.1 || true
'
