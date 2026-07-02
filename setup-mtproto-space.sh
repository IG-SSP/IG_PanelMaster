#!/usr/bin/env bash
set -euo pipefail

SECRET_FILE=/root/mtproto-space-secret.txt
CONTAINER=mtproto-space
PORT=9443

if [[ ! -s "$SECRET_FILE" ]]; then
  openssl rand -hex 16 > "$SECRET_FILE"
  chmod 600 "$SECRET_FILE"
fi

secret="$(cat "$SECRET_FILE")"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  --network host \
  -e SECRET="$secret" \
  telegrammessenger/proxy:latest \
  /bin/bash -lc '
    set -e
    curl -s https://core.telegram.org/getProxyConfig -o /tmp/backend.conf
    IP=$(curl -s -4 https://digitalresistance.dog/myIp)
    INTERNAL_IP=$(ip -4 route get 8.8.8.8 | sed -n "s/.* src \([0-9.]*\).*/\1/p" | head -1)
    echo "#### Telegram Proxy host mode"
    echo "[*] Secret: $SECRET"
    echo "[*] Link: https://t.me/proxy?server=space.indiangolf.ru&port=9443&secret=$SECRET"
    echo "[*] External IP: $IP"
    echo "[*] Internal IP: $INTERNAL_IP"
    exec /usr/local/bin/mtproto-proxy \
      -p 2398 \
      -H 9443 \
      -M 2 \
      -C 60000 \
      --aes-pwd /etc/telegram/hello-explorers-how-are-you-doing \
      -u root \
      /tmp/backend.conf \
      --allow-skip-dh \
      --nat-info "$INTERNAL_IP:$IP" \
      -S "$SECRET"
  '
