#!/usr/bin/env bash
set -euo pipefail

RU_PUBLIC_KEY="J/gXajeUlbptgH2ByFdUAxagPEmcyou2+OzPz0pMczc="

install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /root/codex-backups
tar -czf "/root/codex-backups/before-wg-exit-ru1-$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /usr/local/sbin/cascade-routing /opt/cascade-monitor 2>/dev/null || true

cat >/etc/wireguard/wg-exit-ru1.conf <<EOF
[Interface]
Address = 10.77.5.1/30
PrivateKey = $(cat /etc/wireguard/cascade-keys/wg-exit-ru1.key)
Table = off

[Peer]
PublicKey = ${RU_PUBLIC_KEY}
Endpoint = 51.250.41.144:51835
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg-exit-ru1.conf
systemctl enable wg-quick@wg-exit-ru1.service
systemctl restart wg-quick@wg-exit-ru1.service
