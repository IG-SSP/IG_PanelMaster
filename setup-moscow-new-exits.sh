#!/usr/bin/env bash
set -euo pipefail
DE_PUBLIC_KEY="PDzYPCn8Fy6JzYpDmrHXLWQ/k5ZfSRWjpQm9gnM9diE="
VIE_PUBLIC_KEY="3eJJdsDuM7PGaYyeZzZVeLB2+P+qJ9dupJmlnPKaIwM="

install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /root/codex-backups
tar -czf "/root/codex-backups/before-wg-new-exits-$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /usr/local/sbin/cascade-routing /usr/local/sbin/cascade-health /etc/cascade 2>/dev/null || true

cat >/etc/wireguard/wg-exit-de1.conf <<EOF
[Interface]
Address = 10.77.4.1/30
PrivateKey = $(cat /etc/wireguard/cascade-keys/wg-exit-de1.key)
Table = off

[Peer]
PublicKey = ${DE_PUBLIC_KEY}
Endpoint = 213.176.114.234:51834
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

cat >/etc/wireguard/wg-exit-vie1.conf <<EOF
[Interface]
Address = 10.77.6.1/30
PrivateKey = $(cat /etc/wireguard/cascade-keys/wg-exit-vie1.key)
Table = off

[Peer]
PublicKey = ${VIE_PUBLIC_KEY}
Endpoint = 45.86.245.60:51836
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg-exit-de1.conf /etc/wireguard/wg-exit-vie1.conf
systemctl enable wg-quick@wg-exit-de1.service wg-quick@wg-exit-vie1.service
systemctl restart wg-quick@wg-exit-de1.service wg-quick@wg-exit-vie1.service
