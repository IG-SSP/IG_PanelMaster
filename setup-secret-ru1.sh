#!/usr/bin/env bash
set -euo pipefail

MOSCOW_PUBLIC_KEY="fZRl/QN7HuVSekhzUNZcdWVP13ZsS4wUuZ8omLPx2h8="

install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /root/codex-backups
tar -czf "/root/codex-backups/before-wg-exit-ru1-$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /etc/systemd/system /etc/sysctl.d 2>/dev/null || true

cat >/etc/wireguard/wg-exit-ru1.conf <<EOF
[Interface]
Address = 10.77.5.2/30
ListenPort = 51835
PrivateKey = $(cat /etc/wireguard/cascade-keys/wg-exit-ru1.key)

[Peer]
PublicKey = ${MOSCOW_PUBLIC_KEY}
AllowedIPs = 10.77.5.1/32
EOF

chmod 600 /etc/wireguard/wg-exit-ru1.conf
sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-cascade-forward.conf

iptables -C FORWARD -i wg-exit-ru1 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg-exit-ru1 -j ACCEPT
iptables -C FORWARD -o wg-exit-ru1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -o wg-exit-ru1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.77.5.1/32 -o eth0 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.77.5.1/32 -o eth0 -j MASQUERADE

systemctl enable wg-quick@wg-exit-ru1.service
systemctl restart wg-quick@wg-exit-ru1.service
