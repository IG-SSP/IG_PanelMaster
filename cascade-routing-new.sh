#!/usr/bin/env bash
set -euo pipefail

MARK="0x77"
RESERVE_MARK="0x78"
TABLE_ID="100"
RESERVE_TABLE_ID="101"
HYSTERIA_UID="$(id -u hysteria 2>/dev/null || true)"
RU_URL="https://www.ipdeny.com/ipblocks/data/countries/ru.zone"
WORK_DIR="/etc/cascade"
RU_FILE="$WORK_DIR/ru.zone"
DIRECT_FILE="$WORK_DIR/direct4.zone"
RESERVE_FILE="$WORK_DIR/reserve4.zone"
DIRECT_DOMAINS_FILE="$WORK_DIR/direct-domains.txt"
RESERVE_DOMAINS_FILE="$WORK_DIR/reserve-domains.txt"
NFT_FILE="$WORK_DIR/cascade.nft"
TMP_RU="$(mktemp)"
trap 'rm -f "$TMP_RU"' EXIT

mkdir -p "$WORK_DIR"
curl -fsSL --retry 3 --connect-timeout 10 --max-time 30 "$RU_URL" > "$TMP_RU"
grep -E '^[0-9]+(\.[0-9]+){3}/[0-9]+$' "$TMP_RU" > "$RU_FILE"

cat > "$DIRECT_FILE" <<'DIRECT'
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
224.0.0.0/4
240.0.0.0/4
193.233.91.195/32
77.95.206.192/32
176.124.201.26/32
185.125.202.109/32
45.129.124.11/32
51.250.41.144/32
213.176.114.234/32
45.86.245.60/32
DIRECT
cat "$RU_FILE" >> "$DIRECT_FILE"
if [ -f "$DIRECT_DOMAINS_FILE" ]; then
  while read -r domain; do
    [ -z "$domain" ] && continue
    case "$domain" in \#*) continue ;; esac
    { getent ahostsv4 "$domain" || true; } | awk '{print $1 "/32"}'
  done < "$DIRECT_DOMAINS_FILE" >> "$DIRECT_FILE"
fi
sort -u -o "$DIRECT_FILE" "$DIRECT_FILE"

cat > "$RESERVE_FILE" <<'EMPTY'
EMPTY
if [ -f "$RESERVE_DOMAINS_FILE" ]; then
  while read -r domain; do
    [ -z "$domain" ] && continue
    case "$domain" in \#*) continue ;; esac
    { getent ahostsv4 "$domain" || true; } | awk '{print $1 "/32"}'
  done < "$RESERVE_DOMAINS_FILE" >> "$RESERVE_FILE"
fi
sort -u -o "$RESERVE_FILE" "$RESERVE_FILE"

DIRECT_ELEMENTS="$(paste -sd, "$DIRECT_FILE")"
RESERVE_ELEMENTS="$(paste -sd, "$RESERVE_FILE")"
if [ -z "$RESERVE_ELEMENTS" ]; then
  RESERVE_ELEMENTS="203.0.113.255/32"
fi

cat > "$NFT_FILE" <<NFT

table inet cascade {
  set direct4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $DIRECT_ELEMENTS }
  }

  set reserve4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $RESERVE_ELEMENTS }
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ip saddr 10.42.42.42 ip daddr @reserve4 counter meta mark set $RESERVE_MARK
    ip saddr 10.42.42.42 ip daddr != @direct4 ip daddr != @reserve4 counter meta mark set $MARK
  }

  chain output {
    type route hook output priority mangle; policy accept;
    meta skuid $HYSTERIA_UID ip6 daddr ::/0 counter reject
    meta skuid $HYSTERIA_UID udp dport 53 counter accept
    meta skuid $HYSTERIA_UID ip daddr @reserve4 counter meta mark set $RESERVE_MARK
    meta skuid $HYSTERIA_UID ip daddr != @direct4 ip daddr != @reserve4 counter meta mark set $MARK
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    meta skuid $HYSTERIA_UID oifname "wg-exit-ams1" snat ip to 10.77.1.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-ams2" snat ip to 10.77.2.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-hel1" snat ip to 10.77.3.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-de1" snat ip to 10.77.4.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-vie1" snat ip to 10.77.6.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-ru1" snat ip to 10.77.5.1
  }
}
NFT

nft delete table inet cascade 2>/dev/null || true
nft -f "$NFT_FILE"
mkdir -p /etc/iproute2
[ -f /etc/iproute2/rt_tables ] || printf '255 local\n254 main\n253 default\n0 unspec\n' >/etc/iproute2/rt_tables
if ! grep -qE "^[[:space:]]*$TABLE_ID[[:space:]]+cascade$" /etc/iproute2/rt_tables; then
  printf '%s cascade\n' "$TABLE_ID" >> /etc/iproute2/rt_tables
fi
if ! grep -qE "^[[:space:]]*$RESERVE_TABLE_ID[[:space:]]+reserve$" /etc/iproute2/rt_tables; then
  printf '%s reserve\n' "$RESERVE_TABLE_ID" >> /etc/iproute2/rt_tables
fi
while ip rule del pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID" 2>/dev/null; do :; done
while ip rule del pref 100 fwmark "$MARK" table "$TABLE_ID" 2>/dev/null; do :; done
ip rule add pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID"
ip rule add pref 100 fwmark "$MARK" table "$TABLE_ID"
/usr/local/sbin/cascade-health
