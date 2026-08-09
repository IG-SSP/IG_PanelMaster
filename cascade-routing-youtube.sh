#!/usr/bin/env bash
set -euo pipefail

MARK="0x77"
YOUTUBE_MARK="0x79"
RESERVE_MARK="0x78"
TABLE_ID="100"
YOUTUBE_TABLE_ID="102"
RESERVE_TABLE_ID="101"
HYSTERIA_UID="$(id -u hysteria 2>/dev/null || true)"
TELEMT_UID="$(id -u telemt 2>/dev/null || echo 4294967294)"
RU_URL="https://www.ipdeny.com/ipblocks/data/countries/ru.zone"
WORK_DIR="/etc/cascade"
RU_FILE="$WORK_DIR/ru.zone"
DIRECT_FILE="$WORK_DIR/direct4.zone"
RESERVE_FILE="$WORK_DIR/reserve4.zone"
YOUTUBE_FILE="$WORK_DIR/youtube4.zone"
DIRECT_DOMAINS_FILE="$WORK_DIR/direct-domains.txt"
RESERVE_DOMAINS_FILE="$WORK_DIR/reserve-domains.txt"
YOUTUBE_DOMAINS_FILE="$WORK_DIR/youtube-domains.txt"
TELEGRAM_FILE="$WORK_DIR/telegram4.zone"
NFT_FILE="$WORK_DIR/cascade.nft"
MTPROTO_PROXY_IP="${MTPROTO_PROXY_IP:-172.30.90.2}"
TMP_RU="$(mktemp)"
TMP_RU_VALID="$(mktemp)"
trap 'rm -f "$TMP_RU" "$TMP_RU_VALID"' EXIT

mkdir -p "$WORK_DIR"
if curl --http1.1 -fsSL --retry 3 --retry-all-errors --connect-timeout 10 --max-time 30 "$RU_URL" > "$TMP_RU" \
  && grep -E '^[0-9]+(\.[0-9]+){3}/[0-9]+$' "$TMP_RU" > "$TMP_RU_VALID" \
  && [ -s "$TMP_RU_VALID" ]; then
  install -m 0644 "$TMP_RU_VALID" "$RU_FILE"
elif [ -s "$RU_FILE" ]; then
  echo "warning: RU CIDR refresh failed; using cached $RU_FILE" >&2
else
  echo "error: RU CIDR refresh failed and no cached $RU_FILE is available" >&2
  exit 1
fi

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
45.94.37.67/32
DIRECT
cat "$RU_FILE" >> "$DIRECT_FILE"
if [[ -f "$DIRECT_DOMAINS_FILE" ]]; then
  while read -r domain; do
    [[ -z "$domain" ]] && continue
    case "$domain" in \#*) continue ;; esac
    { getent ahostsv4 "$domain" || true; } | awk '{print $1 "/32"}'
  done < "$DIRECT_DOMAINS_FILE" >> "$DIRECT_FILE"
fi
sort -u -o "$DIRECT_FILE" "$DIRECT_FILE"

cat > "$RESERVE_FILE" <<'EMPTY'
EMPTY
if [[ -f "$RESERVE_DOMAINS_FILE" ]]; then
  while read -r domain; do
    [[ -z "$domain" ]] && continue
    case "$domain" in \#*) continue ;; esac
    { getent ahostsv4 "$domain" || true; } | awk '{print $1 "/32"}'
  done < "$RESERVE_DOMAINS_FILE" >> "$RESERVE_FILE"
fi
sort -u -o "$RESERVE_FILE" "$RESERVE_FILE"

if [[ ! -f "$YOUTUBE_DOMAINS_FILE" ]]; then
  cat > "$YOUTUBE_DOMAINS_FILE" <<'YTDOMAINS'
youtube.com
www.youtube.com
m.youtube.com
youtu.be
www.youtu.be
youtube-nocookie.com
www.youtube-nocookie.com
googlevideo.com
www.googlevideo.com
ytimg.com
i.ytimg.com
s.ytimg.com
ggpht.com
youtubei.googleapis.com
youtube.googleapis.com
YTDOMAINS
fi
>"$YOUTUBE_FILE"
cat >> "$YOUTUBE_FILE" <<'YTRANGES'
64.18.0.0/20
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
72.14.192.0/18
74.125.0.0/16
108.177.8.0/21
108.177.96.0/19
142.250.0.0/15
172.217.0.0/16
172.253.0.0/16
173.194.0.0/16
192.178.0.0/15
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
YTRANGES
while read -r domain; do
  [[ -z "$domain" ]] && continue
  case "$domain" in \#*) continue ;; esac
  { getent ahostsv4 "$domain" || true; } | awk '{print $1 "/32"}'
done < "$YOUTUBE_DOMAINS_FILE" >> "$YOUTUBE_FILE"
sort -u -o "$YOUTUBE_FILE" "$YOUTUBE_FILE"

cat > "$TELEGRAM_FILE" <<'TELEGRAM'
91.108.4.0/22
91.108.8.0/22
91.108.12.0/22
91.108.16.0/22
91.108.20.0/22
91.108.56.0/22
91.105.192.0/23
149.154.160.0/20
185.76.151.0/24
TELEGRAM
{ getent ahostsv4 api.telegram.org || true; } | awk '{print $1 "/32"}' >> "$TELEGRAM_FILE"
sort -u -o "$TELEGRAM_FILE" "$TELEGRAM_FILE"

DIRECT_ELEMENTS="$(paste -sd, "$DIRECT_FILE")"
RESERVE_ELEMENTS="$(paste -sd, "$RESERVE_FILE")"
YOUTUBE_ELEMENTS="$(paste -sd, "$YOUTUBE_FILE")"
TELEGRAM_ELEMENTS="$(paste -sd, "$TELEGRAM_FILE")"
[[ -n "$RESERVE_ELEMENTS" ]] || RESERVE_ELEMENTS="203.0.113.255/32"
[[ -n "$YOUTUBE_ELEMENTS" ]] || YOUTUBE_ELEMENTS="203.0.113.254/32"

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

  set youtube4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $YOUTUBE_ELEMENTS }
  }

  set telegram4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $TELEGRAM_ELEMENTS }
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ip saddr $MTPROTO_PROXY_IP ip daddr @telegram4 counter meta mark set $MARK
    ip saddr 10.42.42.42 ip daddr @youtube4 counter meta mark set $YOUTUBE_MARK
    ip saddr 10.42.42.42 ip daddr @reserve4 counter meta mark set $RESERVE_MARK
    ip saddr 10.42.42.42 ip daddr != @direct4 ip daddr != @reserve4 counter meta mark set $MARK
  }

  chain output {
    type route hook output priority mangle; policy accept;
    meta skuid $TELEMT_UID ip daddr @telegram4 counter meta mark set $MARK
    meta skuid $HYSTERIA_UID ip6 daddr ::/0 counter reject
    meta skuid $HYSTERIA_UID udp dport 53 counter accept
    meta skuid $HYSTERIA_UID ip daddr @youtube4 counter meta mark set $YOUTUBE_MARK
    meta skuid $HYSTERIA_UID ip daddr @reserve4 counter meta mark set $RESERVE_MARK
    meta skuid $HYSTERIA_UID ip daddr != @direct4 ip daddr != @reserve4 counter meta mark set $MARK
  }

  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip daddr @telegram4 oifname "wg-exit-ams1" snat ip to 10.77.1.1
    ip daddr @telegram4 oifname "wg-exit-ams2" snat ip to 10.77.2.1
    ip daddr @telegram4 oifname "wg-exit-hel1" snat ip to 10.77.3.1
    ip daddr @telegram4 oifname "wg-exit-ams3" snat ip to 10.77.7.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-ams1" snat ip to 10.77.1.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-ams2" snat ip to 10.77.2.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-hel1" snat ip to 10.77.3.1
    meta skuid $HYSTERIA_UID oifname "wg-exit-ams3" snat ip to 10.77.7.1
  }
}
NFT

nft -c -f "$NFT_FILE"
nft delete table inet cascade 2>/dev/null || true
nft -f "$NFT_FILE"
mkdir -p /etc/iproute2
[[ -f /etc/iproute2/rt_tables ]] || printf '255 local\n254 main\n253 default\n0 unspec\n' >/etc/iproute2/rt_tables
grep -qE "^[[:space:]]*$TABLE_ID[[:space:]]+cascade$" /etc/iproute2/rt_tables || printf '%s cascade\n' "$TABLE_ID" >> /etc/iproute2/rt_tables
grep -qE "^[[:space:]]*$YOUTUBE_TABLE_ID[[:space:]]+youtube$" /etc/iproute2/rt_tables || printf '%s youtube\n' "$YOUTUBE_TABLE_ID" >> /etc/iproute2/rt_tables
grep -qE "^[[:space:]]*$RESERVE_TABLE_ID[[:space:]]+reserve$" /etc/iproute2/rt_tables || printf '%s reserve\n' "$RESERVE_TABLE_ID" >> /etc/iproute2/rt_tables
while ip rule del pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID" 2>/dev/null; do :; done
while ip rule del pref 95 fwmark "$YOUTUBE_MARK" table "$YOUTUBE_TABLE_ID" 2>/dev/null; do :; done
while ip rule del pref 100 fwmark "$MARK" table "$TABLE_ID" 2>/dev/null; do :; done
ip rule add pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID"
ip rule add pref 95 fwmark "$YOUTUBE_MARK" table "$YOUTUBE_TABLE_ID"
ip rule add pref 100 fwmark "$MARK" table "$TABLE_ID"
/usr/local/sbin/cascade-health
