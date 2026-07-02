#!/usr/bin/env bash
set -euo pipefail

TABLE_ID=100
RESERVE_TABLE_ID=101
MARK=0x77
RESERVE_MARK=0x78

# name ifname probe_ip weight
EXITS='hel1 wg-exit-hel1 10.77.3.2 10
de1 wg-exit-de1 10.77.4.2 10
vie1 wg-exit-vie1 10.77.6.2 10
ams1 wg-exit-ams1 10.77.1.2 3
ams2 wg-exit-ams2 10.77.2.2 1'

RESERVE_EXIT='ru1 wg-exit-ru1 10.77.5.2'

is_alive() {
  local ifname="$1"
  local ip="$2"
  ip link show "$ifname" >/dev/null 2>&1 && ping -I "$ifname" -c 1 -W 1 "$ip" >/dev/null 2>&1
}

build_route() {
  local route=(ip route replace default table "$TABLE_ID")
  local reserve_route=(ip route replace default table "$RESERVE_TABLE_ID")
  local alive=0
  local reserve_alive=0
  local _rname riface rip

  while read -r name ifname ip weight; do
    [ -z "${name:-}" ] && continue
    if is_alive "$ifname" "$ip"; then
      route+=(nexthop dev "$ifname" weight "$weight")
      alive=$((alive + 1))
    fi
  done <<< "$EXITS"

  read -r _rname riface rip <<< "$RESERVE_EXIT"
  if is_alive "$riface" "$rip"; then
    reserve_alive=1
  fi

  if [ "$alive" -eq 0 ]; then
    if [ "$reserve_alive" -eq 1 ]; then
      ip route replace default dev "$riface" table "$TABLE_ID"
    else
      ip route replace blackhole default table "$TABLE_ID"
    fi
  else
    "${route[@]}"
  fi

  if [ "$reserve_alive" -eq 1 ]; then
    "${reserve_route[@]}" dev "$riface"
  elif [ "$alive" -gt 0 ]; then
    "${route[@]/$TABLE_ID/$RESERVE_TABLE_ID}"
  else
    ip route replace blackhole default table "$RESERVE_TABLE_ID"
  fi

  while ip rule del pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID" 2>/dev/null; do :; done
  while ip rule del pref 100 fwmark "$MARK" table "$TABLE_ID" 2>/dev/null; do :; done
  ip rule add pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID"
  ip rule add pref 100 fwmark "$MARK" table "$TABLE_ID"
  ip route flush cache
}

build_route
