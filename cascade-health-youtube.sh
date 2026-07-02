#!/usr/bin/env bash
set -euo pipefail

TABLE_ID=100
YOUTUBE_TABLE_ID=102
RESERVE_TABLE_ID=101
MARK=0x77
YOUTUBE_MARK=0x79
RESERVE_MARK=0x78
STATE_DIR=/run/cascade-health
WEIGHTS_FILE=/etc/cascade/exit-weights.conf
FAIL_DOWN=3
OK_UP=2
PING_TIMEOUT=2

# name ifname probe_ip weight
EXITS='hel1 wg-exit-hel1 10.77.3.2 10
de1 wg-exit-de1 10.77.4.2 10
vie1 wg-exit-vie1 10.77.6.2 10
ams3 wg-exit-ams3 10.77.7.2 10
ams1 wg-exit-ams1 10.77.1.2 3
ams2 wg-exit-ams2 10.77.2.2 1'

RESERVE_EXIT='ru1 wg-exit-ru1 10.77.5.2'

mkdir -p "$STATE_DIR"

declare -A WEIGHT_OVERRIDES=()

load_weight_overrides() {
  local name weight
  [[ -r "$WEIGHTS_FILE" ]] || return 0
  while IFS='=' read -r name weight; do
    [[ "$name" =~ ^[a-z0-9_-]+$ ]] || continue
    [[ "$weight" =~ ^[0-9]+$ ]] || continue
    (( weight >= 0 && weight <= 100 )) || continue
    WEIGHT_OVERRIDES["$name"]="$weight"
  done < "$WEIGHTS_FILE"
}

state_file() {
  printf '%s/%s.state\n' "$STATE_DIR" "$1"
}

read_state() {
  local name="$1" file
  file="$(state_file "$name")"
  if [[ -f "$file" ]]; then
    # shellcheck disable=SC1090
    source "$file"
  else
    status=unknown
    ok_count=0
    fail_count=0
  fi
}

write_state() {
  local name="$1"
  cat > "$(state_file "$name")" <<EOF
status=$status
ok_count=$ok_count
fail_count=$fail_count
updated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
}

probe_once() {
  local ifname="$1" ip="$2"
  ip link show "$ifname" >/dev/null 2>&1 && ping -I "$ifname" -c 1 -W "$PING_TIMEOUT" "$ip" >/dev/null 2>&1
}

update_probe_state() {
  local name="$1" ifname="$2" ip="$3"
  read_state "$name"
  if probe_once "$ifname" "$ip"; then
    ok_count=$((ok_count + 1))
    fail_count=0
    if [[ "$status" != "up" && "$ok_count" -ge "$OK_UP" ]]; then
      status=up
    elif [[ "$status" == "unknown" ]]; then
      status=up
    fi
  else
    fail_count=$((fail_count + 1))
    ok_count=0
    if [[ "$status" == "up" && "$fail_count" -ge "$FAIL_DOWN" ]]; then
      status=down
    elif [[ "$status" == "unknown" ]]; then
      status=down
    fi
  fi
  write_state "$name"
  [[ "$status" == "up" ]]
}

replace_rules() {
  while ip rule del pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID" 2>/dev/null; do :; done
  while ip rule del pref 95 fwmark "$YOUTUBE_MARK" table "$YOUTUBE_TABLE_ID" 2>/dev/null; do :; done
  while ip rule del pref 100 fwmark "$MARK" table "$TABLE_ID" 2>/dev/null; do :; done
  ip rule add pref 90 fwmark "$RESERVE_MARK" table "$RESERVE_TABLE_ID"
  ip rule add pref 95 fwmark "$YOUTUBE_MARK" table "$YOUTUBE_TABLE_ID"
  ip rule add pref 100 fwmark "$MARK" table "$TABLE_ID"
}

build_route() {
  local route=(ip route replace default table "$TABLE_ID")
  local youtube_route=(ip route replace default table "$YOUTUBE_TABLE_ID")
  local reserve_route=(ip route replace default table "$RESERVE_TABLE_ID")
  local alive=0
  local youtube_alive=0
  local reserve_alive=0
  local _rname riface rip

  while read -r name ifname ip weight; do
    [[ -z "${name:-}" ]] && continue
    weight="${WEIGHT_OVERRIDES[$name]:-$weight}"
    if update_probe_state "$name" "$ifname" "$ip"; then
      if [[ "$weight" -gt 0 ]]; then
        route+=(nexthop dev "$ifname" weight "$weight")
        alive=$((alive + 1))
      fi
      if [[ "$name" == "ams1" ]]; then
        youtube_route+=(nexthop dev "$ifname" weight 4)
        youtube_alive=$((youtube_alive + 1))
      elif [[ "$name" == "ams2" ]]; then
        youtube_route+=(nexthop dev "$ifname" weight 1)
        youtube_alive=$((youtube_alive + 1))
      fi
    fi
  done <<< "$EXITS"

  read -r _rname riface rip <<< "$RESERVE_EXIT"
  if update_probe_state "$_rname" "$riface" "$rip"; then
    reserve_alive=1
  fi

  if [[ "$alive" -eq 0 ]]; then
    if [[ "$reserve_alive" -eq 1 ]]; then
      ip route replace default dev "$riface" table "$TABLE_ID"
    else
      ip route replace blackhole default table "$TABLE_ID"
    fi
  else
    "${route[@]}"
  fi

  if [[ "$youtube_alive" -gt 0 ]]; then
    "${youtube_route[@]}"
  elif [[ "$alive" -gt 0 ]]; then
    "${route[@]/$TABLE_ID/$YOUTUBE_TABLE_ID}"
  elif [[ "$reserve_alive" -eq 1 ]]; then
    ip route replace default dev "$riface" table "$YOUTUBE_TABLE_ID"
  else
    ip route replace blackhole default table "$YOUTUBE_TABLE_ID"
  fi

  if [[ "$reserve_alive" -eq 1 ]]; then
    "${reserve_route[@]}" dev "$riface"
  elif [[ "$alive" -gt 0 ]]; then
    "${route[@]/$TABLE_ID/$RESERVE_TABLE_ID}"
  else
    ip route replace blackhole default table "$RESERVE_TABLE_ID"
  fi

  replace_rules
  ip route flush cache
}

load_weight_overrides
build_route
