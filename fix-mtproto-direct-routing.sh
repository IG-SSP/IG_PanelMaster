#!/usr/bin/env bash
set -euo pipefail

ROUTING=/usr/local/sbin/cascade-routing
tmp="$(mktemp)"
grep -v 'ip daddr @telegram4 counter meta mark set $MARK' "$ROUTING" > "$tmp"
install -m 0755 "$tmp" "$ROUTING"
rm -f "$tmp"
"$ROUTING"
docker restart mtproto-space >/dev/null
