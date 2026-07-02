#!/usr/bin/env bash
set -euo pipefail

DOMAIN="45-94-37-67.sslip.io"
PASSWORD="33F2hC5AHannpvzl6mX1vgVY"
EMAIL="admin@indiangolf.ru"

ts="$(date +%Y%m%d-%H%M%S)"
backup="/root/cascade-backups/$ts/hysteria"
mkdir -p "$backup"

for path in /usr/local/bin/hysteria /etc/hysteria /etc/systemd/system/hysteria-server.service; do
  if [[ -e "$path" ]]; then
    cp -a "$path" "$backup/"
  fi
done

install -m 0755 /tmp/hysteria /usr/local/bin/hysteria

if ! id -u hysteria >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin hysteria
fi

mkdir -p /etc/hysteria
cat > /etc/hysteria/config.yaml <<EOF
listen: :8443

acme:
  domains:
    - $DOMAIN
  email: $EMAIL

auth:
  type: password
  password: $PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.cloudflare.com/
    rewriteHost: true
EOF

cat > /etc/systemd/system/hysteria-server.service <<'EOF'
[Unit]
Description=Hysteria Server Service (config.yaml)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=/etc/hysteria
User=hysteria
Group=hysteria
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hysteria-server.service

echo "backup=$backup"
echo "domain=$DOMAIN"
