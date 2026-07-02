# Ручное поднятие новой VPN-сети

Эта инструкция описывает, что приложение должно автоматизировать. Ее можно использовать как аварийный ручной сценарий, если нужно поднять сеть без UI и без orchestrator.

Команды ниже разделены по месту выполнения:

- `Windows` - управляющая машина, где лежит приложение.
- `Ingress VPS` - входной сервер, к которому подключаются клиенты.
- `Exit VPS` - выходной сервер, через который уходит трафик.

Во всех примерах заменяйте значения в угловых скобках:

- `<INGRESS_IP>` - публичный IP входного сервера.
- `<EXIT_IP>` - публичный IP выходного сервера.
- `<SSH_USER>` - обычно `root`, `ubuntu` или `debian`.
- `<KEY_PATH>` - путь к приватному SSH-ключу, по умолчанию `.vpn-secrets\ssh-key`.
- `<DOMAIN>` - домен админки/портала, если используется.
- `<EXIT_NAME>` - короткое имя exit-сервера, например `ams1`, `de1`, `ru1`.

## 1. Подготовить управляющую машину Windows

Выполняется в папке приложения:

```powershell
cd "C:\Users\IgorG\Documents\Сеть VPNов"
```

Создать папки для состояния и секретов:

```powershell
New-Item -ItemType Directory -Force -Path ".vpn-state"
New-Item -ItemType Directory -Force -Path ".vpn-secrets"
```

Положить приватный SSH-ключ в папку `.vpn-secrets`.

Рекомендуемый путь по умолчанию:

```powershell
Copy-Item "<ПУТЬ_К_СКАЧАННОМУ_КЛЮЧУ>" ".vpn-secrets\ssh-key"
```

Ограничить права на ключ, чтобы OpenSSH не отклонял файл:

```powershell
icacls ".vpn-secrets\ssh-key" /inheritance:r
icacls ".vpn-secrets\ssh-key" /grant:r "$env:USERNAME`:R"
```

Проверить SSH-доступ к входному серверу:

```powershell
ssh -i ".vpn-secrets\ssh-key" -o StrictHostKeyChecking=accept-new <SSH_USER>@<INGRESS_IP> "hostname && id && ip route get 1.1.1.1"
```

Если сервер отвечает, можно создавать профиль сети.

## 2. Зафиксировать параметры сети вручную

Перед настройкой серверов нужно выписать параметры сети в отдельный файл. Это заменяет orchestrator и нужно, чтобы не потерять адреса, ключи и роли серверов.

На `Windows` создать файл с черновиком параметров:

```powershell
notepad ".vpn-state\network-manual-notes.txt"
```

Минимально записать туда:

```text
Network name:

Ingress:
  name:
  public IP:
  SSH user:
  SSH key path: .vpn-secrets\ssh-key
  public interface:
  client source IP:

Exit servers:
  - name:
    public IP:
    public interface:
    tunnel:
      ingress IP:
      exit IP:
      prefix: 30
      listen port:
      weight:

Routing:
  main table: 100
  reserve table: 101
  main mark: 0x77
  reserve mark: 0x78
```

Если хочется хранить это в JSON, можно создать файлы вручную:

```text
.vpn-state\network.json
.vpn-secrets\network.secrets.json
```

Но для полностью ручного сценария это необязательно. Главное - отдельно сохранить публичные ключи, приватные ключи, IP туннелей, порты и роли серверов.

## 3. Подготовить Ingress VPS

Зайти на входной сервер:

```powershell
ssh -i ".vpn-secrets\ssh-key" <SSH_USER>@<INGRESS_IP>
```

Дальше команды выполняются уже на `Ingress VPS`.

Обновить пакеты:

```bash
apt-get update
apt-get install -y curl ca-certificates gnupg lsb-release wireguard wireguard-tools iproute2 iptables nftables jq
```

Включить forwarding:

```bash
cat >/etc/sysctl.d/99-vpn-cascade.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF

sysctl --system
```

Создать рабочие директории:

```bash
install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /etc/cascade
install -d -m 755 /root/cascade-backups
```

Сделать резервную копию текущих сетевых настроек:

```bash
tar -czf "/root/cascade-backups/before-ingress-$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /etc/systemd/system /etc/cascade /etc/sysctl.d 2>/dev/null || true
```

## 4. Сгенерировать WireGuard-ключи

На `Ingress VPS`:

```bash
wg genkey | tee /etc/wireguard/cascade-keys/ingress.key | wg pubkey >/etc/wireguard/cascade-keys/ingress.pub
chmod 600 /etc/wireguard/cascade-keys/ingress.key
cat /etc/wireguard/cascade-keys/ingress.pub
```

Сохранить публичный ключ ingress-сервера. Он понадобится для exit-серверов.

На каждом `Exit VPS`:

```bash
apt-get update
apt-get install -y wireguard wireguard-tools iproute2 iptables

install -d -m 700 /etc/wireguard/cascade-keys
wg genkey | tee /etc/wireguard/cascade-keys/<EXIT_NAME>.key | wg pubkey >/etc/wireguard/cascade-keys/<EXIT_NAME>.pub
chmod 600 /etc/wireguard/cascade-keys/<EXIT_NAME>.key
cat /etc/wireguard/cascade-keys/<EXIT_NAME>.pub
```

Сохранить публичный ключ каждого exit-сервера.

## 5. Настроить Exit VPS

На каждом `Exit VPS` создать WireGuard-конфиг.

Пример для туннеля `/30`:

- ingress tunnel IP: `10.77.1.1`
- exit tunnel IP: `10.77.1.2`
- WireGuard порт exit-сервера: `51831`

```bash
cat >/etc/wireguard/wg-exit-<EXIT_NAME>.conf <<EOF
[Interface]
Address = 10.77.1.2/30
ListenPort = 51831
PrivateKey = $(cat /etc/wireguard/cascade-keys/<EXIT_NAME>.key)

[Peer]
PublicKey = <INGRESS_PUBLIC_KEY>
AllowedIPs = 10.77.1.1/32
EOF

chmod 600 /etc/wireguard/wg-exit-<EXIT_NAME>.conf
```

Включить forwarding и NAT на exit-сервере:

```bash
sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-cascade-forward.conf

iptables -C FORWARD -i wg-exit-<EXIT_NAME> -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg-exit-<EXIT_NAME> -j ACCEPT
iptables -C FORWARD -o wg-exit-<EXIT_NAME> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg-exit-<EXIT_NAME> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.77.1.1/32 -o <PUBLIC_INTERFACE> -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.77.1.1/32 -o <PUBLIC_INTERFACE> -j MASQUERADE
```

Запустить WireGuard:

```bash
systemctl enable wg-quick@wg-exit-<EXIT_NAME>.service
systemctl restart wg-quick@wg-exit-<EXIT_NAME>.service
systemctl status wg-quick@wg-exit-<EXIT_NAME>.service --no-pager
```

## 6. Настроить WireGuard на Ingress VPS

На `Ingress VPS` создать конфиг для каждого exit-сервера.

```bash
cat >/etc/wireguard/wg-exit-<EXIT_NAME>.conf <<EOF
[Interface]
Address = 10.77.1.1/30
PrivateKey = $(cat /etc/wireguard/cascade-keys/ingress.key)
Table = off

[Peer]
PublicKey = <EXIT_PUBLIC_KEY>
Endpoint = <EXIT_IP>:51831
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg-exit-<EXIT_NAME>.conf
systemctl enable wg-quick@wg-exit-<EXIT_NAME>.service
systemctl restart wg-quick@wg-exit-<EXIT_NAME>.service
systemctl status wg-quick@wg-exit-<EXIT_NAME>.service --no-pager
```

Проверить туннель:

```bash
wg show
ping -I wg-exit-<EXIT_NAME> -c 3 10.77.1.2
curl --interface wg-exit-<EXIT_NAME> https://api.ipify.org
```

## 7. Настроить таблицы маршрутизации на Ingress VPS

Добавить таблицы:

```bash
mkdir -p /etc/iproute2
grep -qE '^[[:space:]]*100[[:space:]]+cascade$' /etc/iproute2/rt_tables || printf '100 cascade\n' >> /etc/iproute2/rt_tables
grep -qE '^[[:space:]]*101[[:space:]]+reserve$' /etc/iproute2/rt_tables || printf '101 reserve\n' >> /etc/iproute2/rt_tables
```

Добавить основной маршрут через exit-сервер:

```bash
ip route replace default dev wg-exit-<EXIT_NAME> table 100
ip rule add pref 100 fwmark 0x77 table 100 2>/dev/null || true
ip route flush cache
```

Если есть несколько exit-серверов, маршрут с балансировкой выглядит так:

```bash
ip route replace default table 100 \
  nexthop dev wg-exit-ams1 weight 10 \
  nexthop dev wg-exit-de1 weight 10
```

Резервная таблица:

```bash
ip route replace default dev wg-exit-<RESERVE_EXIT_NAME> table 101
ip rule add pref 90 fwmark 0x78 table 101 2>/dev/null || true
ip route flush cache
```

## 8. Настроить nftables-маркировку на Ingress VPS

Пример минимальной маркировки: локальные и российские адреса идут напрямую, остальное маркируется в таблицу `cascade`.

```bash
cat >/etc/cascade/cascade.nft <<'EOF'
table inet cascade {
  set direct4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = {
      0.0.0.0/8,
      10.0.0.0/8,
      100.64.0.0/10,
      127.0.0.0/8,
      169.254.0.0/16,
      172.16.0.0/12,
      192.168.0.0/16,
      224.0.0.0/4,
      240.0.0.0/4
    }
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ip saddr <CLIENT_SOURCE_IP> ip daddr != @direct4 counter meta mark set 0x77
  }
}
EOF

nft delete table inet cascade 2>/dev/null || true
nft -f /etc/cascade/cascade.nft
nft list ruleset | sed -n '/table inet cascade/,/}/p'
```

`<CLIENT_SOURCE_IP>` - это IP источника клиентского трафика на ingress-сервере. Для текущей схемы с контейнером обычно используется адрес вроде `10.42.42.42`, но в новой сети его нужно определить отдельно.

## 9. Установить health-check для exit-серверов

Создать `/usr/local/sbin/cascade-health`:

```bash
cat >/usr/local/sbin/cascade-health <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

TABLE_ID=100
STATE_DIR=/run/cascade-health
mkdir -p "$STATE_DIR"

if ping -I wg-exit-<EXIT_NAME> -c 1 -W 2 10.77.1.2 >/dev/null 2>&1; then
  ip route replace default dev wg-exit-<EXIT_NAME> table "$TABLE_ID"
  echo "status=up" > "$STATE_DIR/<EXIT_NAME>.state"
else
  ip route replace blackhole default table "$TABLE_ID"
  echo "status=down" > "$STATE_DIR/<EXIT_NAME>.state"
fi

ip route flush cache
EOF

chmod +x /usr/local/sbin/cascade-health
```

Создать systemd-сервис и таймер:

```bash
cat >/etc/systemd/system/cascade-health.service <<'EOF'
[Unit]
Description=Cascade VPN health check

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cascade-health
EOF

cat >/etc/systemd/system/cascade-health.timer <<'EOF'
[Unit]
Description=Run Cascade VPN health check

[Timer]
OnBootSec=15s
OnUnitActiveSec=15s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now cascade-health.timer
systemctl start cascade-health.service
systemctl status cascade-health.service --no-pager
```

## 10. Установить клиентский портал и мониторинг

Если используются текущие Python-сервисы проекта, файлы нужно загрузить с Windows на ingress-сервер.

На `Windows`:

```powershell
scp -i ".vpn-secrets\ssh-key" ".\client-portal.py" <SSH_USER>@<INGRESS_IP>:/opt/cascade/client-portal.py
scp -i ".vpn-secrets\ssh-key" ".\cascade-monitor.py" <SSH_USER>@<INGRESS_IP>:/opt/cascade/cascade-monitor.py
```

На `Ingress VPS`:

```bash
apt-get install -y python3 python3-venv
install -d -m 755 /opt/cascade
python3 -m venv /opt/cascade/venv
/opt/cascade/venv/bin/pip install --upgrade pip
```

Создать сервис портала:

```bash
cat >/etc/systemd/system/client-portal.service <<'EOF'
[Unit]
Description=Cascade VPN client portal
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/cascade
ExecStart=/opt/cascade/venv/bin/python /opt/cascade/client-portal.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now client-portal.service
systemctl status client-portal.service --no-pager
```

Создать сервис мониторинга:

```bash
cat >/etc/systemd/system/cascade-monitor.service <<'EOF'
[Unit]
Description=Cascade VPN monitor
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/cascade
ExecStart=/opt/cascade/venv/bin/python /opt/cascade/cascade-monitor.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cascade-monitor.service
systemctl status cascade-monitor.service --no-pager
```

## 11. Проверить готовность сети

На `Ingress VPS`:

```bash
systemctl --no-pager --failed
systemctl status wg-quick@wg-exit-<EXIT_NAME>.service --no-pager
systemctl status cascade-health.timer --no-pager
wg show
ip rule
ip route show table 100
nft list ruleset | grep -A 50 'table inet cascade'
```

Проверить выход через конкретный exit:

```bash
curl --interface wg-exit-<EXIT_NAME> https://api.ipify.org
```

Проверить, что health-check видит сервер:

```bash
cat /run/cascade-health/<EXIT_NAME>.state
```

На `Exit VPS`:

```bash
systemctl status wg-quick@wg-exit-<EXIT_NAME>.service --no-pager
wg show
iptables -t nat -S
```

## 12. Добавить новый Exit VPS вручную

Короткий порядок:

1. Проверить SSH-доступ к новому серверу.
2. Установить `wireguard`, `iproute2`, `iptables`.
3. Сгенерировать WireGuard-ключи на новом exit.
4. Добавить peer на ingress.
5. Добавить peer на exit.
6. Запустить `wg-quick` на обеих сторонах.
7. Добавить новый `nexthop` в таблицу `100`.
8. Добавить новый сервер в health-check.
9. Перезапустить `cascade-health`.
10. Проверить `wg show`, `ip route show table 100`, `curl --interface`.

## 13. Полностью ручной порядок без orchestrator

Это короткий чеклист, если вообще не использовать локальный orchestrator и делать все руками на VPS.

На `Windows`:

```powershell
cd "C:\Users\IgorG\Documents\Сеть VPNов"
New-Item -ItemType Directory -Force -Path ".vpn-secrets"
New-Item -ItemType Directory -Force -Path ".vpn-state"
Copy-Item "<ПУТЬ_К_КЛЮЧУ>" ".vpn-secrets\ssh-key"
icacls ".vpn-secrets\ssh-key" /inheritance:r
icacls ".vpn-secrets\ssh-key" /grant:r "$env:USERNAME`:R"
ssh -i ".vpn-secrets\ssh-key" <SSH_USER>@<INGRESS_IP> "hostname && ip route get 1.1.1.1"
```

На каждом `Exit VPS`:

```bash
apt-get update
apt-get install -y wireguard wireguard-tools iproute2 iptables
install -d -m 700 /etc/wireguard/cascade-keys
wg genkey | tee /etc/wireguard/cascade-keys/<EXIT_NAME>.key | wg pubkey >/etc/wireguard/cascade-keys/<EXIT_NAME>.pub
chmod 600 /etc/wireguard/cascade-keys/<EXIT_NAME>.key
cat /etc/wireguard/cascade-keys/<EXIT_NAME>.pub
```

Скопировать публичный ключ exit-сервера в свои заметки.

На `Ingress VPS`:

```bash
apt-get update
apt-get install -y curl ca-certificates wireguard wireguard-tools iproute2 iptables nftables jq
install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /etc/cascade
install -d -m 755 /root/cascade-backups
wg genkey | tee /etc/wireguard/cascade-keys/ingress.key | wg pubkey >/etc/wireguard/cascade-keys/ingress.pub
chmod 600 /etc/wireguard/cascade-keys/ingress.key
cat /etc/wireguard/cascade-keys/ingress.pub
```

Скопировать публичный ключ ingress-сервера на каждый exit-сервер в конфиг peer.

На каждом `Exit VPS` создать `/etc/wireguard/wg-exit-<EXIT_NAME>.conf`:

```bash
cat >/etc/wireguard/wg-exit-<EXIT_NAME>.conf <<EOF
[Interface]
Address = <EXIT_TUNNEL_IP>/30
ListenPort = <EXIT_WG_PORT>
PrivateKey = $(cat /etc/wireguard/cascade-keys/<EXIT_NAME>.key)

[Peer]
PublicKey = <INGRESS_PUBLIC_KEY>
AllowedIPs = <INGRESS_TUNNEL_IP>/32
EOF

chmod 600 /etc/wireguard/wg-exit-<EXIT_NAME>.conf
sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-cascade-forward.conf
iptables -C FORWARD -i wg-exit-<EXIT_NAME> -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg-exit-<EXIT_NAME> -j ACCEPT
iptables -C FORWARD -o wg-exit-<EXIT_NAME> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg-exit-<EXIT_NAME> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s <INGRESS_TUNNEL_IP>/32 -o <PUBLIC_INTERFACE> -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s <INGRESS_TUNNEL_IP>/32 -o <PUBLIC_INTERFACE> -j MASQUERADE
systemctl enable --now wg-quick@wg-exit-<EXIT_NAME>.service
```

На `Ingress VPS` создать `/etc/wireguard/wg-exit-<EXIT_NAME>.conf` для каждого exit:

```bash
cat >/etc/wireguard/wg-exit-<EXIT_NAME>.conf <<EOF
[Interface]
Address = <INGRESS_TUNNEL_IP>/30
PrivateKey = $(cat /etc/wireguard/cascade-keys/ingress.key)
Table = off

[Peer]
PublicKey = <EXIT_PUBLIC_KEY>
Endpoint = <EXIT_PUBLIC_IP>:<EXIT_WG_PORT>
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg-exit-<EXIT_NAME>.conf
systemctl enable --now wg-quick@wg-exit-<EXIT_NAME>.service
```

На `Ingress VPS` включить policy routing:

```bash
grep -qE '^[[:space:]]*100[[:space:]]+cascade$' /etc/iproute2/rt_tables || printf '100 cascade\n' >> /etc/iproute2/rt_tables
grep -qE '^[[:space:]]*101[[:space:]]+reserve$' /etc/iproute2/rt_tables || printf '101 reserve\n' >> /etc/iproute2/rt_tables
ip route replace default dev wg-exit-<EXIT_NAME> table 100
ip rule add pref 100 fwmark 0x77 table 100 2>/dev/null || true
ip route flush cache
```

На `Ingress VPS` включить маркировку трафика:

```bash
nft delete table inet cascade 2>/dev/null || true
cat >/etc/cascade/cascade.nft <<'EOF'
table inet cascade {
  set direct4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    ip saddr <CLIENT_SOURCE_IP> ip daddr != @direct4 counter meta mark set 0x77
  }
}
EOF
nft -f /etc/cascade/cascade.nft
```

Финальная проверка:

```bash
wg show
ping -I wg-exit-<EXIT_NAME> -c 3 <EXIT_TUNNEL_IP>
curl --interface wg-exit-<EXIT_NAME> https://api.ipify.org
ip rule
ip route show table 100
nft list ruleset | grep -A 30 'table inet cascade'
```

## 14. Минимальная проверка с Windows

Проверить SSH:

```powershell
ssh -i ".vpn-secrets\ssh-key" <SSH_USER>@<INGRESS_IP> "hostname && systemctl --no-pager --failed"
```

Проверить WireGuard и маршруты:

```powershell
ssh -i ".vpn-secrets\ssh-key" <SSH_USER>@<INGRESS_IP> "wg show; ip rule; ip route show table 100"
```

Проверить мониторинг/портал, если известен порт:

```powershell
curl.exe http://<INGRESS_IP>:<PORT>/
```

## 15. Что нельзя делать вручную без бэкапа

Перед изменением этих файлов всегда делать резервную копию:

```bash
tar -czf "/root/cascade-backups/manual-before-change-$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /etc/cascade /etc/systemd/system /etc/sysctl.d /usr/local/sbin/cascade-health 2>/dev/null || true
```

Критичные зоны:

- `/etc/wireguard/*.conf`
- `/etc/cascade/*`
- `/usr/local/sbin/cascade-health`
- `/etc/systemd/system/cascade-*`
- `ip rule`
- `ip route table 100/101`
- `nftables`
- `iptables -t nat`

Ошибка в этих местах может отрезать трафик пользователей или оставить сервер без выхода через нужный маршрут.
