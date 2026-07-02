# Install run 2026-07-02 Timeweb

Цель: проверить и вручную настроить минимальную сеть из ingress и exit, фиксируя шаги для будущего установщика.

Серверы:
- ingress: Cute Hoopoe, 77.95.206.192, user root
- exit: Wild Raven, 80.242.58.14, user root

Секреты:
- Пароли не записываются в журнал.

План:
1. Проверить SSH-доступ.
2. Собрать сведения об ОС, пакетном менеджере, Docker, занятых портах и существующих сервисах.
3. Сравнить с текущим bootstrap-планом приложения.
4. Установить минимальные компоненты.
5. Проверить результат и зафиксировать команды/выводы.

## Ход работ

- 2026-07-02 13:44 MSK: создан журнал.
- 2026-07-02 13:45 MSK: ingress SSH доступен. Host key SHA256:qBXXxP2vwO3Nxyzc198b9K0gNUA3YRLgMCx47gY7NlM.
- 2026-07-02 13:45 MSK: ingress ОС Debian 13 trixie, `apt-get` есть, Docker уже установлен. Порты `51820/udp` и `51821/tcp` заняты docker-proxy, вероятно уже работает wg-easy.
- 2026-07-02 13:46 MSK: exit SSH доступен. Host key SHA256:1UBlk8lt/VjVdGCsHbrK1Cg4MyxgWIOk09L6MS3vCQg.
- 2026-07-02 13:46 MSK: exit ОС Ubuntu 24.04 noble, `apt-get` есть, Docker не найден. Целевые порты wg-easy свободны.
- 2026-07-02 13:52 MSK: ingress осмотрен без изменений. Найден существующий `wg-easy` `ghcr.io/wg-easy/wg-easy:15.3.0`, порты `51820/udp`, `51821/tcp`. Docker active. `hysteria-server.service` inactive.
- 2026-07-02 13:55 MSK: exit настроен: установлены `wireguard`, `wireguard-tools`, Docker CE, Docker Compose plugin. Включен `net.ipv4.ip_forward=1`.
- 2026-07-02 13:55 MSK: exit запущен `wg-easy` `ghcr.io/wg-easy/wg-easy:15.3.0` через `/opt/wg-easy/docker-compose.yml`.
- 2026-07-02 13:55 MSK: exit wg-easy параметры: `WG_HOST=80.242.58.14`, `WG_PORT=51830`, `INSECURE=true`, UI `51831/tcp`.
- 2026-07-02 13:56 MSK: итоговая проверка: ingress `wg-easy` активен на `51820/udp`, `51821/tcp`; exit `wg-easy` активен на `51830/udp`, `51831/tcp`.
- 2026-07-02 14:20 MSK: исправлен preflight установщика: password SSH через `plink` использует сохраненный `hostKey`, скрипт передается через stdin с удалением CRLF, вывод переведен в `key=value`.
- 2026-07-02 14:20 MSK: preflight обоих тестовых VPS проходит. `wg-easy` и занятые порты показываются как warning, потому что установка не должна перетирать существующий контейнер без явного `FORCE_REINSTALL=true`.
- 2026-07-02 15:10 MSK: выполнен idempotency-запуск bootstrap на ingress и exit через backend-код приложения. Оба запуска завершились `OK`; существующий контейнер `wg-easy` не заменялся.
- 2026-07-02 15:10 MSK: для password-режима запуск bootstrap переведен на схему `pscp` загрузить временный скрипт в `/tmp`, затем `plink` выполнить его. Это надежнее для Windows-приложения, чем передавать скрипт через stdin.
- 2026-07-02 15:35 MSK: после переустановки ОС на тестовых VPS SSH host key изменился. Добавлен сценарий подтверждения нового fingerprint в UI: preflight показывает найденный `SHA256:*`, кнопка сохраняет его в `.vpn-secrets`, затем preflight повторяется.
- 2026-07-02 15:55 MSK: установка получила визуальный flow: кнопки блокируются во время запуска, job-карточка показывает текущий stage и progress bar, после успешного bootstrap появляется действие для открытия wg-easy и копирования IP/URL.
- 2026-07-02 16:20 MSK: Hysteria bootstrap исправлен: Hysteria 2.9 требует `tls` или `acme`, поэтому для автоматического режима без домена генерируется self-signed cert/key и клиентам нужен `insecure=true`.
- 2026-07-02 16:25 MSK: в мастере добавлен домен входной ноды. Если домен указан, ingress `wg-easy` получает `WG_HOST=<domain>` и работает без `INSECURE`; если домена нет, ingress `wg-easy` работает по HTTP с `INSECURE=true`.
- 2026-07-02 16:35 MSK: добавлен режим exit `existing wg-easy`: bootstrap не устанавливает и не меняет wg-easy, проверяет наличие контейнера, оставляет volume и выданные профили клиентов нетронутыми, а UI показывает отдельное действие подключения существующего узла.

## Команды, важные для установщика

Exit bootstrap essentials:

```bash
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release iptables nftables wireguard wireguard-tools
install -m 0755 -d /etc/apt/keyrings
. /etc/os-release
curl -fsSL "https://download.docker.com/linux/$ID/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-vpn-manager-forward.conf
mkdir -p /opt/wg-easy
docker compose -f /opt/wg-easy/docker-compose.yml up -d
```

Наблюдения для исправления установщика:
- Для password SSH через PuTTY нужен сценарий доверия host key. `plink -batch` падает, если ключ не закэширован. Нужно показывать fingerprint и давать кнопку `Доверять этому host key`.
- Timeweb mirror `mirror.timeweb.ru` может не резолвиться, но `archive.ubuntu.com` отрабатывает. Такие warning не должны считаться fatal.
- Если `wg-easy` уже есть на ingress, установщик должен показывать `уже установлен`, не предлагать переустановку по умолчанию.
- Hysteria не устанавливалась: для корректной автоматизации нужно отдельно решить режим TLS/domain/insecure.
- Скрипты, которые отправляются из Windows на Linux через stdin, нужно очищать от CRLF на удаленной стороне: `tr -d '\r' | bash -s` или `tr -d '\r' > file && bash file`.
- Для password SSH на Windows лучше не использовать stdin в фоновом процессе приложения. Для preflight подходит `plink -m <local-script>`, для bootstrap - `pscp <local-script> host:/tmp/...` и отдельный `plink "bash /tmp/..."`.
- Переустановка ОС должна рассматриваться как штатный кейс: старый host key нельзя использовать молча, нужно показать новый fingerprint и дождаться явного подтверждения пользователя.
- Момент настройки wg-easy: после успешного bootstrap конкретного сервера. UI должен показать отдельное действие, открыть `http://<server-ip>:<ui-port>/` и дать скопировать публичный IP для первичной настройки.
- Для production-домена входной ноды нужно заранее направить DNS A/AAAA на ingress IP. Без домена bootstrap должен оставлять HTTP-режим wg-easy явно небезопасным, но рабочим для первичной настройки.
- Для VPS с уже используемым wg-easy нужен режим `existing`: не трогать контейнер и клиентские профили. Подключение такого сервера к сети должно идти отдельным peer/route/import flow поверх существующей конфигурации.
