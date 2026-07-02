# VPN Cascade Plan

## Goal

Build a WireGuard cascade where clients connect to the Moscow ingress node.
Russian destinations leave directly via Moscow. Non-Russian traffic is routed to
foreign exit nodes with weighted balancing.

## Safety Rules

- Do not modify existing wg-easy containers on Amsterdam nodes.
- Do not restart Docker or existing WireGuard services without explicit approval.
- Do not apply firewall or route changes that can drop current clients without
  explicit approval.
- Store no private SSH or WireGuard keys in this repository.

## Nodes

| Role | IP | Status | Notes |
| --- | --- | --- | --- |
| Moscow ingress | 193.233.91.195 | Active | Current ingress, wg-easy migrated, reverse proxy on `space.indiangolf.ru` |
| Old Moscow ingress | 77.95.206.192 | Cascade stopped | wg-easy left running, host-level cascade interfaces disabled |
| Amsterdam exit 1 | 176.124.201.26 | SSH closes connection | Debian 13, wg-easy on 51820/udp and 51821/tcp, 1 Gbit |
| Amsterdam exit 2 | 185.125.202.109 | SSH closes connection | Ubuntu 22.04, wg-easy on 51820/udp and 51821/tcp, 200 Mbit |
| Helsinki exit 1 | 45.129.124.11 | Active | Debian 13, 1 Gbit, current only healthy foreign exit |
| Germany exit 1 | 213.176.114.234 | Active | Debian 13, good bandwidth, auto exit |
| Vienna exit 1 | 45.86.245.60 | Active | Ubuntu 26.04, good bandwidth, auto exit |
| Amsterdam exit 3 | 45.94.37.67 | Active | Debian 13, host cascade WG on 51837/udp plus existing wg-easy untouched, Hysteria2 Direct on 8443/udp |
| RU reserve exit | 51.250.41.144 | Ready, manual reserve | Debian 11, expensive outbound, WireGuard only, not in auto routing |
| Germany exit | 216.57.108.70 | SSH timeout | Excluded from first rollout |

## Backups

Backups are stored on each VPS under `/root/codex-backups`. They contain service
state and may contain WireGuard private keys, so keep them on the servers.

| Node | Backup archive |
| --- | --- |
| Moscow `77.95.206.192` | `/root/codex-backups/20260629T105150Z.tgz` |
| Old Moscow `77.95.206.192` before move | `/root/codex-backups/msk-old-before-move-.tgz` |
| New Moscow `193.233.91.195` before setup | `/root/codex-backups/msk-new-before-setup-.tgz` |
| Amsterdam 1 `176.124.201.26` | `/root/codex-backups/20260629T105151Z.tgz` |
| Amsterdam 2 `185.125.202.109` | `/root/codex-backups/20260629T105150Z.tgz` |
| Helsinki 1 `45.129.124.11` | `/root/codex-backups/20260629T123600Z.tgz` |

## Current Ingress State

### 193.233.91.195

- Hostname: `bright-apricot.ptr.network`
- OS: Debian GNU/Linux 13
- Public interface: `net0`, `193.233.91.195/32`
- Domain: `space.indiangolf.ru`
- Caddy reverse proxy:
  - `http://space.indiangolf.ru` redirects to HTTPS
  - `https://space.indiangolf.ru` proxies wg-easy and redirects anonymous users
    to `/login`
  - Let's Encrypt certificate was issued successfully
- wg-easy:
  - image `ghcr.io/wg-easy/wg-easy:15.3.0`
  - UI still also published on `51821/tcp`
  - client WireGuard endpoint in database: `space.indiangolf.ru:51820`
  - migrated client count: 10
- Hysteria2:
  - binary version `v2.9.3`
  - service `hysteria-server.service`
  - listen port `8443/udp`
  - domain/SNI `space.indiangolf.ru`
  - config `/etc/hysteria/config.yaml`
  - Happ/share link stored on the server in `/root/hysteria2-space-happ-link.txt`
  - password stored on the server in `/root/hysteria2-space-password.txt`
  - Caddy certificate is copied into `/etc/hysteria/certs` by
    `hysteria-cert-sync.timer`
- Telegram MTProto proxy:
  - Docker container `mtproto-space`
  - listens on `9443/tcp` in host network mode
  - public endpoint `space.indiangolf.ru:9443`
  - secret stored on the server in `/root/mtproto-space-secret.txt`
  - client links stored on the server in `/root/mtproto-space-links.txt`
  - host-network mode is intentional: the ordinary Docker bridge could reach
    general Internet hosts, but timed out against Telegram DCs
  - local Telegram destination marking is removed from `cascade-routing` so the
    proxy uses the ingress server's direct uplink instead of cascade exits
- Happ subscription:
  - raw subscription URL
    `https://space.indiangolf.ru/happ/196dcc3a9c8a39daed715389e5686baab9b5`
  - base64 subscription URL
    `https://space.indiangolf.ru/happ/196dcc3a9c8a39daed715389e5686baab9b5.b64`
  - token stored on the server in `/root/happ-subscription-token.txt`
  - files served from `/opt/happ-subscription`
  - client portal issues per-profile personal proxy links under
    `https://space.indiangolf.ru/portal/happ-sub/<token>`
  - current personal links protect subscription distribution and can be rotated
    in the portal DB, but they still proxy the shared Hysteria2 subscription;
    fully independent client credentials require changing Hysteria2 auth to
    per-user credentials and reloading the service
  - current nodes:
    - `🌐 Авто`: Moscow Hysteria2 ingress with cascade routing
    - `🇫🇮 HELs-1`: direct Hysteria2 on Helsinki
    - `🇩🇪 DE-1`: direct Hysteria2 on Germany
    - `🇦🇹 VIE-1`: direct Hysteria2 on Vienna
    - `🇳🇱 AMS-3`: direct Hysteria2 on Amsterdam 3
- Client portal:
  - URL `https://space.indiangolf.ru/portal/`
  - primary client UI is browser-first; Telegram Mini App endpoint
    `https://space.indiangolf.ru/portal/app` redirects to the regular portal
  - pages include a support notice for `Фонд свободного интернета им. ИИгоря`
    explaining that donations pay for servers, reserve channels, and service
    development
  - browser login is available at `https://space.indiangolf.ru/portal/manual`;
    it accepts manual username entry, sends access requests to the admin bot,
    and only grants profiles for usernames that were approved as browser/manual
    access without Telegram ID
  - Telegram bot no longer exposes a Mini App button; `/start` sends ordinary
    website URL buttons for the access request flow, explains that access is
    issued on the site, and includes the user's Telegram username for copying
    when Telegram exposes it; confirmed login links are sent only after an admin
    approves access
  - `/start`, `/start@botname`, and `/help` all return the access-request
    instructions and website buttons
  - admins can send `/monitor` or `/admin` to the bot to receive a short-lived
    confirmed login link directly to monitoring or the admin page
  - after approval, the portal shows WireGuard/Amnezia/Happ instructions,
    profile status, WireGuard QR and `.conf`, and a personal Happ/Hysteria2
    subscription link
  - admin UI can delete individual access requests from the requests table
  - Telegram usernames are normalized to lowercase internally because Telegram
    usernames are case-insensitive; this prevents duplicate access rows for the
    same account with different letter case
- Monitoring:
  - URL `https://space.indiangolf.ru/monitor/`
  - service `cascade-monitor.service`
  - local listener `127.0.0.1:8090`
  - source script `/opt/cascade-monitor/monitor.py`
  - public access is protected by Caddy basic auth
  - username `monitor`
  - password stored on the server in `/root/cascade-monitor-password.txt`
  - JSON endpoint `https://space.indiangolf.ru/monitor/api`
  - primary UI is an infographic dashboard: ingress paths, current route,
    active exit, exit cards, external IPs, and secondary technical details
  - exit health in the UI is based on `/run/cascade-health/*.state`, not on a
    single ad-hoc ping, to avoid false down states
- Cascade:
  - `cascade-routing.service`: active
  - `cascade-routing.timer`: active, daily refresh
  - `cascade-health.timer`: active, every 10 seconds
  - current route table `100`: HELs-1, DE-1, and VIE-1 with equal weight `10`
  - container egress test from wg-easy returns `45.129.124.11`
  - Hysteria2 outbound is marked by UID `hysteria`
  - Hysteria2 IPv4 SNATs to the matching cascade link address per `wg-exit-*`
  - Hysteria2 IPv6 outbound is blocked to avoid direct IPv6 leaks
  - health checks use hysteresis: active exits are removed only after 3
    consecutive failed probes and return after 2 consecutive successful probes
  - YouTube/Google video edge traffic has a dedicated mark `0x79` and route
    table `102` named `youtube`; healthy AMS-1 and AMS-2 are used with weights
    4:1, and the route falls back to the normal cascade table if both are down
  - YouTube matching is IP/CDN based via `/etc/cascade/youtube4.zone` and
    `/etc/cascade/youtube-domains.txt`; without a local DNS/ipset resolver this
    is broader and less exact than true per-domain routing
- Auto route table currently includes HELs-1, DE-1, VIE-1, and AMS-3 with equal
  weight `10`.
- Amsterdam exits are currently not participating because both AMS hosts close
  SSH and do not answer their cascade WireGuard probes.
- RU reserve `51.250.41.144` is connected by WireGuard as `wg-exit-ru1` and is
  intentionally excluded from automatic route table `100`. Use only for manual
  emergency routing because outbound traffic is expensive and the Russian exit
  does not reach every target.

## Observed State

### 77.95.206.192

- Hostname: `msk-1-vm-511m`
- OS: Debian GNU/Linux 13
- Public interface: `eth0`, `77.95.206.192/24`
- Installed packages:
  - `docker.io`
  - `docker-compose`
  - `wireguard-tools`
  - `qrencode`
- Docker containers:
  - `wg-easy`, image `ghcr.io/wg-easy/wg-easy:15.3.0`
- Published wg-easy ports:
  - `51820/udp`
  - `51821/tcp`
- wg-easy setup URL redirects to `/setup/1`
- Environment:
  - `INSECURE=true`

### 176.124.201.26

- Hostname: `ams-1-vm-n3rw`
- OS: Debian GNU/Linux 13
- Public interface: `eth0`, `176.124.201.26/24`
- Docker containers:
  - `wg-easy`, image `ghcr.io/wg-easy/wg-easy:15.3.0`
  - `mtproto-proxy`
  - `amnezia-awg`, UDP `41088`
- Published wg-easy ports:
  - `51820/udp`
  - `51821/tcp`
- Host `wireguard-tools`: not installed
- IP forwarding: enabled
- nftables service: inactive
- ufw service: inactive

### 185.125.202.109

- Hostname: `1636947-cw14424.twc1.net`
- OS: Ubuntu 22.04.5 LTS
- Public interface: `eth0`, `185.125.202.109/24`
- Docker containers:
  - `wg-easy`, image `weejewel/wg-easy`
  - `openvpn23`, UDP `1195`
  - `mtproto-proxy`, TCP `443`
- Published wg-easy ports:
  - `51820/udp`
  - `51821/tcp`
- Host `wireguard-tools`: not installed
- IPv4 forwarding: enabled
- ufw service: active

## Target Addressing

Use separate host-level WireGuard tunnels for the cascade. Existing wg-easy
networks remain untouched.

| Link | Interface | Moscow IP | Exit IP | Exit port | Weight |
| --- | --- | --- | --- | --- | --- |
| Moscow -> Amsterdam 1 | `wg-exit-ams1` | `10.77.1.1/30` | `10.77.1.2/30` | `51831/udp` | 5 |
| Moscow -> Amsterdam 2 | `wg-exit-ams2` | `10.77.2.1/30` | `10.77.2.2/30` | `51832/udp` | 1 |
| Moscow -> Helsinki 1 | `wg-exit-hel1` | `10.77.3.1/30` | `10.77.3.2/30` | `51833/udp` | 10 |
| Moscow -> Germany 1 | `wg-exit-de1` | `10.77.4.1/30` | `10.77.4.2/30` | `51834/udp` | 10 |
| Moscow -> RU reserve | `wg-exit-ru1` | `10.77.5.1/30` | `10.77.5.2/30` | `51835/udp` | manual only |
| Moscow -> Vienna 1 | `wg-exit-vie1` | `10.77.6.1/30` | `10.77.6.2/30` | `51836/udp` | 10 |
| Moscow -> Amsterdam 3 | `wg-exit-ams3` | `10.77.7.1/30` | `10.77.7.2/30` | `51837/udp` | 10 |

Client network on Moscow wg-easy:

- Suggested subnet: `10.88.0.0/24`
- Suggested client endpoint: `5.129.204.155:51820/udp`
- Suggested UI port: `51821/tcp`
- Initial client profile: `IG_Phone`

## Routing Design

On Moscow:

- wg-easy handles client profiles and the client-facing WireGuard interface.
- RU prefixes are routed via the Moscow default route.
- Non-RU traffic is marked and sent through exit routes.
- Exit selection should be per-flow, not per-packet, to avoid breaking TCP/UDP
  sessions.
- Weighted distribution:
  - Amsterdam 1: weight 5
  - Amsterdam 2: weight 1
  - Germany: normal weight
- Active implementation:
  - `nft` table `inet cascade`
  - mark `0x77` for non-direct traffic from wg-easy container `10.42.42.42`
  - policy rule `fwmark 0x77` -> table `100`
  - table `100` default route via healthy exits
  - target weights: Helsinki 1 weight 10, Amsterdam 1 weight 3, Amsterdam 2 weight 1
  - daily refresh timer `cascade-routing.timer`
  - domain-based direct exceptions from `/etc/cascade/direct-domains.txt`
  - fast health-check timer `cascade-health.timer`, every 10 seconds

On exit nodes:

- Accept traffic only from the Moscow peer on the cascade interface.
- NAT cascade traffic to the node public interface.
- Do not expose client UI on exit nodes for this cascade.
- Do not route Moscow's wg-easy Docker IP `10.42.42.42` through exit nodes.
  Amsterdam 1 already uses that address for its own wg-easy container.
- Moscow Docker SNATs wg-easy container traffic to the local exit-link address:
  - `wg-exit-ams1`: `10.42.42.42` -> `10.77.1.1`
  - `wg-exit-ams2`: `10.42.42.42` -> `10.77.2.1`
- Exit nodes then masquerade `10.77.x.1` to their public `eth0` address.

## Rollout Plan

1. Read-only audit on Moscow and available exits. Done.
2. Back up current Docker, WireGuard, firewall, and route state on all nodes. Done.
3. Install host-level `wireguard-tools` only where missing. Done.
4. Install wg-easy on Moscow. Done.
5. Create exit interfaces on Amsterdam nodes using new UDP ports. Done.
6. Add Moscow policy routing and RU-prefix handling. Done.
7. User opens Moscow wg-easy UI and completes first setup password.
8. Create `IG_Phone` profile in Moscow wg-easy.
9. Test with a single client profile.
10. Only after confirmation, migrate other devices.

## Open Blockers

- `216.57.108.70:22` is currently unreachable.
- New Moscow UI `51821/tcp` is still public with `INSECURE=true`; the preferred
  access path is `https://space.indiangolf.ru`.
- Client portal is available at `https://space.indiangolf.ru/portal/`; admin
  area is `https://space.indiangolf.ru/portal/admin` with HTTP basic auth.
- Amsterdam exits `176.124.201.26` and `185.125.202.109` are currently unavailable
  for maintenance: SSH closes during key exchange and cascade probes time out.
- Existing imported client profiles that still contain `77.95.206.192:51820`
  must be edited or re-exported to use `space.indiangolf.ru:51820`.

## Fix Log

- Fixed Docker MASQUERADE interaction on Moscow. Initial routing preserved source
  `10.42.42.42` into exit tunnels, but that conflicts with Amsterdam 1's own
  wg-easy Docker IP.
- Removed `10.42.42.42/32` from exit `AllowedIPs`.
- Exit NAT now matches `10.77.1.1/32` and `10.77.2.1/32`.
- Verified `wg-easy` container tests:
  - `https://api.ipify.org` returns `176.124.201.26`
  - `https://ifconfig.me/ip` returns `176.124.201.26`
  - `https://ya.ru` and `https://google.com` return content successfully
- Added `2ip.ru` to domain-based direct exceptions because it resolves to
  `188.40.167.82`, which is not in RU IP ranges.
- Verified with nft counters:
  - `2ip.ru` does not hit the exit-mark rule
  - `2ip.io` hits the exit-mark rule
- 2026-06-30: migrated Moscow ingress to `193.233.91.195`, copied wg-easy
  database/clients and cascade config, updated wg-easy endpoint host to
  `space.indiangolf.ru`, installed Caddy reverse proxy, and stopped old
  Moscow host-level cascade interfaces to avoid duplicate WireGuard peers.
- 2026-06-30: new ingress currently routes non-direct traffic through Helsinki
  only. AMS exits are deferred until they become reachable again.
- 2026-06-30: added Hysteria2 inbound for Happ on
  `space.indiangolf.ru:8443/udp`. Verified a local Hysteria2 client reaches the
  internet with external IPv4 `45.129.124.11`; IPv6 from the Hysteria process is
  blocked.
- 2026-06-30: added a small HTTPS monitoring UI at
  `https://space.indiangolf.ru/monitor/`. It shows route table `100`, exit
  health, WireGuard counters, service states, nft counters, and current external
  IPs for wg-easy and Hysteria2.
- 2026-06-30: added direct Hysteria2 on Helsinki with ACME certificate for
  `45-129-124-11.sslip.io` and published a Happ subscription from Moscow Caddy.
  Verified the direct Helsinki Hysteria2 link returns external IPv4
  `45.129.124.11`. Amsterdam and Frankfurt nodes are deferred because SSH closes
  during connection setup.
- 2026-06-30: added emoji prefixes to Happ subscription node names:
  `🌐 Авто` and `🇫🇮 HELs-1-Direct`.
- 2026-06-30: redesigned the monitor UI to prioritize traffic flow, active
  egress, exit health, and external IPs. Service tables and nft counters are now
  secondary technical details.
- 2026-06-30: added secret Russian reserve server `51.250.41.144` as
  WireGuard-only `wg-exit-ru1`. Verified handshake, ping to `10.77.5.2`, and
  explicit test egress `51.250.41.144`. It is visible in monitoring as a yellow
  reserve and is used only if all foreign auto exits are unavailable.
- 2026-06-30: added DE-1 `213.176.114.234` as `wg-exit-de1` and VIE-1
  `45.86.245.60` as `wg-exit-vie1`. Both are active auto exits with weight `10`.
  Verified handshakes, tunnel pings, explicit egress IPs, and monitor UI.
- 2026-06-30: removed special YouTube/ChatGPT routing to RU-Reserve. The
  `reserve4` nft set is now a dummy placeholder, and tests show ChatGPT uses the
  normal auto route instead of fwmark `0x78`.
- 2026-06-30: added client profile portal on Moscow as `client-portal.service`
  at local `127.0.0.1:8091`, published through Caddy under `/portal/`. It checks
  Telegram usernames against a local whitelist, lets allowed users create up to
  their profile limit, returns `.conf` and QR, and writes created clients into
  wg-easy `clients_table` so they are visible in wg-easy. Admin is protected by
  Caddy basic auth; Caddy was backed up before the change under
  `/root/cascade-backups/20260630-105304/`.
- 2026-06-30: replaced basic auth for `/portal/admin` and `/monitor/` with
  Telegram bot authentication. Login uses `https://t.me/spaceigbot` one-time
  start links instead of Telegram Login Widget, so it does not require BotFather
  domain binding. Unknown users create pending requests; the bot sends the admin
  inline approve/deny buttons and approved users are inserted into the portal
  whitelist with the selected profile limit.
- 2026-06-30: routed Moscow host traffic to Telegram API through the foreign
  WireGuard cascade using nft `telegram4` marking and per-exit SNAT. Verified
  `https://api.telegram.org/` returns HTTP `302` from Moscow after the change.
  Backups:
  `/root/cascade-backups/20260630-112552/`,
  `/root/cascade-backups/20260630-113001/`,
  `/root/cascade-backups/20260630-113337/`.
- 2026-06-30: fixed wg-easy client list failure caused by portal-created client
  rows with empty strings in JSON fields. Updated `TG_gilpert_1` JSON-like
  fields to `NULL` where wg-easy expects nullable JSON, patched
  `client-portal.py` to create future rows the same way, and backed up the DB to
  `/root/cascade-backups/20260630-133041/wg-easy.before-json-fix.db`.
- 2026-06-30: installed direct Hysteria2 on DE-1
  `213-176-114-234.sslip.io:8443` and VIE-1
  `45-86-245-60.sslip.io:8443`, using the same direct-node password as HELs-1.
  Verified real Hysteria client egress:
  DE-1 -> `213.176.114.234`, VIE-1 -> `45.86.245.60`, HELs-1 ->
  `45.129.124.11`. Updated Happ subscription to four selectable nodes:
  `🌐 Авто`, `🇫🇮 HELs-1`, `🇩🇪 DE-1`, `🇦🇹 VIE-1`.
- 2026-06-30: added Telegram Mini App at
  `https://space.indiangolf.ru/portal/app`. It validates Telegram WebApp
  `initData`, creates the same portal session cookie, and opens links for
  profiles, admin, and monitoring based on the Telegram role. The bot sends an
  inline `Открыть VPN` WebApp button on `/start`; a direct button was also sent
  to admin Telegram ID `190409129`. Backup:
  `/root/cascade-backups/20260630-134532/`.
- 2026-07-01: changed the bot to browser-first operation. The persistent
  Telegram menu is reset to commands, `/start` sends URL buttons to the website
  instead of a WebApp button, `/portal/app` redirects to the regular portal,
  and users receive a short-lived confirmed login link only after approval.
- 2026-06-30: added hard server-side cap of 25 profiles per Telegram username
  in `client-portal.py`; admin POSTs and bot approvals are clamped even if a
  larger value is submitted. Verified `max_profiles=999` stores as `25`.
- 2026-06-30: made the monitor faster and less fragile by skipping external
  exit-IP curl checks after failed tunnel pings, reducing dead-exit wait time,
  and increasing page auto-refresh from 15s to 60s. Local monitor render time
  dropped to about 4s. Backup:
  `/root/cascade-backups/20260630-135416/`.
- 2026-06-30: added AMS-3 `45.94.37.67` as `wg-exit-ams3` on `10.77.7.0/30`,
  listen port `51837/udp`, auto weight `10`. Existing wg-easy on that host
  remains untouched on `51820/udp` and `51821/tcp`. Verified handshake, tunnel
  ping, explicit egress IP `45.94.37.67`, and table `100` participation.
