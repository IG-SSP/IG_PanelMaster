#!/usr/bin/env python3
import html
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

WEIGHTS_FILE = "/etc/cascade/exit-weights.conf"
CASCADE_HEALTH = "/usr/local/sbin/cascade-health"
NETWORK_FILE = os.environ.get("CASCADE_NETWORK_FILE", "/etc/cascade/network.json")
WIREGUARD_ONLY = os.environ.get("CASCADE_WIREGUARD_ONLY", "0").strip().lower() in ("1", "true", "yes")
EXITS = []

BASE_SERVICES = ["cascade-routing.service", "cascade-health.timer", "docker.service", "caddy.service"]


def env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


CACHE_INTERVAL = env_int("CASCADE_MONITOR_CACHE_INTERVAL", 30, 10, 300)
CACHE_MAX_AGE = max(60, CACHE_INTERVAL * 3)
CLIENT_SOCKET_TIMEOUT = 5
MAX_POST_BODY = 64 * 1024
MAX_HTTP_WORKERS = 8
CACHE_LOCK = threading.Lock()
CACHE_REFRESH = threading.Event()
CACHE_DATA = None
CACHE_UPDATED = 0.0
CACHE_ERROR = ""


def run(cmd, timeout=4):
    try:
        p = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
        return {"ok": p.returncode == 0, "rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": 124, "out": "", "err": "timeout"}
    except Exception as exc:
        return {"ok": False, "rc": 1, "out": "", "err": str(exc)}


def exit_key(exit_):
    return exit_["iface"].replace("wg-exit-", "")


def configured_exits():
    """Load portable exit metadata, while preserving the current deployment fallback."""
    try:
        with open(NETWORK_FILE, "r", encoding="utf-8") as f:
            document = json.load(f)
        source = document.get("exits", []) if isinstance(document, dict) else []
        result = []
        for index, item in enumerate(source, start=1):
            if not isinstance(item, dict):
                continue
            iface = str(item.get("iface") or f"wg-exit-{index}").strip()
            if not iface.replace("-", "").replace("_", "").isalnum():
                continue
            result.append({
                "name": str(item.get("name") or iface),
                "iface": iface,
                "probe": str(item.get("probe") or item.get("exitAddress") or ""),
                "expected_ip": str(item.get("expected_ip") or item.get("publicIp") or ""),
                "weight": max(0, min(int(item.get("weight", 10)), 100)),
                "mode": "reserve" if item.get("mode") == "reserve" else "auto",
            })
        if result:
            return result
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return [dict(item) for item in EXITS]


def monitored_services(exits):
    services = [f"wg-quick@{item['iface']}.service" for item in exits]
    services.extend(BASE_SERVICES)
    if not WIREGUARD_ONLY:
        services.extend(["hysteria-server.service", "hysteria-cert-sync.timer"])
    return list(dict.fromkeys(services))


def load_weight_overrides():
    weights = {}
    if not os.path.exists(WEIGHTS_FILE):
        return weights
    try:
        with open(WEIGHTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if not key.replace("-", "").replace("_", "").isalnum():
                    continue
                try:
                    weight = int(value)
                except ValueError:
                    continue
                if 0 <= weight <= 100:
                    weights[key] = weight
    except OSError:
        return {}
    return weights


def effective_exits():
    overrides = load_weight_overrides()
    exits = []
    for item in configured_exits():
        exit_ = dict(item)
        key = exit_key(exit_)
        exit_["key"] = key
        exit_["default_weight"] = item["weight"]
        if exit_.get("mode") != "reserve":
            exit_["weight"] = overrides.get(key, item["weight"])
        exits.append(exit_)
    return exits


def save_weights(params):
    configured = configured_exits()
    allowed = {exit_key(e) for e in configured if e.get("mode") != "reserve"}
    lines = ["# Managed by cascade-monitor. Weight 0 disables an auto exit from balancing.\n"]
    for e in configured:
        key = exit_key(e)
        if key not in allowed:
            continue
        raw = params.get(f"weight_{key}", [""])[0]
        try:
            weight = int(raw)
        except ValueError:
            raise ValueError(f"Bad weight for {key}")
        if not 0 <= weight <= 100:
            raise ValueError(f"Weight for {key} must be 0..100")
        lines.append(f"{key}={weight}\n")
    tmp = WEIGHTS_FILE + ".tmp"
    os.makedirs(os.path.dirname(WEIGHTS_FILE), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.replace(tmp, WEIGHTS_FILE)
    return run(CASCADE_HEALTH, 15)


def parse_wg_dump():
    dump = run("wg show all dump", 3)["out"]
    data = {}
    for line in dump.splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            iface, pub, _priv, listen, _fwmark = parts
            data.setdefault(iface, {"public_key": pub, "listen_port": listen, "peers": []})
        elif len(parts) >= 9:
            iface, pub, _preshared, endpoint, allowed, handshake, rx, tx, keepalive = parts[:9]
            data.setdefault(iface, {"public_key": "", "listen_port": "", "peers": []})
            hs = int(handshake or 0)
            age = None if hs == 0 else int(time.time() - hs)
            data[iface]["peers"].append(
                {
                    "public_key": pub,
                    "endpoint": endpoint,
                    "allowed_ips": allowed,
                    "latest_handshake": hs,
                    "handshake_age_sec": age,
                    "rx_bytes": int(rx or 0),
                    "tx_bytes": int(tx or 0),
                    "keepalive": keepalive,
                }
            )
    return data


def service_states(exits):
    result = {}
    for svc in monitored_services(exits):
        r = run(f"systemctl is-active {svc}", 2)
        result[svc] = r["out"] or "unknown"
    return result


def route_table():
    return run("ip route show table 100", 3)["out"]


def health_state(exit_):
    state_name = exit_["iface"].replace("wg-exit-", "")
    path = f"/run/cascade-health/{state_name}.state"
    if not os.path.exists(path):
        return {"status": "unknown", "ok_count": 0, "fail_count": 0, "updated_at": ""}
    state = {"status": "unknown", "ok_count": 0, "fail_count": 0, "updated_at": ""}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if "=" not in line:
                    continue
                key, value = line.strip().split("=", 1)
                if key in ("ok_count", "fail_count"):
                    try:
                        state[key] = int(value)
                    except ValueError:
                        state[key] = 0
                else:
                    state[key] = value
    except OSError:
        pass
    return state


def nft_counters():
    out = run(
        "nft list chain inet cascade prerouting; "
        "nft list chain inet cascade output; "
        "nft list chain inet cascade postrouting",
        4,
    )["out"]
    return [line.strip() for line in out.splitlines() if "counter packets" in line]


def probe_exit(exit_):
    iface = exit_["iface"]
    state = health_state(exit_)
    ping_ok = state["status"] == "up"
    if not ping_ok:
        return {
            "ping_ok": False,
            "public_ip": "",
            "curl_ok": False,
            "health": state,
            "error": f"health={state['status']}, fail_count={state['fail_count']}",
        }
    ip = run(f"curl --interface {iface} -4 --connect-timeout 2 --max-time 3 -sS https://api.ipify.org", 4)
    return {
        "ping_ok": ping_ok,
        "public_ip": ip["out"] if ip["ok"] else "",
        "curl_ok": ip["ok"],
        "health": state,
        "error": ip["err"],
    }


def wg_easy_ip():
    r = run(
        "docker exec wg-easy sh -lc "
        "'wget -qO- --timeout=6 https://api.ipify.org || curl -sS --max-time 6 https://api.ipify.org'",
        8,
    )
    return r["out"] if r["ok"] else ""


def hysteria_ip():
    if WIREGUARD_ONLY:
        return ""
    r = run("runuser -u hysteria -- curl -4 --max-time 6 -sS https://api.ipify.org", 8)
    return r["out"] if r["ok"] else ""


def collect():
    wg = parse_wg_dump()
    route = route_table()
    exits = []
    for e in effective_exits():
        item = dict(e)
        item["wg"] = wg.get(e["iface"], {})
        item["probe_result"] = probe_exit(e)
        item["in_route_table"] = e["iface"] in route
        exits.append(item)
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "hostname": run("hostname", 2)["out"],
        "services": service_states(exits),
        "route_table_100": route,
        "exits": exits,
        "client_entrypoints": {
            "wg_easy_container_external_ip": wg_easy_ip(),
            "hysteria_process_external_ip": hysteria_ip(),
        },
        "nft_counters": nft_counters(),
    }


def refresh_cache():
    global CACHE_DATA, CACHE_UPDATED, CACHE_ERROR
    try:
        data = collect()
    except Exception as exc:
        with CACHE_LOCK:
            CACHE_ERROR = str(exc)
        return False
    with CACHE_LOCK:
        CACHE_DATA = data
        CACHE_UPDATED = time.monotonic()
        CACHE_ERROR = ""
    return True


def cache_snapshot():
    with CACHE_LOCK:
        data = CACHE_DATA
        updated = CACHE_UPDATED
        error = CACHE_ERROR
    age = max(0.0, time.monotonic() - updated) if updated else None
    return data, age, error


def cached_api_data():
    data, age, error = cache_snapshot()
    if data is None:
        return None
    result = dict(data)
    result["cache"] = {
        "age_seconds": round(age, 1),
        "interval_seconds": CACHE_INTERVAL,
        "max_age_seconds": CACHE_MAX_AGE,
        "last_error": error,
    }
    return result


def collector_loop():
    while True:
        refresh_cache()
        CACHE_REFRESH.wait(CACHE_INTERVAL)
        CACHE_REFRESH.clear()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        self.request_slots = threading.BoundedSemaphore(MAX_HTTP_WORKERS)
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


def fmt_bytes(n):
    try:
        n = int(n)
    except Exception:
        return "-"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def fmt_age(seconds):
    if seconds is None:
        return "нет"
    try:
        seconds = int(seconds)
    except Exception:
        return "нет"
    if seconds < 60:
        return f"{seconds}с"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}м"
    hours = minutes // 60
    return f"{hours}ч {minutes % 60}м"


def badge(ok, text, warn=False):
    cls = "warn" if warn else ("ok" if ok else "bad")
    return f"<span class=\"badge {cls}\">{html.escape(text)}</span>"


def exit_state(exit_):
    return exit_["probe_result"]["ping_ok"] and exit_["in_route_table"]


def reserve_ready(exit_):
    return exit_.get("mode") == "reserve" and exit_["probe_result"]["ping_ok"]


def route_label(route):
    if not route:
        return "нет маршрута"
    if "blackhole" in route:
        return "fail-closed"
    return route.replace("default dev ", "").replace("\n", " / ")


def render_html(data):
    auto_exits = [e for e in data["exits"] if e.get("mode") != "reserve"]
    reserve_exits = [e for e in data["exits"] if e.get("mode") == "reserve"]
    active_exits = [e for e in auto_exits if exit_state(e)]
    ready_reserves = [e for e in reserve_exits if reserve_ready(e)]
    configured_exits = len(auto_exits)
    route = data["route_table_100"]
    route_summary = route_label(route)
    wg_ip = data["client_entrypoints"]["wg_easy_container_external_ip"] or "n/a"
    active_name = active_exits[0]["name"] if active_exits else "нет активного выхода"
    active_ip = active_exits[0]["probe_result"].get("public_ip", "") if active_exits else ""
    required_services = {k: v for k, v in data["services"].items() if not k.startswith("caddy")}
    system_ok = bool(required_services) and all(v == "active" for v in required_services.values())
    total_weight = sum(e["weight"] for e in auto_exits if exit_state(e))

    svc_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{badge(v == 'active', v)}</td></tr>"
        for k, v in data["services"].items()
    )
    exit_rows = []
    exit_cards = []
    weight_rows = []
    for e in data["exits"]:
        peers = e.get("wg", {}).get("peers", [])
        peer = peers[0] if peers else {}
        age = peer.get("handshake_age_sec")
        hs = fmt_age(age)
        healthy = exit_state(e)
        reserve = e.get("mode") == "reserve"
        ready = reserve_ready(e)
        share = 0 if total_weight == 0 or not healthy else round(e["weight"] / total_weight * 100)
        rx = fmt_bytes(peer.get("rx_bytes", 0))
        tx = fmt_bytes(peer.get("tx_bytes", 0))
        pub = e["probe_result"].get("public_ip") or "нет ответа"
        state_text = "в маршруте" if healthy else ("резерв готов" if ready else "исключен")
        card_class = "live" if healthy else ("reserve" if ready else "offline")
        exit_cards.append(
            f"""
<article class="exit-card {card_class}">
  <div class="exit-head">
    <div><strong>{html.escape(e['name'])}</strong><span>{html.escape(e['iface'])}</span></div>
    {badge(healthy, state_text, warn=ready and not healthy)}
  </div>
  <div class="bar"><i style="width:{share}%"></i></div>
  <div class="exit-grid">
    <div><span>{'Режим' if reserve else 'Доля'}</span><b>{'ручной' if reserve else str(share) + '%'}</b></div>
    <div><span>Handshake</span><b>{html.escape(hs)}</b></div>
    <div><span>IP выхода</span><b>{html.escape(pub)}</b></div>
    <div><span>Трафик RX/TX</span><b>{rx} / {tx}</b></div>
  </div>
</article>"""
        )
        if not reserve:
            disabled = e["weight"] == 0
            weight_rows.append(
                f"""<label class="weight-row"><span><b>{html.escape(e['name'])}</b><small>{html.escape(e['iface'])}</small></span><input type="number" min="0" max="100" name="weight_{html.escape(e['key'])}" value="{e['weight']}"><em>{'выключен из балансировки' if disabled else 'по умолчанию ' + str(e['default_weight'])}</em></label>"""
            )
        exit_rows.append(
            f"""
<tr>
  <td><strong>{html.escape(e['name'])}</strong><br><span>{html.escape(e['iface'])}</span></td>
  <td>{badge(healthy, 'active' if healthy else ('reserve' if ready else 'down'), warn=ready and not healthy)}</td>
  <td>{e['weight']}</td>
  <td>{html.escape(hs)}</td>
  <td>{fmt_bytes(peer.get('rx_bytes', 0))} / {fmt_bytes(peer.get('tx_bytes', 0))}</td>
  <td>{badge(e['probe_result']['ping_ok'], 'ping')} {badge(e['probe_result']['curl_ok'], e['probe_result'].get('public_ip') or 'curl')}</td>
</tr>"""
        )
    counters = "\n".join(html.escape(x) for x in data["nft_counters"])
    entry_metric = "" if WIREGUARD_ONLY else f'''<div class="panel"><div class="muted">Hysteria показывает</div><div class="metric">{html.escape(data["client_entrypoints"]["hysteria_process_external_ip"] or "n/a")}</div><div class="small">дополнительный вход</div></div>'''
    input_title = "WireGuard" if WIREGUARD_ONLY else "WireGuard + Hysteria"
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Cascade Monitor</title>
<style>
:root{{--ink:#e7f3ff;--muted:#8ea9c4;--sky:#020812;--panel:#061426;--panel2:#04111f;--line:#173f65;--mint:#4ebeff;--sun:#83dfff;--danger:#ff8da9;color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;font-family:ui-monospace,"Cascadia Mono","Segoe UI Mono",monospace;background-color:var(--sky);background-image:linear-gradient(rgba(63,137,196,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(63,137,196,.025) 1px,transparent 1px);background-size:22px 22px;color:var(--ink)}}main{{max-width:1220px;margin:0 auto;padding:28px}}h1{{font-size:28px;margin:0 0 6px}}h2{{font-size:18px;margin:28px 0 12px;color:var(--sun)}}.muted,td span,.exit-grid span,.step span{{color:var(--muted)}}.top,.toolbar{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}.toolbar{{align-items:center;justify-content:flex-end;flex-wrap:wrap}}.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}}.panel,.flow,.exit-card,details{{background:rgba(6,20,38,.92);border:1px solid var(--line);border-radius:12px;padding:14px;box-shadow:4px 4px 0 #01040a}}.metric{{font-size:26px;font-weight:800;margin-top:4px;line-height:1.15;color:var(--sun)}}.small{{font-size:13px;color:var(--muted)}}.flow{{margin-top:16px;display:grid;grid-template-columns:1fr 40px 1fr 40px 1fr;gap:10px;align-items:stretch}}.step{{min-height:112px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:14px}}.step b{{display:block;font-size:18px;margin:6px 0}}.arrow{{display:grid;place-items:center;color:var(--sun);font-size:26px}}.exit-list{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}.exit-card.live{{border-color:#2f8b67}}.exit-card.reserve{{border-color:#8b742f}}.exit-card.offline{{opacity:.72}}.exit-head{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}}.exit-head strong{{display:block;font-size:17px}}.exit-head span{{display:block;font-size:12px;margin-top:2px}}.bar{{height:8px;background:#0a2239;border-radius:999px;overflow:hidden;margin:14px 0}}.bar i{{display:block;height:100%;background:var(--mint);border-radius:999px}}.exit-card.reserve .bar i{{width:100%!important;background:#d3a83b}}.exit-card.offline .bar i{{background:#48637a}}.exit-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}.exit-grid b{{display:block;margin-top:3px;word-break:break-word}}.weights{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:12px 0}}.weight-row{{display:grid;grid-template-columns:1fr 82px;gap:10px;align-items:center;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px}}.weight-row small,.weight-row em{{display:block;color:var(--muted);font-size:12px;font-style:normal;margin-top:3px}}.weight-row input,select{{width:100%;border:1px solid #315f80;border-radius:8px;background:#020b15;color:var(--ink);padding:9px;font:inherit}}button,.button{{border:1px solid #5ecbff;border-radius:8px;background:#0b2d4c;color:var(--ink);padding:10px 13px;font:inherit;font-weight:800;cursor:pointer;text-decoration:none}}button:hover,.button:hover{{filter:brightness(1.15)}}table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);overflow:hidden}}td,th{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--sun);background:#09213a}}.badge{{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;background:#20364a;color:var(--ink);margin:1px;white-space:nowrap}}.ok{{background:#123c31;color:#92efbd}}.bad{{background:#4a2030;color:#ffb1c4}}.warn{{background:#4c3e16;color:#ffd86e}}pre{{white-space:pre-wrap;background:#020b15;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}}summary{{cursor:pointer;color:var(--sun);font-weight:800}}a{{color:var(--sun)}}@media(max-width:900px){{main{{padding:14px}}.grid,.exit-list,.flow,.weights{{grid-template-columns:1fr}}.arrow{{display:none}}td,th{{font-size:13px}}.top{{display:block}}.toolbar{{justify-content:flex-start;margin-top:14px}}}}
</style></head><body><main>
<div class="top"><div><h1>VPN Cascade Monitor</h1><div class="muted">{html.escape(data['hostname'])} · <span id="generated">{html.escape(data['generated_at'])}</span> · <span id="countdown">обновление через 60с</span></div></div><div class="toolbar"><select id="interval" aria-label="Интервал обновления"><option value="15">15с</option><option value="30">30с</option><option value="60" selected>60с</option><option value="0">пауза</option></select><button type="button" onclick="location.reload()">Обновить</button><button type="button" id="copyJson">Скопировать JSON</button><a class="button" href="api" download="cascade-status.json">JSON</a>{badge(system_ok, 'серввисы OK' if system_ok else 'есть проблема')}</div></div>
<section class="grid">
  <div class="panel"><div class="muted">Активный выход</div><div class="metric">{html.escape(active_name)}</div><div class="small">{html.escape(active_ip or route_summary)}</div></div>
  <div class="panel"><div class="muted">Доступно авто-выходов</div><div class="metric">{len(active_exits)} / {configured_exits}</div><div class="small">резервов готово: {len(ready_reserves)}</div></div>
  <div class="panel"><div class="muted">wg-easy показывает</div><div class="metric">{html.escape(wg_ip)}</div><div class="small">WireGuard-клиенты</div></div>
  {entry_metric}
</section>
<section class="flow">
  <div class="step"><span>Вход</span><b>{input_title}</b><div class="small">wg-easy: {html.escape(wg_ip)}</div></div>
  <div class="arrow">→</div>
  <div class="step"><span>Решение маршрута</span><b>{html.escape(route_summary)}</b><div class="small">RU/direct остаются в Москве, остальное идет в table 100</div></div>
  <div class="arrow">→</div>
  <div class="step"><span>Текущий выход</span><b>{html.escape(active_name)}</b><div class="small">{html.escape(active_ip or 'нет рабочего выхода')}</div></div>
</section>
<h2>Куда сейчас уходит трафик</h2><section class="exit-list">{''.join(exit_cards)}</section>
<h2>Балансировка</h2>
<form class="panel" method="post" action="weights">
  <div class="muted">Вес задает долю трафика среди живых auto-выходов. `0` временно убирает выход из балансировки, но не отключает WireGuard и не скрывает health-статус.</div>
  <div class="weights">{''.join(weight_rows)}</div>
  <button type="submit">Применить веса</button>
</form>
<details><summary>Технические детали</summary>
<h2>Exits</h2><table><thead><tr><th>Exit</th><th>Status</th><th>Weight</th><th>Handshake</th><th>RX / TX</th><th>Probe</th></tr></thead><tbody>{''.join(exit_rows)}</tbody></table>
<h2>Services</h2><table><tbody>{svc_rows}</tbody></table>
<h2>nft counters</h2><pre>{counters}</pre>
</details>
</main><script>
const select=document.getElementById('interval'), label=document.getElementById('countdown');let left=60,timer=null;
function schedule(){{clearInterval(timer);left=Number(select.value);if(!left){{label.textContent='автообновление на паузе';return}}timer=setInterval(()=>{{left-=1;label.textContent=`обновление через ${{left}}с`;if(left<=0)location.reload()}},1000)}}
select.addEventListener('change',schedule);schedule();
document.getElementById('copyJson').addEventListener('click',async e=>{{try{{const text=await fetch('api',{{cache:'no-store'}}).then(r=>r.text());await navigator.clipboard.writeText(text);e.currentTarget.textContent='JSON скопирован'}}catch(_err){{e.currentTarget.textContent='Не удалось скопировать'}}}});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(CLIENT_SOCKET_TIMEOUT)

    def log_message(self, _fmt, *_args):
        return

    def do_HEAD(self):
        if self.path not in ("/", "/api", "/api/", "/health"):
            self.send_response(404)
            self.end_headers()
            return
        data, age, _error = cache_snapshot()
        healthy = data is not None and age is not None and age <= CACHE_MAX_AGE
        status = 200 if data is not None else 503
        if self.path == "/health":
            status = 200 if healthy else 503
        self.send_response(status)
        if self.path.startswith("/api"):
            self.send_header("content-type", "application/json; charset=utf-8")
        elif self.path == "/health":
            self.send_header("content-type", "text/plain; charset=utf-8")
        else:
            self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.end_headers()

    def do_GET(self):
        if self.path not in ("/", "/api", "/api/", "/health"):
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/health":
            data, age, error = cache_snapshot()
            healthy = data is not None and age is not None and age <= CACHE_MAX_AGE
            age_text = "unknown" if age is None else f"{age:.1f}"
            body = f"{'ok' if healthy else 'stale'} age={age_text} error={error or '-'}\n".encode()
            self.send_response(200 if healthy else 503)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/api"):
            data = cached_api_data()
            if data is None:
                body = json.dumps({"error": "status cache is not ready"}).encode()
                self.send_response(503)
                self.send_header("content-type", "application/json; charset=utf-8")
                self.send_header("cache-control", "no-store")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = json.dumps(data, ensure_ascii=False, indent=2).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        data, _age, _error = cache_snapshot()
        if data is None:
            body = b"<h1>Status cache is not ready</h1>"
            self.send_response(503)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = render_html(data).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/weights":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("content-length", "0") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_POST_BODY:
            self.send_response(413)
            self.end_headers()
            return
        raw = self.rfile.read(length).decode()
        try:
            result = save_weights(parse_qs(raw))
        except ValueError as exc:
            body = f"<h1>Ошибка веса</h1><p>{html.escape(str(exc))}</p><p><a href='/'>Назад</a></p>".encode()
            self.send_response(400)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        CACHE_REFRESH.set()
        if not result["ok"]:
            body = f"<h1>Не удалось применить веса</h1><pre>{html.escape(result['err'] or result['out'])}</pre><p><a href='/'>Назад</a></p>".encode()
            self.send_response(500)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(303)
        self.send_header("location", "/")
        self.end_headers()


if __name__ == "__main__":
    threading.Thread(target=collector_loop, name="status-collector", daemon=True).start()
    BoundedThreadingHTTPServer(("127.0.0.1", 8090), Handler).serve_forever()
