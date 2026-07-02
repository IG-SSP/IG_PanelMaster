#!/usr/bin/env python3
import html
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

WEIGHTS_FILE = "/etc/cascade/exit-weights.conf"
CASCADE_HEALTH = "/usr/local/sbin/cascade-health"
EXITS = [
    {"name": "HELs-1", "iface": "wg-exit-hel1", "probe": "10.77.3.2", "expected_ip": "45.129.124.11", "weight": 10, "mode": "auto"},
    {"name": "DE-1", "iface": "wg-exit-de1", "probe": "10.77.4.2", "expected_ip": "213.176.114.234", "weight": 10, "mode": "auto"},
    {"name": "VIE-1", "iface": "wg-exit-vie1", "probe": "10.77.6.2", "expected_ip": "45.86.245.60", "weight": 10, "mode": "auto"},
    {"name": "AMS-3", "iface": "wg-exit-ams3", "probe": "10.77.7.2", "expected_ip": "45.94.37.67", "weight": 10, "mode": "auto"},
    {"name": "AMS-1", "iface": "wg-exit-ams1", "probe": "10.77.1.2", "expected_ip": "176.124.201.26", "weight": 3, "mode": "auto"},
    {"name": "AMS-2", "iface": "wg-exit-ams2", "probe": "10.77.2.2", "expected_ip": "185.125.202.109", "weight": 1, "mode": "auto"},
    {"name": "RU-Reserve", "iface": "wg-exit-ru1", "probe": "10.77.5.2", "expected_ip": "51.250.41.144", "weight": 0, "mode": "reserve"},
]

SERVICES = [
    "wg-quick@wg-exit-hel1.service",
    "wg-quick@wg-exit-de1.service",
    "wg-quick@wg-exit-vie1.service",
    "wg-quick@wg-exit-ams1.service",
    "wg-quick@wg-exit-ams2.service",
    "wg-quick@wg-exit-ru1.service",
    "cascade-routing.service",
    "cascade-health.timer",
    "hysteria-server.service",
    "hysteria-cert-sync.timer",
    "docker.service",
    "caddy.service",
]


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
    for item in EXITS:
        exit_ = dict(item)
        key = exit_key(exit_)
        exit_["key"] = key
        exit_["default_weight"] = item["weight"]
        if exit_.get("mode") != "reserve":
            exit_["weight"] = overrides.get(key, item["weight"])
        exits.append(exit_)
    return exits


def save_weights(params):
    allowed = {exit_key(e) for e in EXITS if e.get("mode") != "reserve"}
    lines = ["# Managed by cascade-monitor. Weight 0 disables an auto exit from balancing.\n"]
    for e in EXITS:
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


def service_states():
    result = {}
    for svc in SERVICES:
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
        "services": service_states(),
        "route_table_100": route,
        "exits": exits,
        "client_entrypoints": {
            "wg_easy_container_external_ip": wg_easy_ip(),
            "hysteria_process_external_ip": hysteria_ip(),
        },
        "nft_counters": nft_counters(),
    }


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
    hy_ip = data["client_entrypoints"]["hysteria_process_external_ip"] or "n/a"
    same_path = wg_ip != "n/a" and wg_ip == hy_ip
    active_name = active_exits[0]["name"] if active_exits else "нет активного выхода"
    active_ip = active_exits[0]["probe_result"].get("public_ip", "") if active_exits else ""
    system_ok = all(v == "active" for v in data["services"].values())
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
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="60">
<title>VPN Cascade Monitor</title>
<style>
body{{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0d1013;color:#eef2f4}}main{{max-width:1220px;margin:0 auto;padding:28px}}h1{{font-size:28px;margin:0 0 6px}}h2{{font-size:18px;margin:28px 0 12px}}.muted,td span,.exit-grid span,.step span{{color:#9aa5ad}}.top{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}}.panel,.flow,.exit-card,details{{background:#171c21;border:1px solid #2a323a;border-radius:8px;padding:14px}}.metric{{font-size:26px;font-weight:750;margin-top:4px;line-height:1.15}}.small{{font-size:13px;color:#aeb7be}}.flow{{margin-top:16px;display:grid;grid-template-columns:1fr 40px 1fr 40px 1fr;gap:10px;align-items:stretch}}.step{{min-height:112px;background:#11161a;border:1px solid #2a323a;border-radius:8px;padding:14px}}.step b{{display:block;font-size:18px;margin:6px 0}}.arrow{{display:grid;place-items:center;color:#7f8b95;font-size:26px}}.exit-list{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}.exit-card.live{{border-color:#2f6b4f}}.exit-card.reserve{{border-color:#75622b}}.exit-card.offline{{opacity:.72}}.exit-head{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}}.exit-head strong{{display:block;font-size:17px}}.exit-head span{{display:block;font-size:12px;margin-top:2px}}.bar{{height:8px;background:#273039;border-radius:999px;overflow:hidden;margin:14px 0}}.bar i{{display:block;height:100%;background:#52d98d;border-radius:999px}}.exit-card.reserve .bar i{{width:100%!important;background:#d3a83b}}.exit-card.offline .bar i{{background:#6b747d}}.exit-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}.exit-grid b{{display:block;margin-top:3px;word-break:break-word}}.weights{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:12px 0}}.weight-row{{display:grid;grid-template-columns:1fr 82px;gap:10px;align-items:center;background:#11161a;border:1px solid #2a323a;border-radius:8px;padding:12px}}.weight-row small,.weight-row em{{display:block;color:#9aa5ad;font-size:12px;font-style:normal;margin-top:3px}}.weight-row input{{width:100%;box-sizing:border-box;border:1px solid #3b4955;border-radius:8px;background:#0d1216;color:#eef2f4;padding:9px;font:inherit}}button{{border:0;border-radius:8px;background:#3978f2;color:white;padding:11px 15px;font:inherit;font-weight:700;cursor:pointer}}button:hover{{filter:brightness(1.08)}}table{{width:100%;border-collapse:collapse;background:#171c21;border:1px solid #2a323a;border-radius:8px;overflow:hidden}}td,th{{text-align:left;padding:10px;border-bottom:1px solid #2a323a;vertical-align:top}}th{{color:#c8d0d6;background:#20262c}}.badge{{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;background:#3a4148;color:#dbe2e7;margin:1px;white-space:nowrap}}.ok{{background:#153d2a;color:#92efbd}}.bad{{background:#4a2020;color:#ffb1a8}}.warn{{background:#4c3e16;color:#ffd86e}}pre{{white-space:pre-wrap;background:#11161a;border:1px solid #2a323a;border-radius:8px;padding:12px;overflow:auto}}summary{{cursor:pointer;color:#dfe7ec;font-weight:650}}a{{color:#8cc8ff}}@media(max-width:900px){{.grid,.exit-list,.flow,.weights{{grid-template-columns:1fr}}.arrow{{display:none}}td,th{{font-size:13px}}.top{{display:block}}}}
</style></head><body><main>
<div class="top"><div><h1>VPN Cascade Monitor</h1><div class="muted">{html.escape(data['hostname'])} · {html.escape(data['generated_at'])} · автообновление 60с · <a href="api">JSON</a></div></div><div>{badge(system_ok, 'сервисы OK' if system_ok else 'есть проблема')}</div></div>
<section class="grid">
  <div class="panel"><div class="muted">Активный выход</div><div class="metric">{html.escape(active_name)}</div><div class="small">{html.escape(active_ip or route_summary)}</div></div>
  <div class="panel"><div class="muted">Доступно авто-выходов</div><div class="metric">{len(active_exits)} / {configured_exits}</div><div class="small">резервов готово: {len(ready_reserves)}</div></div>
  <div class="panel"><div class="muted">wg-easy показывает</div><div class="metric">{html.escape(wg_ip)}</div><div class="small">WireGuard-клиенты</div></div>
  <div class="panel"><div class="muted">Hysteria Auto показывает</div><div class="metric">{html.escape(hy_ip)}</div><div class="small">{'тот же путь' if same_path else 'отличается от wg-easy'}</div></div>
</section>
<section class="flow">
  <div class="step"><span>Входы</span><b>WireGuard + Hysteria</b><div class="small">wg-easy: {html.escape(wg_ip)}<br>Hysteria: {html.escape(hy_ip)}</div></div>
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
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        return

    def do_HEAD(self):
        if self.path not in ("/", "/api", "/api/", "/health"):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        if self.path.startswith("/api"):
            self.send_header("content-type", "application/json; charset=utf-8")
        elif self.path == "/health":
            self.send_header("content-type", "text/plain; charset=utf-8")
        else:
            self.send_header("content-type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        if self.path not in ("/", "/api", "/api/", "/health"):
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        data = collect()
        if self.path.startswith("/api"):
            body = json.dumps(data, ensure_ascii=False, indent=2).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        body = render_html(data).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/weights":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("content-length", "0") or "0")
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
    ThreadingHTTPServer(("127.0.0.1", 8090), Handler).serve_forever()
