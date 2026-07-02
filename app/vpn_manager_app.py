#!/usr/bin/env python3
import json
import os
import base64
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / ".vpn-state" / "network.json"
PROFILES_PATH = ROOT / ".vpn-state" / "profiles.json"
SECRETS_PATH = ROOT / ".vpn-secrets" / "network.secrets.json"
EXAMPLE_PATH = ROOT / "config" / "network.example.json"
OUTPUT_DIR = ROOT / "build" / "generated"
ORCHESTRATOR = ROOT / "tools" / "vpn-orchestrator.ps1"
JOBS = {}
JOBS_LOCK = threading.Lock()
DEBUG_LOG_PATH = ROOT / "build" / "logs" / "vpn-manager-debug.log"


def debug_log(message):
    try:
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DEBUG_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except Exception:
        pass


def read_json(path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def default_manifest():
    return read_json(EXAMPLE_PATH, {
        "productVersion": 1,
        "admin": {
            "configured": False,
            "lastLogin": "",
        },
        "ingress": {
            "name": "primary-ingress",
            "host": "",
            "sshUser": "root",
            "domain": "",
            "publicIp": "",
            "publicInterface": "eth0",
            "clientSourceIp": "10.42.42.42",
            "wgPort": 51820,
            "hysteriaUser": "hysteria",
        },
        "routing": {
            "tableId": 100,
            "reserveTableId": 101,
            "mark": "0x77",
            "reserveMark": "0x78",
            "directDomains": [],
            "reserveDomains": [],
        },
        "protocols": {
            "wireguard": True,
            "hysteria": True,
            "mtproto": False,
            "clientPortal": True,
            "monitoring": True,
        },
        "users": [],
        "exits": [],
    })


def normalize_manifest(manifest):
    base = default_manifest()
    manifest.setdefault("productVersion", base["productVersion"])
    manifest.setdefault("admin", base["admin"])
    manifest.setdefault("ingress", base["ingress"])
    manifest.setdefault("routing", base["routing"])
    manifest.setdefault("protocols", base["protocols"])
    manifest.setdefault("users", base["users"])
    manifest.setdefault("exits", base["exits"])
    for key, value in base["admin"].items():
        manifest["admin"].setdefault(key, value)
    for key, value in base["ingress"].items():
        manifest["ingress"].setdefault(key, value)
    for key, value in base["routing"].items():
        manifest["routing"].setdefault(key, value)
    for key, value in base["protocols"].items():
        manifest["protocols"].setdefault(key, value)
    return manifest


def default_secrets():
    return {
        "ssh": {"ingressKeyPath": "", "serverPasswords": {}},
        "wireguard": {
            "ingress": {"privateKey": "", "publicKey": ""},
            "exits": {},
        },
        "telegram": {"botToken": "", "botUsername": "", "adminTelegramIds": ""},
    }


def load_manifest():
    return normalize_manifest(read_json(MANIFEST_PATH, default_manifest()))


def profile_id(value):
    value = "".join(ch.lower() if ch.isalnum() else "-" for ch in (value or "").strip())
    value = "-".join(part for part in value.split("-") if part)
    return value or "network-profile"


def load_profiles():
    data = read_json(PROFILES_PATH, {"profiles": []})
    profiles = data.get("profiles", []) if isinstance(data, dict) else []
    return profiles


def save_profiles(profiles):
    write_json(PROFILES_PATH, {"profiles": profiles})


def save_network_profile(manifest):
    manifest = normalize_manifest(manifest)
    name = manifest.get("profileName") or manifest.get("ingress", {}).get("name") or "Network profile"
    pid = manifest.get("profileId") or profile_id(name)
    manifest["profileId"] = pid
    manifest["profileName"] = name
    snapshot = json.loads(json.dumps(manifest, ensure_ascii=False))
    snapshot.setdefault("admin", {})["configured"] = False
    profiles = [p for p in load_profiles() if p.get("id") != pid]
    profiles.append({
        "id": pid,
        "name": name,
        "ingressHost": manifest.get("ingress", {}).get("host", ""),
        "exits": len(manifest.get("exits", [])),
        "manifest": snapshot,
    })
    save_profiles(profiles)
    return profiles[-1]


def load_network_profile(pid):
    for item in load_profiles():
        if item.get("id") == pid:
            manifest = normalize_manifest(item.get("manifest") or default_manifest())
            manifest["profileId"] = item.get("id")
            manifest["profileName"] = item.get("name")
            manifest.setdefault("admin", {})["configured"] = True
            write_json(MANIFEST_PATH, manifest)
            return manifest
    return None


def load_secrets():
    return read_json(SECRETS_PATH, default_secrets())


def secret_status(secrets, manifest):
    wg = secrets.get("wireguard", {})
    ingress = wg.get("ingress", {})
    exits = wg.get("exits", {})
    return {
        "ingressPrivateKey": bool(ingress.get("privateKey")),
        "ingressPublicKey": bool(ingress.get("publicKey")),
        "telegramBotToken": bool(secrets.get("telegram", {}).get("botToken")),
        "telegramBotUsername": bool(secrets.get("telegram", {}).get("botUsername")),
        "adminTelegramIds": bool(secrets.get("telegram", {}).get("adminTelegramIds")),
        "exits": {
            e.get("name", ""): {
                "privateKey": bool(exits.get(e.get("name", ""), {}).get("privateKey")),
                "publicKey": bool(exits.get(e.get("name", ""), {}).get("publicKey")),
                "presharedKey": bool(exits.get(e.get("name", ""), {}).get("presharedKey")),
            }
            for e in manifest.get("exits", [])
        },
    }


def generated_files():
    if not OUTPUT_DIR.exists():
        return []
    result = []
    for path in sorted(OUTPUT_DIR.glob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            result.append({
                "name": path.name,
                "size": path.stat().st_size,
                "hasMissingSecrets": "__MISSING_" in text,
                "preview": text[:12000],
            })
    return result


def merge_secret_values(current, incoming):
    current.setdefault("ssh", {})
    current.setdefault("wireguard", {}).setdefault("ingress", {})
    current.setdefault("wireguard", {}).setdefault("exits", {})
    current.setdefault("telegram", {})
    ssh_key_path = str(incoming.get("ssh", {}).get("ingressKeyPath", "")).strip()
    if ssh_key_path:
        current["ssh"]["ingressKeyPath"] = ssh_key_path
    for name, password in incoming.get("ssh", {}).get("serverPasswords", {}).items():
        password = str(password or "")
        if password:
            current["ssh"].setdefault("serverPasswords", {})[str(name)] = password
    wg_in = incoming.get("wireguard", {})
    ingress_in = wg_in.get("ingress", {})
    for key in ("privateKey", "publicKey"):
        value = str(ingress_in.get(key, "")).strip()
        if value:
            current["wireguard"]["ingress"][key] = value
    exits_in = wg_in.get("exits", {})
    for name, values in exits_in.items():
        current["wireguard"]["exits"].setdefault(name, {})
        for key in ("privateKey", "publicKey", "presharedKey"):
            value = str(values.get(key, "")).strip()
            if value:
                current["wireguard"]["exits"][name][key] = value
    for key in ("botToken", "botUsername", "adminTelegramIds"):
        value = str(incoming.get("telegram", {}).get(key, "")).strip()
        if value:
            current["telegram"][key] = value
    return current


P = 2 ** 255 - 19
A24 = 121665


def x25519(k, u=9):
    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) ** 2) % P
        z3 = (x1 * ((da - cb) ** 2)) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P)) % P


def wg_private_key():
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return base64.b64encode(bytes(raw)).decode("ascii")


def wg_public_key(private_key):
    raw = base64.b64decode(private_key)
    k = int.from_bytes(raw, "little")
    pub = x25519(k, 9).to_bytes(32, "little")
    return base64.b64encode(pub).decode("ascii")


def wg_preshared_key():
    return base64.b64encode(os.urandom(32)).decode("ascii")


def ensure_wireguard_secrets(manifest, secrets):
    wg = secrets.setdefault("wireguard", {})
    ingress = wg.setdefault("ingress", {})
    if not ingress.get("privateKey"):
        ingress["privateKey"] = wg_private_key()
    if not ingress.get("publicKey"):
        ingress["publicKey"] = wg_public_key(ingress["privateKey"])
    exits = wg.setdefault("exits", {})
    for item in manifest.get("exits", []):
        name = item.get("name") or "exit"
        entry = exits.setdefault(name, {})
        if not entry.get("privateKey"):
            entry["privateKey"] = wg_private_key()
        if not entry.get("publicKey"):
            entry["publicKey"] = wg_public_key(entry["privateKey"])
        if not entry.get("presharedKey"):
            entry["presharedKey"] = wg_preshared_key()
    return secrets


DISCOVERY_SCRIPT = r'''
set -eu
hostname="$(hostname 2>/dev/null || true)"
default_iface="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}' || true)"
public_ip="$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
if [ -z "$public_ip" ]; then
  public_ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}' || true)"
fi
domain=""
if [ -f /etc/caddy/Caddyfile ]; then
  domain="$(awk '/^[A-Za-z0-9_.-]+[[:space:]]*\{/ {gsub("{","",$1); print $1; exit}' /etc/caddy/Caddyfile 2>/dev/null || true)"
fi
services=""
for svc in client-portal.service cascade-monitor.service caddy.service hysteria-server.service docker.service cascade-routing.service cascade-health.timer; do
  state="$(systemctl is-active "$svc" 2>/dev/null || true)"
  services="${services}${svc}=${state};"
done
wg_easy=0
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'wg-easy'; then
  wg_easy=1
fi
python3 - "$hostname" "$default_iface" "$public_ip" "$domain" "$wg_easy" "$services" <<'PY'
import json, sys
services = {}
for item in sys.argv[6].strip(';').split(';'):
    if '=' in item:
        k, v = item.split('=', 1)
        services[k] = v
print(json.dumps({
    'hostname': sys.argv[1],
    'publicInterface': sys.argv[2],
    'publicIp': sys.argv[3],
    'domain': sys.argv[4],
    'wgEasy': sys.argv[5] == '1',
    'services': services,
}, ensure_ascii=False))
PY
'''


def build_remote_command(host, ssh_user, key_path, password, remote_command, batch=True, host_key=""):
    host = str(host or '').strip()
    ssh_user = str(ssh_user or 'root').strip() or 'root'
    key_path = os.path.expandvars(os.path.expanduser(str(key_path or '').strip()))
    password = str(password or '')
    if key_path and not os.path.isabs(key_path):
        key_path = str(ROOT / key_path)
    if not host:
        raise ValueError('host is required')
    target = f'{ssh_user}@{host}'
    if password:
        plink = shutil.which('plink') or shutil.which('plink.exe')
        if not plink:
            raise RuntimeError('Password auth requires PuTTY plink.exe in PATH. Install PuTTY or use an SSH key.')
        cmd = [
            plink,
            '-ssh',
            '-batch',
            '-pw',
            password,
            '-no-antispoof',
        ]
        if host_key:
            cmd.extend(['-hostkey', str(host_key).strip()])
        return cmd + [target, remote_command]
    if not key_path:
        raise ValueError('ssh key path is required')
    if not os.path.exists(key_path):
        raise ValueError(f'ssh key not found: {key_path}')
    options = [
        'ssh', '-i', key_path,
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=8',
    ]
    if batch:
        options.extend(['-o', 'BatchMode=yes'])
    return options + [target, remote_command]


def write_temp_script(script_text):
    script_text = str(script_text or "").replace("\r\n", "\n").replace("\r", "\n")
    handle = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", newline="\n", suffix=".sh")
    try:
        handle.write(script_text)
        return handle.name
    finally:
        handle.close()


def build_plink_file_command(host, ssh_user, password, host_key, command_file):
    cmd = build_remote_command(host, ssh_user, "", password, "", host_key=host_key)
    target = cmd[-2]
    return cmd[:-2] + ["-m", str(command_file)] + [target]


def build_pscp_upload_command(host, ssh_user, password, host_key, local_path, remote_path):
    host = str(host or '').strip()
    ssh_user = str(ssh_user or 'root').strip() or 'root'
    if not host:
        raise ValueError('host is required')
    pscp = shutil.which('pscp') or shutil.which('pscp.exe')
    if not pscp:
        raise RuntimeError('Password auth upload requires PuTTY pscp.exe in PATH.')
    cmd = [pscp, '-batch', '-pw', str(password or '')]
    if host_key:
        cmd.extend(['-hostkey', str(host_key).strip()])
    return cmd + [str(local_path), f'{ssh_user}@{host}:{remote_path}']


def extract_ssh_host_key(text):
    for line in str(text or "").splitlines():
        line = line.strip()
        if "SHA256:" in line:
            return line[line.find("SHA256:"):].split()[0]
    return ""


def host_key_failure(text):
    text = str(text or "")
    return (
        "Host key not in manually configured list" in text
        or "The host key is not cached for this server" in text
        or "Cannot confirm a host key in batch mode" in text
    )


def probe_ssh_host_key(host, ssh_user, password):
    if not password:
        return ""
    temp_path = write_temp_script("exit 0\n")
    try:
        cmd = build_plink_file_command(host, ssh_user, password, "", temp_path)
        proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=20)
        return extract_ssh_host_key(f"{proc.stdout}\n{proc.stderr}")
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def discover_ingress(host, ssh_user, key_path, password=''):
    host_key = load_secrets().get("ssh", {}).get("hostKeys", {}).get(str(host or "").strip(), "")
    cmd = build_remote_command(host, ssh_user, key_path, password, f"bash -lc {json.dumps(DISCOVERY_SCRIPT)}", host_key=host_key)
    proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=25)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or 'ssh discovery failed').strip())
    try:
        return json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'invalid discovery output: {proc.stdout[:500]}') from exc


def fetch_ingress_monitor(host, ssh_user, key_path, password=''):
    remote = "curl -fsS --connect-timeout 3 --max-time 8 http://127.0.0.1:8090/api"
    host_key = load_secrets().get("ssh", {}).get("hostKeys", {}).get(str(host or "").strip(), "")
    cmd = build_remote_command(host, ssh_user, key_path, password, remote, host_key=host_key)
    proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=20)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or 'monitor api unavailable').strip())
    try:
        return json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'invalid monitor output: {proc.stdout[:500]}') from exc


def merge_monitor_into_manifest(manifest, monitor, connection):
    manifest = normalize_manifest(manifest)
    host = str(connection.get("host", "")).strip()
    ssh_user = str(connection.get("sshUser", "root")).strip() or "root"
    hostname = str(monitor.get("hostname") or "").strip()
    services = monitor.get("services") or {}
    old_exits = {str(item.get("name", "")): item for item in manifest.get("exits", [])}
    old_by_iface = {str(item.get("iface", "")): item for item in manifest.get("exits", [])}

    if hostname:
        manifest["profileName"] = manifest.get("profileName") or hostname
        manifest["ingress"]["name"] = hostname
    if host:
        manifest["ingress"]["host"] = host
        manifest["ingress"]["publicIp"] = manifest["ingress"].get("publicIp") or host
    manifest["ingress"]["sshUser"] = ssh_user
    manifest["admin"]["configured"] = True
    manifest["protocols"]["monitoring"] = True
    manifest["protocols"]["wireguard"] = bool(monitor.get("exits")) or services.get("docker.service") == "active"
    manifest["protocols"]["hysteria"] = services.get("hysteria-server.service") == "active"
    manifest["protocols"]["clientPortal"] = services.get("client-portal.service") == "active" or services.get("caddy.service") == "active"

    exits = []
    for idx, item in enumerate(monitor.get("exits") or []):
        name = str(item.get("name") or item.get("key") or f"exit-{idx + 1}")
        iface = str(item.get("iface") or "")
        previous = old_exits.get(name) or old_by_iface.get(iface) or {}
        probe_result = item.get("probe_result") or {}
        wg = item.get("wg") or {}
        listen_port = previous.get("listenPort") or wg.get("listen_port") or (51830 + idx)
        try:
            listen_port = int(listen_port)
        except (TypeError, ValueError):
            listen_port = 51830 + idx
        public_ip = (
            previous.get("publicIp")
            or item.get("expected_ip")
            or probe_result.get("public_ip")
            or previous.get("host")
            or ""
        )
        exit_item = {
            "name": name,
            "mode": item.get("mode") or previous.get("mode") or "auto",
            "host": previous.get("host") or public_ip,
            "sshUser": previous.get("sshUser") or "root",
            "publicIp": public_ip,
            "publicInterface": previous.get("publicInterface") or "eth0",
            "iface": iface or previous.get("iface") or f"wg-exit-{safe_slug(name, str(idx + 1))}",
            "ingressAddress": previous.get("ingressAddress") or "",
            "exitAddress": previous.get("exitAddress") or item.get("probe") or "",
            "prefixLength": previous.get("prefixLength") or 30,
            "listenPort": listen_port,
            "weight": int(item.get("weight") or 0),
            "defaultWeight": item.get("default_weight", item.get("weight", previous.get("defaultWeight", 0))),
            "monitorKey": item.get("key") or "",
            "lastMonitorStatus": "active" if item.get("in_route_table") else "standby",
        }
        exits.append(exit_item)

    if exits:
        manifest["exits"] = exits
    return manifest


def sync_manifest_from_monitor(connection):
    monitor = fetch_ingress_monitor(
        str(connection.get("host", "")).strip(),
        str(connection.get("sshUser", "root")).strip() or "root",
        str(connection.get("keyPath", "")).strip(),
        str(connection.get("password", "")),
    )
    manifest = merge_monitor_into_manifest(load_manifest(), monitor, connection)
    write_json(MANIFEST_PATH, manifest)
    profile = save_network_profile(manifest)
    return {"ok": True, "manifest": manifest, "profile": profile, "profiles": load_profiles(), "monitor": monitor}


def run_render():
    if not MANIFEST_PATH.exists():
        write_json(MANIFEST_PATH, default_manifest())
    if not SECRETS_PATH.exists():
        write_json(SECRETS_PATH, default_secrets())
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ORCHESTRATOR),
        "render",
        "-ManifestPath",
        str(MANIFEST_PATH),
        "-SecretsPath",
        str(SECRETS_PATH),
        "-OutputDir",
        str(OUTPUT_DIR),
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=60)
    return {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}


def safe_slug(value, fallback="server"):
    value = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    value = "-".join(part for part in value.split("-") if part)
    return value or fallback


def sh_quote(value):
    return "'" + str(value or "").replace("'", "'\"'\"'") + "'"


def service_iface(server, idx=0):
    explicit = str(server.get("iface") or "").strip()
    if explicit and len(explicit) <= 15:
        return explicit
    slug = safe_slug(server.get("name"), f"{idx + 1}")[:8]
    return f"wgvm-{slug}"[:15]


def service_wireguard_script(server, role, manifest, secrets):
    if not manifest.get("protocols", {}).get("wireguard", True):
        return ""
    wg = secrets.get("wireguard", {})
    ingress_secret = wg.get("ingress", {})
    ingress_private = ingress_secret.get("privateKey", "")
    ingress_public = ingress_secret.get("publicKey", "")
    client_source = manifest.get("ingress", {}).get("clientSourceIp") or "10.42.42.42"
    table_id = int(manifest.get("routing", {}).get("tableId") or 100)
    reserve_table_id = int(manifest.get("routing", {}).get("reserveTableId") or 101)
    mark = manifest.get("routing", {}).get("mark") or "0x77"
    reserve_mark = manifest.get("routing", {}).get("reserveMark") or "0x78"
    exits = manifest.get("exits", [])
    if role == "exit":
        exit_secret = wg.get("exits", {}).get(server.get("name") or "", {})
        iface = service_iface(server)
        ingress_addr = server.get("ingressAddress") or "10.77.11.1"
        exit_addr = server.get("exitAddress") or "10.77.11.2"
        prefix = int(server.get("prefixLength") or 30)
        listen_port = int(server.get("listenPort") or 51830)
        public_iface = server.get("publicInterface") or "eth0"
        private_key = exit_secret.get("privateKey", "")
        psk = exit_secret.get("presharedKey", "")
        return f"""
echo "[stage] configure-service-wireguard"
mkdir -p /etc/wireguard
if container_exists wg-easy; then
  echo "Detected existing wg-easy container; service tunnel will use {iface} and will not edit wg-easy peers."
  docker exec wg-easy sh -c 'wg show interfaces 2>/dev/null || true' 2>/dev/null | sed 's/^/wg-easy-interface=/' || true
fi
cat >/etc/wireguard/{iface}.conf <<EOF
[Interface]
Address = {exit_addr}/{prefix}
ListenPort = {listen_port}
PrivateKey = {private_key}
Table = off

[Peer]
PublicKey = {ingress_public}
PresharedKey = {psk}
AllowedIPs = {ingress_addr}/32, {client_source}/32
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/{iface}.conf
systemctl enable wg-quick@{iface}.service
systemctl restart wg-quick@{iface}.service
iptables -C FORWARD -i {iface} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {iface} -j ACCEPT
iptables -C FORWARD -o {iface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o {iface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s {ingress_addr}/32 -o {public_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {ingress_addr}/32 -o {public_iface} -j MASQUERADE
iptables -t nat -C POSTROUTING -s {client_source}/32 -o {public_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {client_source}/32 -o {public_iface} -j MASQUERADE
"""
    auto_nexthops = []
    reserve_nexthops = []
    configs = []
    for idx, exit_item in enumerate(exits):
        exit_secret = wg.get("exits", {}).get(exit_item.get("name") or "", {})
        iface = service_iface(exit_item, idx)
        ingress_addr = exit_item.get("ingressAddress") or f"10.77.{11 + idx}.1"
        exit_addr = exit_item.get("exitAddress") or f"10.77.{11 + idx}.2"
        prefix = int(exit_item.get("prefixLength") or 30)
        endpoint = exit_item.get("publicIp") or exit_item.get("host") or ""
        listen_port = int(exit_item.get("listenPort") or (51830 + idx))
        weight = int(exit_item.get("weight") or 1)
        psk = exit_secret.get("presharedKey", "")
        public_key = exit_secret.get("publicKey", "")
        configs.append(f"""
cat >/etc/wireguard/{iface}.conf <<EOF
[Interface]
Address = {ingress_addr}/{prefix}
PrivateKey = {ingress_private}
Table = off

[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
Endpoint = {endpoint}:{listen_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/{iface}.conf
systemctl enable wg-quick@{iface}.service
systemctl restart wg-quick@{iface}.service
""")
        nexthop = f"nexthop dev {iface} weight {max(1, weight)}"
        if exit_item.get("mode") == "reserve":
            reserve_nexthops.append(nexthop)
        else:
            auto_nexthops.append(nexthop)
    if not configs:
        return """
echo "[stage] configure-service-wireguard"
echo "No exit servers in manifest; service WireGuard routing skipped."
"""
    auto_route = f"ip route replace default table {table_id} {' '.join(auto_nexthops)}" if auto_nexthops else "true"
    reserve_route = f"ip route replace default table {reserve_table_id} {' '.join(reserve_nexthops)}" if reserve_nexthops else "true"
    return f"""
echo "[stage] configure-service-wireguard"
mkdir -p /etc/wireguard /etc/vpn-manager /etc/iproute2
{''.join(configs)}
grep -qE '^[[:space:]]*{table_id}[[:space:]]+vpn_manager$' /etc/iproute2/rt_tables || printf '{table_id} vpn_manager\\n' >> /etc/iproute2/rt_tables
grep -qE '^[[:space:]]*{reserve_table_id}[[:space:]]+vpn_manager_reserve$' /etc/iproute2/rt_tables || printf '{reserve_table_id} vpn_manager_reserve\\n' >> /etc/iproute2/rt_tables
{auto_route}
{reserve_route}
ip rule add pref 100 fwmark {mark} table {table_id} 2>/dev/null || true
ip rule add pref 90 fwmark {reserve_mark} table {reserve_table_id} 2>/dev/null || true
cat >/etc/vpn-manager/cascade.nft <<EOF
table inet vpn_manager_cascade {{
  set direct4 {{
    type ipv4_addr
    flags interval
    auto-merge
    elements = {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }}
  }}
  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    ip saddr {client_source} ip daddr != @direct4 counter meta mark set {mark}
  }}
}}
EOF
nft delete table inet vpn_manager_cascade 2>/dev/null || true
nft -f /etc/vpn-manager/cascade.nft
ip route flush cache
"""


def bootstrap_script(server, role, manifest, secrets):
    name = safe_slug(server.get("name"), role)
    public_ip = server.get("publicIp") or server.get("host") or ""
    wg_port = int(server.get("wgPort") or (51820 if role == "ingress" else 51830))
    ui_port = int(server.get("uiPort") or (51821 if role == "ingress" else 51831))
    hysteria_port = int(server.get("hysteriaPort") or (8443 if role == "ingress" else 8444))
    domain = server.get("domain") or manifest.get("ingress", {}).get("domain", "")
    protocols = manifest.get("protocols", {})
    wg_mode = server.get("wgEasyMode") or ("install" if role == "ingress" else "install")
    preserve_existing_wg = role == "exit" and wg_mode == "existing"
    install_wg = "true" if protocols.get("wireguard", True) and not preserve_existing_wg else "false"
    install_hysteria = "true" if protocols.get("hysteria", True) else "false"
    insecure = "true" if role == "exit" or (role == "ingress" and not domain) else "false"
    wg_host = domain if role == "ingress" and domain else public_ip
    hysteria_password = "__SET_HYSTERIA_PASSWORD__"
    service_wg = service_wireguard_script(server, role, manifest, secrets)
    return f"""#!/usr/bin/env bash
set -euo pipefail

ROLE={sh_quote(role)}
SERVER_NAME={sh_quote(name)}
WG_HOST={sh_quote(wg_host)}
WG_PORT={wg_port}
WG_UI_PORT={ui_port}
WG_INSECURE={insecure}
INSTALL_WG_EASY={install_wg}
INSTALL_HYSTERIA={install_hysteria}
HYSTERIA_PORT={hysteria_port}
HYSTERIA_PASSWORD={sh_quote(hysteria_password)}
WG_EASY_MODE={sh_quote(wg_mode)}
FORCE_REINSTALL="${{FORCE_REINSTALL:-false}}"

echo "[stage] validate-root"
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root or use a root-capable SSH user." >&2
  exit 1
fi

echo "[stage] validate-os"
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This bootstrap currently supports Debian/Ubuntu servers with apt-get." >&2
  exit 1
fi

port_in_use() {{
  local port="$1"
  ss -lntup 2>/dev/null | grep -Eq "[:.]$port[[:space:]]"
}}

container_exists() {{
  command -v docker >/dev/null 2>&1 && docker ps -a --format '{{{{.Names}}}}' 2>/dev/null | grep -qx "$1"
}}

backup_dir="/root/vpn-manager-backups/$SERVER_NAME-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"
cp -a /opt/wg-easy /etc/hysteria /etc/systemd/system/hysteria-server.service "$backup_dir"/ 2>/dev/null || true
echo "[stage] backup-created $backup_dir"

echo "[stage] install-packages"
export DEBIAN_FRONTEND=noninteractive
export TERM="${{TERM:-dumb}}"
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release iptables nftables wireguard wireguard-tools openssl

if ! command -v docker >/dev/null 2>&1; then
  echo "[stage] install-docker"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

echo "[stage] enable-forwarding"
systemctl enable --now docker
sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\\n' >/etc/sysctl.d/99-vpn-manager-forward.conf

if [ "$INSTALL_WG_EASY" = "true" ]; then
  echo "[stage] configure-wg-easy"
  if container_exists wg-easy && [ "$FORCE_REINSTALL" != "true" ]; then
    echo "wg-easy container already exists; leaving it unchanged. Set FORCE_REINSTALL=true to replace it."
  else
    if port_in_use "$WG_PORT" && [ "$FORCE_REINSTALL" != "true" ]; then
      echo "Port $WG_PORT is already in use; not installing wg-easy." >&2
      exit 1
    fi
    if port_in_use "$WG_UI_PORT" && [ "$FORCE_REINSTALL" != "true" ]; then
      echo "Port $WG_UI_PORT is already in use; not installing wg-easy UI." >&2
      exit 1
    fi
    mkdir -p /opt/wg-easy
    cat >/opt/wg-easy/docker-compose.yml <<EOF
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:15
    container_name: wg-easy
    environment:
      - WG_HOST=$WG_HOST
      - WG_PORT=$WG_PORT
      - INSECURE=$WG_INSECURE
    volumes:
      - wg-easy_etc_wireguard:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    ports:
      - "$WG_PORT:51820/udp"
      - "$WG_UI_PORT:51821/tcp"
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    restart: unless-stopped
volumes:
  wg-easy_etc_wireguard:
EOF
    docker compose -f /opt/wg-easy/docker-compose.yml up -d
  fi
fi

if [ "$INSTALL_WG_EASY" != "true" ] && [ "$WG_EASY_MODE" = "existing" ]; then
  echo "[stage] preserve-existing-wg-easy"
  echo "Existing wg-easy mode: leaving current container, config and client profiles unchanged."
  if ! container_exists wg-easy; then
    echo "Existing wg-easy mode was selected, but container wg-easy was not found." >&2
    exit 1
  fi
fi

{service_wg}

if [ "$INSTALL_HYSTERIA" = "true" ]; then
  echo "[stage] inspect-hysteria"
  if systemctl is-active --quiet hysteria-server.service && [ "$FORCE_REINSTALL" != "true" ]; then
    echo "hysteria-server.service is already active; leaving it unchanged. Set FORCE_REINSTALL=true to replace it."
    INSTALL_HYSTERIA=false
  fi
fi

if [ "$INSTALL_HYSTERIA" = "true" ]; then
  echo "[stage] configure-hysteria"
  if port_in_use "$HYSTERIA_PORT" && [ "$FORCE_REINSTALL" != "true" ]; then
    echo "Port $HYSTERIA_PORT is already in use; not installing Hysteria." >&2
    exit 1
  fi
  if [ "$HYSTERIA_PASSWORD" = "__SET_HYSTERIA_PASSWORD__" ]; then
    HYSTERIA_PASSWORD="$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)"
    echo "$HYSTERIA_PASSWORD" >/root/hysteria-password.txt
    chmod 600 /root/hysteria-password.txt
  fi
  curl -fsSL https://get.hy2.sh/ -o /tmp/install-hysteria.sh
  bash /tmp/install-hysteria.sh
  mkdir -p /etc/hysteria
  if [ ! -s /etc/hysteria/server.crt ] || [ ! -s /etc/hysteria/server.key ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout /etc/hysteria/server.key \
      -out /etc/hysteria/server.crt \
      -subj "/CN=$WG_HOST" \
      -days 3650 >/dev/null 2>&1
    chmod 600 /etc/hysteria/server.key
    chmod 644 /etc/hysteria/server.crt
  fi
  cat >/etc/hysteria/config.yaml <<EOF
listen: :$HYSTERIA_PORT
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: $HYSTERIA_PASSWORD
masquerade:
  type: proxy
  proxy:
    url: https://www.cloudflare.com/
    rewriteHost: true
EOF
  cat >/etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl reset-failed hysteria-server.service 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable --now hysteria-server.service
fi

echo "[stage] verify-services"
systemctl is-active docker >/dev/null 2>&1 && echo "docker active" || echo "docker not active"
if [ "$INSTALL_HYSTERIA" = "true" ]; then
  systemctl is-active hysteria-server.service >/dev/null 2>&1 && echo "hysteria active" || echo "hysteria not active"
fi

if [ "$ROLE" = "exit" ]; then
  if [ "$WG_EASY_MODE" = "existing" ]; then
    EXTRA_NOTE="Existing wg-easy was preserved. Connect it manually or via import flow; current client profiles were not changed."
  else
    EXTRA_NOTE="For exit servers wg-easy is started with INSECURE=true so the first browser setup can be completed."
  fi
else
  EXTRA_NOTE="Ingress wg-easy keeps its existing configuration unless FORCE_REINSTALL=true is set."
fi

cat <<EOF

Bootstrap finished for $SERVER_NAME ($ROLE).
wg-easy UI: http://$WG_HOST:$WG_UI_PORT/
$EXTRA_NOTE
If Hysteria was enabled, password is in /root/hysteria-password.txt unless explicitly set in this script.
EOF
"""


def render_bootstrap_files(manifest):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    secrets = ensure_wireguard_secrets(manifest, load_secrets())
    write_json(SECRETS_PATH, secrets)
    files = []
    ingress = dict(manifest.get("ingress", {}))
    ingress.setdefault("role", "ingress")
    ingress.setdefault("name", ingress.get("name") or "ingress")
    ingress.setdefault("host", ingress.get("host") or ingress.get("publicIp") or "")
    ingress.setdefault("publicIp", ingress.get("publicIp") or ingress.get("host") or "")
    ingress_path = OUTPUT_DIR / "bootstrap-ingress.sh"
    ingress_path.write_text(bootstrap_script(ingress, "ingress", manifest, secrets), encoding="utf-8")
    files.append(ingress_path.name)
    for item in manifest.get("exits", []):
        server = dict(item)
        server.setdefault("host", server.get("host") or server.get("publicIp") or "")
        server.setdefault("publicIp", server.get("publicIp") or server.get("host") or "")
        path = OUTPUT_DIR / f"bootstrap-exit-{safe_slug(server.get('name'), 'exit')}.sh"
        path.write_text(bootstrap_script(server, "exit", manifest, secrets), encoding="utf-8")
        files.append(path.name)
    return files


def bootstrap_files_for_manifest(manifest):
    files = [{"file": "bootstrap-ingress.sh", "role": "ingress", "server": manifest.get("ingress", {})}]
    for item in manifest.get("exits", []):
        files.append({
            "file": f"bootstrap-exit-{safe_slug(item.get('name'), 'exit')}.sh",
            "role": "exit",
            "server": item,
        })
    return files


def server_has_auth(server, secrets):
    host = server.get("host") or server.get("publicIp") or ""
    passwords = secrets.get("ssh", {}).get("serverPasswords", {})
    key_path = secrets.get("ssh", {}).get("ingressKeyPath", "")
    password = passwords.get(server.get("name", "")) or passwords.get(host) or ""
    return bool(key_path or password), bool(password), bool(key_path)


def installation_plan():
    manifest = load_manifest()
    secrets = load_secrets()
    existing = {item.get("name") for item in generated_files()}
    steps = []
    for idx, item in enumerate(bootstrap_files_for_manifest(manifest), start=1):
        server = dict(item["server"])
        host = server.get("host") or server.get("publicIp") or ""
        has_auth, has_password, has_key = server_has_auth(server, secrets)
        blockers = []
        warnings = []
        if not host:
            blockers.append("Не указан IP/host сервера.")
        if not has_auth:
            blockers.append("Нет SSH-ключа или сохраненного пароля для подключения.")
        if item["file"] not in existing:
            warnings.append("Bootstrap-файл еще не сгенерирован.")
        if item["role"] == "exit":
            if server.get("wgEasyMode") == "existing":
                warnings.append("Режим existing wg-easy: контейнер и клиентские профили не меняются; будет добавлен отдельный служебный WireGuard-интерфейс.")
            else:
                warnings.append("После установки откройте wg-easy UI выходного сервера и завершите первичную настройку.")
        steps.append({
            "order": idx,
            "file": item["file"],
            "role": item["role"],
            "server": server.get("name") or item["role"],
            "host": host,
            "sshUser": server.get("sshUser") or "root",
            "hasPassword": has_password,
            "hasKey": has_key,
            "wgEasyMode": server.get("wgEasyMode") or "install",
            "generated": item["file"] in existing,
            "blockers": blockers,
            "warnings": warnings,
        })
    return {
        "ok": True,
        "steps": steps,
        "canRun": all(not step["blockers"] for step in steps),
        "summary": {
            "servers": len(steps),
            "ingress": 1 if steps else 0,
            "exits": max(0, len(steps) - 1),
            "blocked": sum(1 for step in steps if step["blockers"]),
        },
    }


def bootstrap_target_for_file(manifest, filename):
    filename = str(filename or "")
    if filename == "bootstrap-ingress.sh":
        server = dict(manifest.get("ingress", {}))
        server["role"] = "ingress"
        return server
    prefix = "bootstrap-exit-"
    if filename.startswith(prefix) and filename.endswith(".sh"):
        slug = filename[len(prefix):-3]
        for item in manifest.get("exits", []):
            if safe_slug(item.get("name"), "exit") == slug:
                server = dict(item)
                server["role"] = "exit"
                return server
    raise ValueError(f"cannot map bootstrap file to server: {filename}")


def run_remote_script(server, script_text, secrets):
    script_text = str(script_text or "").replace("\r\n", "\n").replace("\r", "\n")
    host = server.get("host") or server.get("publicIp")
    ssh_user = server.get("sshUser") or "root"
    passwords = secrets.get("ssh", {}).get("serverPasswords", {})
    password = passwords.get(server.get("name", "")) or passwords.get(host or "") or ""
    host_key = secrets.get("ssh", {}).get("hostKeys", {}).get(str(host or "").strip(), "")
    key_path = secrets.get("ssh", {}).get("ingressKeyPath", "")
    remote_path = f"/tmp/vpn-manager-{safe_slug(server.get('name'), 'server')}.sh"
    temp_path = ""
    if password:
        temp_path = write_temp_script(script_text)
        upload = subprocess.run(
            build_pscp_upload_command(host, ssh_user, password, host_key, temp_path, remote_path),
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=120,
        )
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        if upload.returncode != 0:
            return {
                "ok": False,
                "returncode": upload.returncode,
                "stdout": upload.stdout,
                "stderr": upload.stderr,
                "host": host,
                "server": server.get("name", ""),
                "role": server.get("role", ""),
            }
        cmd = build_remote_command(host, ssh_user, "", password, f"chmod 700 {remote_path} && bash {remote_path}", host_key=host_key)
        proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=900)
    else:
        remote = f"bash -lc {json.dumps(f'tr -d \"\\\\r\" > {remote_path} && chmod 700 {remote_path} && bash {remote_path}')}"
        cmd = build_remote_command(host, ssh_user, key_path, password, remote, host_key=host_key)
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            input=script_text,
            text=True,
            capture_output=True,
            timeout=900,
        )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "host": host,
        "server": server.get("name", ""),
        "role": server.get("role", ""),
    }


def start_remote_script_job(server, script_text, secrets, filename):
    script_text = str(script_text or "").replace("\r\n", "\n").replace("\r", "\n")
    host = server.get("host") or server.get("publicIp")
    ssh_user = server.get("sshUser") or "root"
    passwords = secrets.get("ssh", {}).get("serverPasswords", {})
    password = passwords.get(server.get("name", "")) or passwords.get(host or "") or ""
    host_key = secrets.get("ssh", {}).get("hostKeys", {}).get(str(host or "").strip(), "")
    key_path = secrets.get("ssh", {}).get("ingressKeyPath", "")
    remote_path = f"/tmp/vpn-manager-{safe_slug(server.get('name'), 'server')}.sh"
    role = server.get("role", "")
    ui_port = int(server.get("uiPort") or (51821 if role == "ingress" else 51831))
    wg_host = server.get("publicIp") or host
    wg_easy_url = f"http://{wg_host}:{ui_port}/" if wg_host else ""
    installs_wg_easy = "INSTALL_WG_EASY=true" in script_text
    existing_wg_easy = role == "exit" and server.get("wgEasyMode") == "existing"
    if password:
        cmd = build_remote_command(host, ssh_user, "", password, f"chmod 700 {remote_path} && bash {remote_path}", host_key=host_key)
    else:
        remote = f"bash -lc {json.dumps(f'tr -d \"\\\\r\" > {remote_path} && chmod 700 {remote_path} && bash {remote_path}')}"
        cmd = build_remote_command(host, ssh_user, key_path, password, remote, host_key=host_key)
    job_id = uuid.uuid4().hex
    job = {
        "id": job_id,
        "file": filename,
        "server": server.get("name", ""),
        "role": role,
        "host": host,
        "wgHost": wg_host,
        "wgEasyUrl": wg_easy_url if (installs_wg_easy or existing_wg_easy) else "",
        "nextAction": "connect-existing-wg-easy" if existing_wg_easy else ("configure-wg-easy" if installs_wg_easy and wg_easy_url else ""),
        "status": "running",
        "stage": "queued",
        "returncode": None,
        "startedAt": time.time(),
        "finishedAt": None,
        "lines": [],
        "error": "",
    }
    with JOBS_LOCK:
        JOBS[job_id] = job

    def append(line):
        with JOBS_LOCK:
            clean = line.rstrip()
            if clean.startswith("[stage]"):
                job["stage"] = clean.replace("[stage]", "", 1).strip() or job.get("stage", "running")
            job["lines"].append(clean)
            job["lines"] = job["lines"][-400:]

    def worker():
        try:
            if password:
                append("[stage] upload-script")
                temp_path = write_temp_script(script_text)
                try:
                    upload = subprocess.run(
                        build_pscp_upload_command(host, ssh_user, password, host_key, temp_path, remote_path),
                        cwd=str(ROOT),
                        text=True,
                        capture_output=True,
                        timeout=120,
                    )
                finally:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                if upload.returncode != 0:
                    append(upload.stdout)
                    append(upload.stderr)
                    with JOBS_LOCK:
                        job["returncode"] = upload.returncode
                        job["status"] = "failed"
                        job["error"] = upload.stderr or upload.stdout or "script upload failed"
                        job["finishedAt"] = time.time()
                    return
            proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                stdin=None if password else subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if not password:
                assert proc.stdin is not None
                proc.stdin.write(script_text)
                proc.stdin.close()
            assert proc.stdout is not None
            for line in proc.stdout:
                append(line)
            rc = proc.wait(timeout=5)
            with JOBS_LOCK:
                job["returncode"] = rc
                job["status"] = "completed" if rc == 0 else "failed"
                job["finishedAt"] = time.time()
        except Exception as exc:
            with JOBS_LOCK:
                job["status"] = "failed"
                job["error"] = str(exc)
                job["finishedAt"] = time.time()

    threading.Thread(target=worker, daemon=True).start()
    return job


def preflight_script(server, role):
    wg_port = int(server.get("wgPort") or (51820 if role == "ingress" else 51830))
    ui_port = int(server.get("uiPort") or (51821 if role == "ingress" else 51831))
    hysteria_port = int(server.get("hysteriaPort") or (8443 if role == "ingress" else 8444))
    return f"""set -eu
echo "uid=$(id -u)"
echo "user=$(id -un)"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  echo "os_id=${{ID:-unknown}}"
  echo "os_version=${{VERSION_ID:-unknown}}"
else
  echo "os_id=unknown"
  echo "os_version=unknown"
fi
command -v apt-get >/dev/null 2>&1 && echo "apt_get=present" || echo "apt_get=missing"
if command -v docker >/dev/null 2>&1; then
  echo "docker=present"
  docker --version | sed 's/^/docker_version=/'
  docker ps -a --format 'container={{{{.Names}}}} {{{{.Status}}}}' 2>/dev/null || true
  docker exec wg-easy sh -c 'wg show interfaces 2>/dev/null || true' 2>/dev/null | sed 's/^/wg_easy_interface=/' || true
else
  echo "docker=missing"
fi
command -v wg >/dev/null 2>&1 && wg show interfaces 2>/dev/null | sed 's/^/wg_interface=/' || true
echo "docker_service=$(systemctl is-active docker 2>/dev/null || true)"
echo "hysteria_service=$(systemctl is-active hysteria-server.service 2>/dev/null || true)"
ss -lntup 2>/dev/null | grep -E '(:{wg_port}|:{ui_port}|:{hysteria_port})[[:space:]]' | sed 's/^/port=/' || true
test -w /root && echo "root_writable=yes" || echo "root_writable=no"
"""


def preflight_bootstrap_file(filename):
    debug_log(f"preflight start file={filename}")
    manifest = load_manifest()
    secrets = load_secrets()
    server = bootstrap_target_for_file(manifest, filename)
    host = server.get("host") or server.get("publicIp")
    ssh_user = server.get("sshUser") or "root"
    passwords = secrets.get("ssh", {}).get("serverPasswords", {})
    password = passwords.get(server.get("name", "")) or passwords.get(host or "") or ""
    host_key = secrets.get("ssh", {}).get("hostKeys", {}).get(str(host or "").strip(), "")
    key_path = secrets.get("ssh", {}).get("ingressKeyPath", "")
    script_text = preflight_script(server, server.get('role', 'server')).replace("\r\n", "\n").replace("\r", "\n")
    if password:
        temp_path = write_temp_script(script_text)
        try:
            debug_log(f"preflight plink-m host={host} file={filename}")
            cmd = build_plink_file_command(host, ssh_user, password, host_key, temp_path)
            proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True, timeout=45)
            debug_log(f"preflight plink-m done host={host} rc={proc.returncode}")
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    else:
        remote = "tr -d '\\r' | bash -s"
        debug_log(f"preflight ssh-stdin host={host} file={filename}")
        cmd = build_remote_command(host, ssh_user, key_path, password, remote, host_key=host_key)
        proc = subprocess.run(cmd, cwd=str(ROOT), input=script_text, text=True, capture_output=True, timeout=45)
        debug_log(f"preflight ssh-stdin done host={host} rc={proc.returncode}")
    result = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "host": host,
        "server": server.get("name", ""),
        "role": server.get("role", ""),
        "checks": parse_preflight_output(proc.stdout, proc.stderr, proc.returncode),
    }
    combined_output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if password and proc.returncode != 0 and host_key_failure(combined_output):
        candidate = extract_ssh_host_key(combined_output) or probe_ssh_host_key(host, ssh_user, password)
        detail = "SSH host key изменился или еще не подтвержден."
        if candidate:
            detail += f" Найден новый fingerprint: {candidate}"
        result["hostKeyError"] = True
        result["hostKeyCandidate"] = candidate
        result["hostKeyCurrent"] = host_key
        result["checks"] = [{
            "name": "SSH host key",
            "status": "bad",
            "detail": detail,
        }]
    debug_log(f"preflight result file={filename} ok={result['ok']} rc={result['returncode']}")
    return result


def parse_preflight_output(stdout, stderr, returncode):
    text = f"{stdout or ''}\n{stderr or ''}"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    values = {}
    containers = []
    ports = []
    for line in lines:
        if line.startswith("container="):
            containers.append(line.split("=", 1)[1])
        elif line.startswith("port="):
            ports.append(line.split("=", 1)[1])
        elif "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    checks = []

    def add(name, status, detail=""):
        checks.append({"name": name, "status": status, "detail": detail})

    add("SSH подключение", "ok" if returncode == 0 else "bad", "сервер ответил" if returncode == 0 else "нет успешного ответа")
    add("Root-доступ", "ok" if values.get("uid") == "0" else "bad", "root" if values.get("uid") == "0" else "нужен root или sudo без пароля")
    add("Debian/Ubuntu apt-get", "ok" if values.get("apt_get") == "present" else "bad", f"{values.get('os_id', 'unknown')} {values.get('os_version', '')}".strip())
    add("Docker", "warn" if values.get("docker") == "missing" else "ok", "будет установлен" if values.get("docker") == "missing" else values.get("docker_version", "уже установлен"))
    has_wg_easy = any("wg-easy" in item for item in containers)
    add("wg-easy контейнер", "warn" if has_wg_easy else "ok", "контейнер уже есть, bootstrap не будет менять его без FORCE_REINSTALL" if has_wg_easy else "не найден")
    hysteria_active = values.get("hysteria_service") == "active"
    add("Hysteria service", "warn" if hysteria_active else "ok", "активный сервис будет пропущен без FORCE_REINSTALL" if hysteria_active else values.get("hysteria_service", "not-found"))
    add("Порты", "warn" if ports else "ok", "\n".join(ports[:6]) if ports else "целевые порты свободны или не обнаружены")
    add("Права записи", "ok" if values.get("root_writable") == "yes" else "bad", "можно писать в /root" if values.get("root_writable") == "yes" else "нет записи в /root")
    return checks


def preflight_all_bootstrap():
    plan = installation_plan()
    results = []
    for step in plan["steps"]:
        if step["blockers"]:
            results.append({"ok": False, **step, "checks": [{"name": "План", "status": "bad", "detail": "; ".join(step["blockers"])}], "stdout": "", "stderr": ""})
            continue
        try:
            result = preflight_bootstrap_file(step["file"])
            results.append({**step, **result})
        except Exception as exc:
            results.append({"ok": False, **step, "checks": [{"name": "Preflight", "status": "bad", "detail": str(exc)}], "stdout": "", "stderr": str(exc)})
    return {"ok": all(item.get("ok") for item in results), "plan": plan, "results": results}


def run_bootstrap_file(filename):
    manifest = load_manifest()
    secrets = load_secrets()
    path = OUTPUT_DIR / str(filename or "")
    if not path.exists() or not path.is_file():
        raise ValueError(f"bootstrap file not found: {filename}")
    if not path.name.startswith("bootstrap-"):
        raise ValueError("only bootstrap files can be run from this action")
    script_text = path.read_text(encoding="utf-8-sig")
    server = bootstrap_target_for_file(manifest, path.name)
    return run_remote_script(server, script_text, secrets)


def start_bootstrap_file(filename):
    manifest = load_manifest()
    secrets = load_secrets()
    path = OUTPUT_DIR / str(filename or "")
    if not path.exists() or not path.is_file():
        raise ValueError(f"bootstrap file not found: {filename}")
    if not path.name.startswith("bootstrap-"):
        raise ValueError("only bootstrap files can be run from this action")
    script_text = path.read_text(encoding="utf-8-sig")
    server = bootstrap_target_for_file(manifest, path.name)
    return start_remote_script_job(server, script_text, secrets, path.name)


def get_job(job_id):
    with JOBS_LOCK:
        job = JOBS.get(str(job_id))
        if not job:
            return None
        return json.loads(json.dumps(job, ensure_ascii=False))


def list_jobs():
    with JOBS_LOCK:
        jobs = list(JOBS.values())
        jobs.sort(key=lambda item: item.get("startedAt") or 0, reverse=True)
        return json.loads(json.dumps(jobs[:20], ensure_ascii=False))


def html_page():
    return r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Manager</title>
<style>
:root{color-scheme:dark;--bg:#070a0d;--panel:#0f151b;--ink:#edf4f2;--muted:#84919a;--line:#222c34;--accent:#2fbf8f;--accent2:#5b6f7c;--bad:#df5b58;--warn:#d79a32;--ok:#34d399}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:var(--bg);color:var(--ink);font-size:14px}button,input,select,textarea{font:inherit}button{border:0;background:var(--accent);color:white;border-radius:6px;padding:9px 12px;cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}button.secondary{background:#1a2430;color:#dce7ee;border:1px solid #2e3b48}button.danger{background:#9d3434}button.link{background:transparent;color:#dbe8ef;text-align:left}.app.locked{display:none}.shell{display:grid;grid-template-columns:260px 1fr;min-height:100vh}.side{background:#0b1118;color:#eef4f7;padding:18px;border-right:1px solid var(--line)}.brand{font-weight:750;font-size:20px;margin-bottom:4px}.brand-sub{color:#7d8b98;font-size:12px;margin-bottom:18px}.nav button{width:100%;margin:3px 0;text-align:left;background:transparent;color:#c8d4dc;border-radius:6px}.nav button.active{background:#182431;color:white}.main{padding:20px 24px 36px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:16px}.title h1{margin:0 0 4px;font-size:24px}.muted{color:var(--muted)}h2{font-size:18px;margin:22px 0 10px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.cards3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.panel,.choice,.node,.exit-card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.choice{min-height:150px;display:flex;flex-direction:column;justify-content:space-between}.choice h2{margin-top:0}.metric{font-size:24px;font-weight:750;margin-top:6px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.stack{display:grid;gap:12px}.tabs{display:none}.tabs.active{display:block}.form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.field label{display:block;font-size:12px;font-weight:650;color:#93a2ae;margin-bottom:5px}.field input,.field select,.field textarea,.table input{width:100%;border:1px solid #2a3744;border-radius:6px;padding:8px;background:#0b1118;color:#eef4f7}.field textarea{min-height:70px;resize:vertical}.checkrow{display:flex;gap:8px;align-items:center;background:#0b1118;border:1px solid var(--line);border-radius:6px;padding:9px}.checkrow input{width:auto}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.badge{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;font-size:12px;background:#1c2732;color:#c9d6df}.badge.ok{background:#103328;color:#86efac}.badge.bad{background:#3a1717;color:#fca5a5}.badge.warn{background:#3a2a11;color:#facc6b}.exit-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.exit-head{display:flex;justify-content:space-between;gap:12px}.exit-name{font-size:17px;font-weight:750}.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 10px;margin-top:12px}.kv span:nth-child(odd){color:var(--muted)}pre{margin:0;background:#05080c;color:#d7e3ea;border-radius:8px;padding:12px;overflow:auto;max-height:520px;white-space:pre-wrap}.file-row{display:grid;grid-template-columns:220px 100px 1fr;gap:10px;align-items:center;border-bottom:1px solid var(--line);padding:8px 0}.flow{display:grid;grid-template-columns:1fr 40px 1fr 40px 1fr;gap:10px;align-items:center}.node{min-height:95px}.arrow{text-align:center;color:#7a8691;font-size:22px}.toast{position:fixed;right:18px;bottom:18px;background:#182431;color:#fff;padding:12px 14px;border-radius:8px;box-shadow:0 10px 30px #0008;display:none}.empty{padding:22px;border:1px dashed var(--line);border-radius:8px;background:#101821;color:var(--muted)}.wizard-steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:12px}.step-pill{border:1px solid var(--line);background:#101821;border-radius:6px;padding:8px;color:#9aa8b3}.step-pill.active{border-color:var(--accent);color:#86efac;font-weight:700}.table{width:100%;border-collapse:collapse;background:#101821;border:1px solid var(--line);border-radius:8px;overflow:hidden}.table th,.table td{text-align:left;padding:9px;border-bottom:1px solid var(--line)}.table th{background:#151f2a;color:#aebbc5}.progress{height:8px;background:#0b1118;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin-top:10px}.progress i{display:block;height:100%;background:#1fb383;width:0;transition:width .25s}.install-card.running{border-color:#2f8cff}.install-card.completed{border-color:#1fb383}.install-card.failed{border-color:#c04444}.modal-backdrop{position:fixed;inset:0;background:#0009;display:grid;place-items:center;z-index:50;padding:20px}.modal-backdrop.hidden{display:none}.modal{width:min(620px,100%);background:#111923;border:1px solid #324253;border-radius:10px;padding:18px;box-shadow:0 24px 80px #000c}.modal h2{margin-top:0}.notice{border:1px solid #29465d;background:#0c1824;border-radius:8px;padding:12px;margin-top:10px}@media(max-width:980px){.shell{grid-template-columns:1fr}.side{position:sticky;top:0;z-index:5}.nav{display:flex;gap:6px;overflow:auto}.nav button{width:auto;white-space:nowrap}.grid,.cards3,.row,.form,.exit-list,.flow,.wizard-steps{grid-template-columns:1fr}.arrow{display:none}.main{padding:16px}}
.landing{position:fixed;inset:0;z-index:20;overflow:hidden;background:#071121;color:white;display:grid;place-items:center;padding:32px}.landing.hidden{display:none}.landing:before{content:"";position:absolute;inset:0;background:linear-gradient(#102038 1px,transparent 1px),linear-gradient(90deg,#102038 1px,transparent 1px);background-size:96px 96px;opacity:.28}.landing:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,#071121f8 0%,#071121e8 43%,#071121a8 100%)}.landing-svg{position:absolute;inset:-4%;width:108%;height:108%;z-index:0;opacity:.78;animation:landingDrift 18s ease-in-out infinite alternate}.landing-svg .glow{animation:svgGlow 7s ease-in-out infinite alternate}.landing-svg .link{stroke:#1262a7;stroke-width:1.2;opacity:.52}.landing-svg .node{fill:#168cff;opacity:.78}.terminal-stream{position:absolute;z-index:1;left:44px;top:34px;bottom:34px;width:min(470px,30vw);overflow:hidden;font:14px/1.55 Consolas,ui-monospace,monospace;color:#2f8bca88;letter-spacing:.2px}.terminal-stream span{display:block;opacity:.34;transform:translateX(-4px);animation:terminalLine 8s ease-in-out infinite}.terminal-stream span:nth-child(2){animation-delay:.2s}.terminal-stream span:nth-child(3){animation-delay:.4s}.terminal-stream span:nth-child(4){animation-delay:.6s}.terminal-stream span:nth-child(5){animation-delay:.8s}.terminal-stream span:nth-child(6){animation-delay:1s}.terminal-stream span:nth-child(7){animation-delay:1.2s}.terminal-stream span:nth-child(8){animation-delay:1.4s}.terminal-stream span:nth-child(9){animation-delay:1.6s}.terminal-stream span:nth-child(10){animation-delay:1.8s}.terminal-stream span:nth-child(11){animation-delay:2s}.terminal-stream span:nth-child(12){animation-delay:2.2s}.terminal-stream span:nth-child(13){animation-delay:2.4s}.terminal-stream span:nth-child(14){animation-delay:2.6s}.terminal-stream span:nth-child(15){animation-delay:2.8s}.terminal-stream span:nth-child(16){animation-delay:3s}.terminal-stream span:nth-child(17){animation-delay:3.2s}.terminal-stream span:nth-child(18){animation-delay:3.4s}.terminal-stream span:nth-child(19){animation-delay:3.6s}.terminal-stream span:nth-child(20){animation-delay:3.8s}.auth-card{position:relative;z-index:2;width:min(520px,92vw);padding:34px 36px;border:1px solid #24405f;border-radius:14px;background:#081425cc;box-shadow:0 28px 80px #0008}.auth-top,.auth-dot{display:none}.auth-body{padding:0}.ig-mark{width:86px;height:70px;display:grid;place-items:center;margin:0 auto 18px;border-radius:14px;border:1px solid #156dce;background:linear-gradient(135deg,#0ea5ff,#115ee9);font-weight:900;font-size:32px;letter-spacing:0;color:#eaf6ff;box-shadow:0 0 34px #168cff55}.auth-title{font-size:28px;font-weight:800;text-align:center;margin:0 0 8px}.auth-sub{color:#a6b4c8;text-align:center;margin:0 0 28px;line-height:1.45}.entry-actions{display:grid;gap:12px}.entry-actions button{position:relative;min-height:58px;padding:15px 48px 15px 18px;border:1px solid #304b6d;background:#101d32;color:#f4f8ff;border-radius:8px;text-align:left;font-size:16px;font-weight:750;letter-spacing:0;box-shadow:none}.entry-actions button:after{content:"→";position:absolute;right:18px;top:50%;transform:translateY(-52%);color:#9bcaff;font-size:22px}.entry-actions button:first-child{background:linear-gradient(180deg,#178cff,#1166f4);border-color:#2998ff;text-align:center;padding-left:48px;box-shadow:0 10px 30px #087cff3f}.entry-actions button:first-child:after{color:white}.entry-actions button:hover{background:#172844;border-color:#2998ff;color:#ffffff}.entry-actions button:first-child:hover{background:linear-gradient(180deg,#2b9cff,#1672ff)}.entry-actions button:focus-visible{outline:2px solid #2c9cf0;outline-offset:2px}.auth-foot{display:flex;justify-content:space-between;align-items:center;margin-top:24px;padding-top:18px;border-top:1px solid #223a57;color:#8395ad;font-size:13px}.auth-foot:before{content:"IG";color:#9aaabe}.auth-foot:after{content:"local · v0.1";color:#74849a}@keyframes landingDrift{from{transform:translate3d(-1.2%,-.8%,0) scale(1)}to{transform:translate3d(1.2%,.8%,0) scale(1.025)}}@keyframes svgGlow{from{opacity:.34}to{opacity:.72}}@keyframes terminalLine{0%,100%{opacity:.3;transform:translateX(-4px)}45%,65%{opacity:.82;transform:translateX(0)}}@media(max-width:1100px){.terminal-stream{display:none}}@media(max-width:760px){.landing{padding:18px}.auth-card{width:100%;padding:26px 20px}.ig-mark{width:74px;height:62px;font-size:28px}.auth-title{font-size:24px}.entry-actions button{min-height:56px}}@media(prefers-reduced-motion:reduce){.landing-svg,.landing-svg .glow,.terminal-stream span{animation:none}}
.monitor-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.monitor-flow{display:grid;grid-template-columns:1fr 40px 1fr 40px 1fr;gap:10px;align-items:stretch;margin-top:12px}.monitor-card{background:#111820;border:1px solid #2a3744;border-radius:8px;padding:14px}.monitor-card strong{display:block;font-size:17px}.monitor-card.live{border-color:#2e6b4f}.monitor-card.reserve{border-color:#75622b}.monitor-card.offline{opacity:.72}.monitor-exits{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:12px}.bar{height:8px;background:#273039;border-radius:999px;overflow:hidden;margin:12px 0}.bar i{display:block;height:100%;background:#52d98d;border-radius:999px}.monitor-card.reserve .bar i{background:#d3a83b;width:100%!important}.monitor-card.offline .bar i{background:#6b747d}@media(max-width:980px){.monitor-grid,.monitor-flow,.monitor-exits{grid-template-columns:1fr}}
.wizard-steps{background:#081425;border:1px solid #203a58;border-radius:12px;padding:8px;box-shadow:0 18px 60px #0005}.step-pill{position:relative;border:1px solid #253a54;background:#0c1728;border-radius:8px;padding:10px 12px;color:#8fa2b8}.step-pill.active{border-color:#2387ee;color:#eaf6ff;background:#10233d;box-shadow:inset 0 0 0 1px #2387ee44}.step-pill.active:after{content:"";position:absolute;left:12px;right:12px;bottom:-9px;height:2px;background:#2387ee;box-shadow:0 0 14px #2387ee}.wizard-shell{position:relative;overflow:hidden;border:1px solid #203a58;border-radius:14px;background:#071121;box-shadow:0 24px 70px #0007}.wizard-shell:before{content:"";position:absolute;inset:0;background:linear-gradient(#102038 1px,transparent 1px),linear-gradient(90deg,#102038 1px,transparent 1px);background-size:72px 72px;opacity:.18;pointer-events:none}.wizard-shell:after{content:"";position:absolute;inset:0;background:radial-gradient(circle at 88% 8%,#0d8cff55,transparent 34%),linear-gradient(90deg,#071121f8,#071121d8);pointer-events:none}.wizard-inner{position:relative;z-index:1;padding:18px}.wizard-hero{display:grid;grid-template-columns:1fr auto;gap:16px;align-items:start;margin-bottom:16px}.wizard-kicker{font:12px Consolas,ui-monospace,monospace;color:#59b7ff;text-transform:uppercase;letter-spacing:.08em}.wizard-hero h2{margin:4px 0 6px;font-size:24px}.wizard-status{display:grid;grid-template-columns:repeat(3,minmax(120px,1fr));gap:8px;min-width:430px}.wizard-stat{background:#09182a;border:1px solid #213a55;border-radius:8px;padding:10px}.wizard-stat b{display:block;font-size:18px;margin-top:3px}.wizard-work{display:grid;gap:12px}.wizard-panel{background:#0b1625cc;border:1px solid #243d59;border-radius:10px;padding:14px}.wizard-panel h3{margin:0 0 8px;font-size:17px}.wizard-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;margin-top:14px}.setup-head{display:grid;grid-template-columns:minmax(260px,1fr) auto;gap:14px;align-items:end;margin-bottom:14px}.setup-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.setup-card{background:#101d32cc;border:1px solid #304b6d;border-radius:10px;padding:14px;box-shadow:0 12px 30px #0003}.setup-card.ingress{border-color:#2387ee;box-shadow:inset 0 0 0 1px #2387ee44,0 12px 30px #0003}.setup-card.exit{border-color:#3a4a63}.setup-card-top{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:12px}.setup-icon{width:42px;height:42px;border-radius:10px;display:grid;place-items:center;background:#e40058;color:white;font-weight:800}.setup-card.ingress .setup-icon{background:linear-gradient(135deg,#0ea5ff,#115ee9)}.setup-title{font-weight:800}.setup-sub{font-size:12px;color:#9aa5ba}.role-tabs{display:flex;gap:6px}.role-tabs button{padding:7px 10px;background:#0c1728;color:#aeb8ca;border:1px solid #2c405a}.role-tabs button.active{background:#173c5f;color:#d9ecff;border-color:#2387ee}.setup-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.setup-fields .field:nth-child(2),.setup-fields .field:nth-child(5){grid-column:1/-1}.setup-note{margin-top:12px;color:#9ab0c8;font-size:13px}.protocol-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.protocol-card{display:flex;gap:12px;align-items:flex-start;background:#101d32;border:1px solid #304b6d;border-radius:10px;padding:14px;cursor:pointer}.protocol-card input{margin-top:4px}.protocol-card strong{display:block}.install-sequence{display:grid;gap:10px}.install-step{display:grid;grid-template-columns:42px 1fr auto;gap:12px;align-items:center;background:#101d32;border:1px solid #304b6d;border-radius:10px;padding:12px}.install-step i{width:34px;height:34px;border-radius:9px;background:#0d2947;color:#8fd0ff;display:grid;place-items:center;font-style:normal;font-weight:800}.install-step.active{border-color:#2387ee}.install-step.done{border-color:#1fb383}.control-note{border:1px solid #29465d;background:#0c1824;border-radius:8px;padding:12px;color:#b7c7d7}@media(max-width:980px){.wizard-hero,.wizard-status,.setup-head,.setup-grid,.setup-fields,.protocol-grid{grid-template-columns:1fr}.wizard-status{min-width:0}.wizard-actions{justify-content:flex-start}.install-step{grid-template-columns:36px 1fr}}
.protocol-card{position:relative;align-items:center}.protocol-card input{width:16px;height:16px;accent-color:#2798ff}.protocol-card small{display:block;color:#9fb0c4;margin-top:4px}.protocol-card em{display:none}.proto-icon{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;font-weight:900;color:#fff;background:#0d2947;border:1px solid #275176;flex:0 0 auto}.protocol-card.is-on{border-color:#2387ee;background:#10223b}.protocol-card.is-on .proto-icon{background:linear-gradient(135deg,#158cff,#0d5fe8);box-shadow:0 0 18px #168cff44}.protocol-card.is-off{opacity:.72}.install-step.prepare{border-color:#245f9c}.install-step.prepare i{background:#0d3b6b;color:#9fd4ff}.install-step.prepare.done{border-color:#2f8cff;box-shadow:inset 0 0 0 1px #2f8cff44}.install-step.check{border-color:#75521c}.install-step.check i{background:#5a390d;color:#ffd28a}.install-step.check.done{border-color:#d9922d;box-shadow:inset 0 0 0 1px #d9922d44}.install-step.run{border-color:#22664d}.install-step.run i{background:#0c4635;color:#8ff0c3}.install-step.run.problem{border-color:#c04444}.install-step.run.problem i{background:#642020;color:#ffb4b4}.render-shell{position:relative;overflow:hidden;border:1px solid #203a58;border-radius:14px;background:#071121;padding:16px;box-shadow:0 20px 60px #0006}.render-shell:before{content:"";position:absolute;inset:0;background:linear-gradient(#102038 1px,transparent 1px),linear-gradient(90deg,#102038 1px,transparent 1px);background-size:72px 72px;opacity:.12;pointer-events:none}.render-shell>*{position:relative}.install-plan-card,.build-file-card{background:#0b1625cc;border:1px solid #243d59;border-radius:10px;padding:14px}.install-plan-card.ok{border-color:#1fb383}.install-plan-card.bad{border-color:#c04444}.install-plan-card.warn{border-color:#d9922d}.check-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.check-item{background:#081425;border:1px solid #20334d;border-radius:8px;padding:10px}.check-item b{display:block;margin-bottom:4px}.pretty-log{display:grid;gap:6px;background:#05080c;border:1px solid #1b2938;border-radius:8px;padding:10px;margin-top:10px;max-height:320px;overflow:auto;font:13px/1.35 Consolas,ui-monospace,monospace}.log-line{display:grid;grid-template-columns:90px 1fr;gap:10px;border-bottom:1px solid #132033;padding:5px 0}.log-line:last-child{border-bottom:0}.log-kind{color:#7dbdff}.log-line.err .log-kind{color:#ff8c8c}.log-line.stage .log-kind{color:#8ff0c3}.modal-actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:14px}@media(max-width:980px){.check-grid{grid-template-columns:1fr}.log-line{grid-template-columns:1fr}}
.btn-prepare{background:#1469c8;border:1px solid #2f8cff}.btn-check{background:#9a6118;border:1px solid #d9922d}.btn-run{background:#16805e;border:1px solid #24b783}.btn-run.danger{background:#9d3434;border-color:#c04444}
</style>
</head>
<body>
<section id="landing" class="landing">
  <svg class="landing-svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
    <defs>
      <radialGradient id="loginGlow" cx="78%" cy="82%" r="45%">
        <stop offset="0%" stop-color="#0d8cff" stop-opacity=".8"/>
        <stop offset="58%" stop-color="#0b4f99" stop-opacity=".22"/>
        <stop offset="100%" stop-color="#071121" stop-opacity="0"/>
      </radialGradient>
      <pattern id="dotMap" width="16" height="16" patternUnits="userSpaceOnUse">
        <circle cx="2" cy="2" r="1.3" fill="#0d8cff" opacity=".26"/>
      </pattern>
    </defs>
    <rect width="1600" height="900" fill="url(#loginGlow)" class="glow"/>
    <rect x="1020" y="30" width="470" height="420" fill="url(#dotMap)" opacity=".5"/>
    <path class="link" d="M1040 320 L1210 160 L1430 220 M1040 320 L1248 470 L1480 560 M1248 470 L1210 160 M1248 470 L1380 710"/>
    <path class="link" d="M70 570 L310 520 L520 430 L700 500 M520 430 L620 290 L820 290"/>
    <circle class="node" cx="1040" cy="320" r="5"/><circle class="node" cx="1210" cy="160" r="6"/><circle class="node" cx="1430" cy="220" r="4"/>
    <circle class="node" cx="1248" cy="470" r="5"/><circle class="node" cx="1480" cy="560" r="4"/><circle class="node" cx="1380" cy="710" r="5"/>
    <circle class="node" cx="310" cy="520" r="5"/><circle class="node" cx="520" cy="430" r="4"/><circle class="node" cx="700" cy="500" r="3"/>
  </svg>
  <div class="terminal-stream" id="terminalStream" aria-hidden="true"></div>
  <div class="auth-card">
    <div class="auth-top"><span class="auth-dot"></span><span class="auth-dot"></span><span class="auth-dot"></span></div>
    <div class="auth-body">
      <div class="ig-mark">IG</div>
      <h1 class="auth-title">VPN Manager</h1>
      <p class="auth-sub">Локальный центр управления сетями, VPS и доступами.</p>
      <div class="entry-actions">
        <button onclick="startNewNetwork()">Создать сеть</button>
        <button onclick="enterNetwork()">Войти в сеть</button>
      </div>
    </div>
    <div class="auth-foot">local control panel</div>
  </div>
</section>
<div id="appShell" class="app locked">
<div class="shell">
  <aside class="side">
    <div class="brand">VPN Manager</div>
    <div class="brand-sub">локальный центр управления</div>
    <div class="nav">
      <button data-tab="home" class="active">Начало</button>
      <button data-tab="admin">Админка сети</button>
      <button data-tab="vps">VPS и балансировка</button>
      <button data-tab="users">Пользователи</button>
      <button data-tab="connect">Подключение</button>
      <button data-tab="wizard">Новая сеть</button>
      <button data-tab="secrets">Секреты</button>
      <button data-tab="render">Сборка</button>
      <button onclick="logout()">Выйти</button>
    </div>
  </aside>
  <main class="main">
    <div class="top">
      <div class="title"><h1 id="pageTitle">Начало</h1><div class="muted" id="subtitle">Выберите рабочий сценарий</div></div>
      <div class="actions"><button class="secondary" onclick="loadState()">Обновить</button><button class="secondary" onclick="saveProfile()">Сохранить профиль</button><button onclick="saveAll()">Сохранить</button></div>
    </div>

    <section id="home" class="tabs active">
      <div class="cards3">
        <article class="choice"><div><h2>Войти в админку</h2><p class="muted">Управление существующей сетью: VPS, доли, резервы, пользователи, лимиты и сборка скриптов.</p></div><button onclick="enterAdmin()">Открыть админку</button></article>
        <article class="choice"><div><h2>Подключить серверы</h2><p class="muted">Добавление новых VPS, ключей, публичных IP, интерфейсов и весов балансировки.</p></div><button onclick="showTab('vps')">Настроить VPS</button></article>
        <article class="choice"><div><h2>Создать новую сеть</h2><p class="muted">Пошаговый мастер: ingress, протоколы, exit-узлы, резервы, пользователи и автоматическая сборка.</p></div><button onclick="startNewNetwork()">Начать мастер</button></article>
      </div>
      <h2>Живой мониторинг</h2>
      <div class="panel">
        <div class="actions" style="justify-content:space-between"><div><b>Ingress monitor</b><div class="muted">Тот же read-only снимок, что отдает `cascade-monitor` на VPS.</div></div><div class="actions"><button class="secondary" onclick="refreshMonitor()">Обновить мониторинг</button><button onclick="syncProfileFromMonitor()">Синхронизировать профиль</button></div></div>
        <div id="monitorOverviewHome" style="margin-top:12px"></div>
      </div>
      <h2>Текущее состояние</h2>
      <div class="grid">
        <div class="panel"><div class="muted">Ingress</div><div class="metric" id="metricIngress">-</div></div>
        <div class="panel"><div class="muted">Auto exits</div><div class="metric" id="metricAuto">0</div></div>
        <div class="panel"><div class="muted">Reserve exits</div><div class="metric" id="metricReserve">0</div></div>
        <div class="panel"><div class="muted">Пользователи</div><div class="metric" id="metricUsers">0</div></div>
      </div>
      <h2>Топология</h2>
      <div class="flow">
        <div class="node"><b>Клиенты</b><div class="muted">WireGuard / Hysteria</div><div id="flowDomain"></div></div>
        <div class="arrow">→</div>
        <div class="node"><b>Ingress</b><div class="muted" id="flowIngress"></div><div id="flowSource"></div></div>
        <div class="arrow">→</div>
        <div class="node"><b>Exit pool</b><div class="muted" id="flowExits"></div><div id="flowWeights"></div></div>
      </div>
      <h2>VPS</h2>
      <div class="exit-list" id="overviewExits"></div>
    </section>

    <section id="admin" class="tabs">
      <div class="grid">
        <div class="panel"><div class="muted">Админка</div><div class="metric" id="metricAdmin">-</div></div>
        <div class="panel"><div class="muted">Протоколы</div><div class="metric" id="metricProtocols">0</div></div>
        <div class="panel"><div class="muted">Секреты</div><div class="metric" id="metricSecrets">0%</div></div>
        <div class="panel"><div class="muted">Generated</div><div class="metric" id="metricGenerated">0</div></div>
      </div>
      <h2>Ingress</h2>
      <div class="panel"><div class="form" id="ingressForm"></div></div>
      <h2>Протоколы</h2>
      <div class="panel"><div class="form" id="protocolForm"></div></div>
      <h2>Routing</h2>
      <div class="panel"><div class="form" id="routingForm"></div></div>
    </section>

    <section id="vps" class="tabs">
      <div class="actions" style="margin-bottom:12px"><button onclick="addExit()">Добавить VPS</button><button class="secondary" onclick="normalizeWeights()">Выровнять доли auto</button><button class="secondary" onclick="saveProfile()">Сохранить профиль</button></div>
      <div class="panel" style="margin-bottom:12px">
        <div class="actions" style="justify-content:space-between"><div><h2 style="margin:0">Мониторинг ingress</h2><div class="muted">Read-only снимок как на серверном `/monitor/`: активный выход, резервы, веса, handshake и проверки.</div></div><div class="actions"><button class="secondary" onclick="refreshMonitor()">Обновить мониторинг</button><button onclick="syncProfileFromMonitor()">Синхронизировать профиль</button></div></div>
        <div id="monitorOverviewVps" style="margin-top:12px"></div>
      </div>
      <div class="stack" id="exitEditor"></div>
    </section>

    <section id="users" class="tabs">
      <div class="actions" style="margin-bottom:12px"><button onclick="addUser()">Добавить пользователя</button></div>
      <div id="userEditor"></div>
    </section>


    <section id="connect" class="tabs">
      <div class="panel">
        <h2>Подключить существующий входной VPS</h2>
        <p class="muted">Укажите IP сервера и локальный путь к SSH-ключу. Приложение подключится по SSH и прочитает hostname, публичный интерфейс/IP, домен Caddy и активные сервисы портала/мониторинга.</p>
        <div class="form">
          <div class="field"><label>IP / host входного VPS</label><input id="discoverHost" placeholder="203.0.113.10"></div>
          <div class="field"><label>SSH user</label><input id="discoverUser" value="root"></div>
          <div class="field"><label>Способ входа</label><select id="discoverAuth" onchange="renderAuthMode()"><option value="key">SSH-ключ</option><option value="password">Пароль</option></select></div>
          <div class="field"><label>Путь к SSH-ключу</label><input id="discoverKey" value=".vpn-secrets\ssh-key" placeholder=".vpn-secrets\ssh-key"></div>
          <div class="field" id="discoverPasswordField" style="display:none"><label>SSH password</label><input id="discoverPassword" type="password" autocomplete="current-password" placeholder="сохраняется в .vpn-secrets"></div>
        </div>
        <div class="actions" style="margin-top:12px"><button onclick="discoverIngress()">Обнаружить сервер</button><button class="secondary" onclick="applyKeyHint('id_ed25519')">id_ed25519</button><button class="secondary" onclick="applyKeyHint('id_rsa')">id_rsa</button></div>
        <p class="muted">По умолчанию положите приватный SSH-ключ в папку приложения <code>.vpn-secrets</code> и укажите путь <code>.vpn-secrets\ssh-key</code>. Например: <code>C:\Users\IgorG\Documents\Сеть VPNов\.vpn-secrets\ssh-key</code>. Для входа по паролю на Windows нужен <code>plink.exe</code> из PuTTY в PATH; пароль сохраняется локально в <code>.vpn-secrets</code>, не в профиль сети.</p>
        <pre id="discoverOutput">Ожидаю подключения.</pre>
      </div>
      <div class="panel" style="margin-top:12px">
        <div class="actions" style="justify-content:space-between"><div><h2 style="margin:0">Мониторинг подключаемой сети</h2><div class="muted">Безопасная read-only проверка через уже установленный `cascade-monitor` на ingress.</div></div><div class="actions"><button class="secondary" onclick="refreshMonitor()">Обновить мониторинг</button><button onclick="syncProfileFromMonitor()">Синхронизировать профиль</button></div></div>
        <div id="monitorOverviewConnect" style="margin-top:12px"></div>
      </div>
    </section>
    <section id="wizard" class="tabs">
      <div class="wizard-steps">
        <div class="step-pill active" data-wstep="0">1. Ingress</div>
        <div class="step-pill" data-wstep="1">2. Протоколы</div>
        <div class="step-pill" data-wstep="2">3. Проверка</div>
        <div class="step-pill" data-wstep="3">4. Установка</div>
      </div>
      <div id="wizardBody"></div>
    </section>

    <section id="secrets" class="tabs">
      <div class="panel">
        <div class="form" id="secretForm"></div>
        <p class="muted">Поля секретов не подставляются обратно в браузер. Если оставить поле пустым, существующее значение в `.vpn-secrets` сохранится.</p>
      </div>
      <h2>Статус секретов</h2>
      <div class="exit-list" id="secretStatus"></div>
    </section>

    <section id="render" class="tabs">
      <div class="render-shell">
        <div class="actions" style="justify-content:space-between">
          <div><b>Установка сети</b><div class="muted">Порядок: сгенерировать bootstrap, проверить все VPS, затем запускать установку с явным подтверждением.</div></div>
          <div class="actions"><button class="btn-prepare" onclick="renderBootstrap()">Сгенерировать bootstrap</button><button class="secondary" onclick="refreshInstallPlan()">Обновить план</button><button class="btn-check" onclick="preflightAllBootstrap()">Проверить все</button><button class="btn-run danger" onclick="runAllBootstrap()">Запустить очередь</button></div>
        </div>
        <h2>План установки</h2>
        <div id="installPlan" class="stack"></div>
        <h2>Прогресс установки</h2>
        <div id="jobProgress" class="stack"></div>
        <h2>Скрипты</h2>
        <div id="generatedFiles"></div>
      </div>
    </section>
  </main>
</div>
</div>
<div class="toast" id="toast"></div>
<div class="modal-backdrop hidden" id="installModal"><div class="modal"><div id="installModalBody"></div><div class="actions" style="margin-top:14px;justify-content:flex-end"><button class="secondary" onclick="closeInstallModal()">Закрыть</button></div></div></div>
<script>
let state = null;
let wizardStep = 0;
let monitorData = null;
let setupServers = [];
let activeJobs = {};
let installPlan = null;
let preflightResults = [];
const titles = {home:'Начало', admin:'Админка сети', vps:'VPS и балансировка', users:'Пользователи', connect:'Подключение существующей сети', wizard:'Создание новой сети', secrets:'Секреты', render:'Сборка'};
document.querySelectorAll('.nav button').forEach(btn=>btn.addEventListener('click',()=>showTab(btn.dataset.tab)));
function showTab(id){document.querySelectorAll('.tabs').forEach(x=>x.classList.remove('active'));document.getElementById(id).classList.add('active');document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.tab===id));document.getElementById('pageTitle').textContent=titles[id];if(id==='wizard')renderWizard();}
function toast(text){const t=document.getElementById('toast');t.textContent=text;t.style.display='block';setTimeout(()=>t.style.display='none',2800)}
async function api(path, body){const opt=body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}:{};const r=await fetch(path,opt);let data={};try{data=await r.json()}catch(e){data={error:await r.text().catch(()=>'')}}if(!r.ok){const checks=(data.checks||[]).map(c=>`${c.name}: ${c.detail||c.status}`).join('\n');throw new Error(data.error||data.stderr||checks||'HTTP '+r.status)}return data}
async function loadState(){state=await api('/api/state');await loadJobs(true);renderAll();toast('Данные обновлены');maybeAutoRefreshMonitor()}
async function loadJobs(startPolling=true){try{const r=await api('/api/jobs');activeJobs={};(r.jobs||[]).forEach(j=>{activeJobs[j.id]=j;if(startPolling&&j.status==='running')pollJob(j.id)});}catch(e){}}
function setLandingVisible(){const landing=document.getElementById('landing');const app=document.getElementById('appShell');if(!state||!state.manifest.admin.configured){landing.classList.remove('hidden');app.classList.add('locked')}else{landing.classList.add('hidden');app.classList.remove('locked')}}
function val(path){return path.split('.').reduce((o,k)=>o&&o[k],state.manifest)??''}
function setVal(path,value){const keys=path.split('.');let o=state.manifest;keys.slice(0,-1).forEach(k=>o=o[k]);o[keys.at(-1)]=value}
function field(label,path,type='text'){const id='f_'+path.replaceAll('.','_');return `<div class="field"><label>${label}</label><input id="${id}" type="${type}" value="${escapeHtml(String(val(path)))}" oninput="setVal('${path}', this.value)"></div>`}
function numberField(label,path){const id='f_'+path.replaceAll('.','_');return `<div class="field"><label>${label}</label><input id="${id}" type="number" value="${escapeHtml(String(val(path)))}" oninput="setVal('${path}', Number(this.value)||0)"></div>`}
function textarea(label,path){const id='f_'+path.replaceAll('.','_');const value=(val(path)||[]).join('\n');return `<div class="field"><label>${label}</label><textarea id="${id}" oninput="setVal('${path}', this.value.split('\\n').map(x=>x.trim()).filter(Boolean))">${escapeHtml(value)}</textarea></div>`}
function escapeHtml(s){return s.replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function renderAll(){ensureShape();setLandingVisible();syncConnectionForm();renderOverview();renderIngress();renderExits();renderUsers();renderSecrets();renderGenerated();renderJobs();renderInstallPlan();renderWizard();renderMonitor();renderAuthMode()}
function ensureShape(){state.manifest.admin ||= {configured:false,lastLogin:''};state.manifest.protocols ||= {wireguard:true,hysteria:true,mtproto:false,clientPortal:true,monitoring:true};state.manifest.users ||= [];state.manifest.exits ||= []}
function renderOverview(){const m=state.manifest, exits=m.exits||[], auto=exits.filter(e=>e.mode!=='reserve'), reserve=exits.filter(e=>e.mode==='reserve');document.getElementById('metricIngress').textContent=m.ingress.host||'-';document.getElementById('metricAuto').textContent=auto.length;document.getElementById('metricReserve').textContent=reserve.length;document.getElementById('metricUsers').textContent=(m.users||[]).length;document.getElementById('metricAdmin').textContent=m.admin.configured?'готова':'не настроена';document.getElementById('metricProtocols').textContent=Object.values(m.protocols||{}).filter(Boolean).length;const sec=state.secretStatus;let total=2+exits.length*2, done=(sec.ingressPrivateKey?1:0)+(sec.ingressPublicKey?1:0);exits.forEach(e=>{const s=sec.exits[e.name]||{};done+=(s.privateKey?1:0)+(s.publicKey?1:0)});document.getElementById('metricSecrets').textContent=total?Math.round(done/total*100)+'%':'0%';document.getElementById('metricGenerated').textContent=(state.generatedFiles||[]).length;document.getElementById('flowDomain').textContent=m.ingress.domain||'';document.getElementById('flowIngress').textContent=(m.ingress.publicIp||m.ingress.host||'-')+' / '+(m.ingress.publicInterface||'-');document.getElementById('flowSource').textContent='source '+(m.ingress.clientSourceIp||'-');document.getElementById('flowExits').textContent=auto.map(e=>e.name).join(', ')||'нет auto exit';document.getElementById('flowWeights').textContent='weights '+auto.map(e=>e.weight).join(' / ');document.getElementById('overviewExits').innerHTML=exits.length?exits.map(exitCard).join(''):'<div class="empty">VPS пока не добавлены.</div>'}
function exitCard(e,i){return `<article class="exit-card"><div class="exit-head"><div><div class="exit-name">${escapeHtml(e.name||'-')}</div><div class="muted">${escapeHtml(e.iface||'-')}</div></div><span class="badge ${e.mode==='reserve'?'warn':'ok'}">${escapeHtml(e.mode||'auto')}</span></div><div class="kv"><span>Host</span><span>${escapeHtml(e.host||'-')}</span><span>Public IP</span><span>${escapeHtml(e.publicIp||'-')}</span><span>Tunnel</span><span>${escapeHtml(e.ingressAddress||'-')} ↔ ${escapeHtml(e.exitAddress||'-')}</span><span>Port</span><span>${e.listenPort||'-'}</span><span>Weight</span><span>${e.weight||0}</span></div></article>`}
function renderIngress(){document.getElementById('ingressForm').innerHTML=[field('Name','ingress.name'),field('SSH host/IP','ingress.host'),field('SSH user','ingress.sshUser'),field('Domain','ingress.domain'),field('Public IP','ingress.publicIp'),field('Public interface','ingress.publicInterface'),field('Client source IP','ingress.clientSourceIp'),numberField('WireGuard port','ingress.wgPort'),field('Hysteria user','ingress.hysteriaUser')].join('');document.getElementById('protocolForm').innerHTML=['wireguard','hysteria','mtproto','clientPortal','monitoring'].map(k=>protocolCheck(k)).join('');document.getElementById('routingForm').innerHTML=[numberField('Table ID','routing.tableId'),numberField('Reserve table ID','routing.reserveTableId'),field('Mark','routing.mark'),field('Reserve mark','routing.reserveMark'),textarea('Direct domains','routing.directDomains'),textarea('Reserve domains','routing.reserveDomains')].join('')}
function protocolCheck(key){const labels={wireguard:'WireGuard клиентский вход',hysteria:'Hysteria2 / Happ',mtproto:'Telegram MTProto',clientPortal:'Клиентский портал',monitoring:'Мониторинг'};return `<label class="checkrow"><input type="checkbox" ${state.manifest.protocols[key]?'checked':''} onchange="state.manifest.protocols['${key}']=this.checked"> ${labels[key]}</label>`}
function renderExits(){const exits=state.manifest.exits||[];document.getElementById('exitEditor').innerHTML=exits.map((e,i)=>`<div class="panel"><div class="actions" style="justify-content:space-between"><b>${escapeHtml(e.name||'Новый VPS')}</b><div class="actions"><span class="badge ${e.mode==='reserve'?'warn':'ok'}">${e.mode==='reserve'?'резерв':'auto'}</span><button class="danger" onclick="removeExit(${i})">Удалить</button></div></div><div class="form">${exitField(i,'Имя сервера','name')}${exitSelect(i)}${exitField(i,'SSH host/IP','host')}${exitField(i,'SSH user','sshUser')}${exitField(i,'Public IP','publicIp')}${exitField(i,'Public interface','publicInterface')}${exitField(i,'WG interface','iface')}${exitField(i,'Ingress tunnel IP','ingressAddress')}${exitField(i,'Exit tunnel IP','exitAddress')}${exitNum(i,'Prefix','prefixLength')}${exitNum(i,'Listen port','listenPort')}${exitNum(i,'Доля / weight','weight')}</div></div>`).join('')||'<div class="empty">Нажмите “Добавить VPS”.</div>'}
function exitField(i,label,key){return `<div class="field"><label>${label}</label><input value="${escapeHtml(String(state.manifest.exits[i][key]??''))}" oninput="state.manifest.exits[${i}]['${key}']=this.value"></div>`}
function exitNum(i,label,key){return `<div class="field"><label>${label}</label><input type="number" value="${escapeHtml(String(state.manifest.exits[i][key]??0))}" oninput="state.manifest.exits[${i}]['${key}']=Number(this.value)||0"></div>`}
function exitSelect(i){const mode=state.manifest.exits[i].mode||'auto';return `<div class="field"><label>Mode</label><select onchange="state.manifest.exits[${i}].mode=this.value"><option value="auto" ${mode==='auto'?'selected':''}>auto</option><option value="reserve" ${mode==='reserve'?'selected':''}>reserve</option></select></div>`}
function addExit(){state.manifest.exits ||= [];const n=state.manifest.exits.length+1;state.manifest.exits.push({name:'EXIT-'+n,mode:'auto',host:'',sshUser:'root',publicIp:'',publicInterface:'eth0',iface:'wg-exit-new'+n,ingressAddress:'10.77.'+(10+n)+'.1',exitAddress:'10.77.'+(10+n)+'.2',prefixLength:30,listenPort:51840+n,weight:10});renderAll()}
function removeExit(i){state.manifest.exits.splice(i,1);renderAll()}
function normalizeWeights(){const auto=state.manifest.exits.filter(e=>e.mode!=='reserve');auto.forEach(e=>e.weight=10);renderAll();toast('Доли auto выровнены')}
function renderUsers(){const users=state.manifest.users||[];document.getElementById('userEditor').innerHTML=users.length?`<table class="table"><thead><tr><th>Username</th><th>Лимит</th><th>Заметка</th><th></th></tr></thead><tbody>${users.map((u,i)=>`<tr><td><input value="${escapeHtml(u.username||'')}" oninput="state.manifest.users[${i}].username=this.value"></td><td><input type="number" min="0" max="25" value="${u.maxProfiles??1}" oninput="state.manifest.users[${i}].maxProfiles=Number(this.value)||0"></td><td><input value="${escapeHtml(u.note||'')}" oninput="state.manifest.users[${i}].note=this.value"></td><td><button class="danger" onclick="removeUser(${i})">Удалить</button></td></tr>`).join('')}</tbody></table>`:'<div class="empty">Пользователи пока не добавлены.</div>'}
function addUser(){state.manifest.users ||= [];state.manifest.users.push({username:'',maxProfiles:1,note:''});renderAll()}
function removeUser(i){state.manifest.users.splice(i,1);renderAll()}
function syncConnectionForm(){if(!state)return;const host=document.getElementById('discoverHost'), user=document.getElementById('discoverUser'), key=document.getElementById('discoverKey');if(host&&!host.value)host.value=state.manifest.ingress?.host||'';if(user&&!user.value)user.value=state.manifest.ingress?.sshUser||'root';if(key&&!key.value)key.value=state.connection?.ingressKeyPath||'.vpn-secrets\\ssh-key'}
function renderAuthMode(){[['discoverAuth','discoverKey','discoverPasswordField'],['wizardAuth','wizardKey','wizardPasswordField']].forEach(([authId,keyId,passId])=>{const auth=document.getElementById(authId), key=document.getElementById(keyId), pass=document.getElementById(passId);if(!auth||!key||!pass)return;const password=auth.value==='password';key.closest('.field').style.display=password?'none':'';pass.style.display=password?'':'none'})}
function activeAuthMode(){const active=document.querySelector('.tabs.active')?.id;if(active==='wizard')return document.getElementById('wizardAuth')?.value||'key';return document.getElementById('discoverAuth')?.value||document.getElementById('wizardAuth')?.value||'key'}
function connectionPayload(){const authMode=activeAuthMode();const ingress=setupServers.find(s=>s.role==='ingress')||{};const host=(document.getElementById('discoverHost')?.value||document.getElementById('f_ingress_host')?.value||ingress.host||state.manifest.ingress?.host||'').trim();const sshUser=(document.getElementById('discoverUser')?.value||document.getElementById('f_ingress_sshUser')?.value||ingress.sshUser||state.manifest.ingress?.sshUser||'root').trim()||'root';const savedKey=state.connection?.ingressKeyPath||'.vpn-secrets\\ssh-key';const enteredKey=document.getElementById('discoverKey')?.value||document.getElementById('wizardKey')?.value||savedKey;const keyPath=authMode==='key'?enteredKey.trim():'';const password=authMode==='password'?(document.getElementById('discoverPassword')?.value||document.getElementById('wizardPassword')?.value||ingress.password||savedServerPassword(ingress.name,ingress.host)||''):'';return {host,sshUser,keyPath,password,authMode}}
function applyKeyHint(name){document.getElementById('discoverKey').value='.vpn-secrets\\'+name}
async function discoverIngress(){const payload=connectionPayload();const out=document.getElementById('discoverOutput');out.textContent='Подключаюсь по SSH...';try{const res=await api('/api/discover/ingress',payload);state.manifest=res.manifest;state.profiles=res.profiles;out.textContent=JSON.stringify(res.discovery,null,2);await refreshMonitor(false);await loadState();showTab('admin');toast('Сервер обнаружен, профиль сохранен')}catch(e){out.textContent=e.message;alert(e.message)}}
let monitorAutoTried=false;
function maybeAutoRefreshMonitor(){if(monitorAutoTried)return;const p=connectionPayload();if(!p.host||(!p.keyPath&&!p.password))return;monitorAutoTried=true;refreshMonitor(false)}
async function refreshMonitor(showToast=true){const targets=['monitorOverviewHome','monitorOverviewConnect','monitorOverviewVps'];targets.forEach(id=>{const el=document.getElementById(id);if(el)el.innerHTML='<div class="empty">Загружаю мониторинг...</div>'});try{monitorData=await api('/api/monitor/ingress',connectionPayload());renderMonitor();if(showToast)toast('Мониторинг обновлен')}catch(e){monitorData={error:e.message};renderMonitor();if(showToast)alert(e.message)}}
async function syncProfileFromMonitor(){toast('Синхронизирую профиль из мониторинга...');try{const r=await api('/api/monitor/sync',connectionPayload());state.manifest=r.manifest;state.profiles=r.profiles;monitorData=r.monitor;renderAll();toast('Профиль обновлен из мониторинга')}catch(e){alert('Не удалось синхронизировать профиль:\\n'+e.message)}}
function renderMonitor(){const targets=['monitorOverviewHome','monitorOverviewConnect','monitorOverviewVps'];targets.forEach(id=>{const el=document.getElementById(id);if(!el)return;el.innerHTML=monitorHtml(monitorData)})}
function monitorHtml(data){if(!data)return '<div class="empty">Мониторинг еще не загружен. Если профиль уже есть, нажмите “Обновить мониторинг”.</div>';if(data.error)return `<div class="empty">${escapeHtml(data.error)}</div>`;const exits=data.exits||[], auto=exits.filter(e=>e.mode!=='reserve'), reserve=exits.filter(e=>e.mode==='reserve'), active=auto.filter(exitHealthy), ready=reserve.filter(e=>e.probe_result&&e.probe_result.ping_ok);const entry=data.client_entrypoints||{}, wg=entry.wg_easy_container_external_ip||'n/a', hy=entry.hysteria_process_external_ip||'n/a', route=data.route_table_100||'нет маршрута';const activeName=active[0]?.name||'нет активного выхода';const activeIp=active[0]?.probe_result?.public_ip||'';const totalWeight=auto.filter(exitHealthy).reduce((s,e)=>s+(Number(e.weight)||0),0);const systemOk=Object.values(data.services||{}).every(v=>v==='active');return `<div class="actions" style="justify-content:space-between;margin-bottom:10px"><div class="muted">${escapeHtml(data.hostname||'ingress')} · ${escapeHtml(data.generated_at||'')} · read-only</div><span class="badge ${systemOk?'ok':'warn'}">${systemOk?'сервисы OK':'есть проблема'}</span></div><div class="monitor-grid"><div class="panel"><div class="muted">Активный выход</div><div class="metric">${escapeHtml(activeName)}</div><div class="muted">${escapeHtml(activeIp||routeLabel(route))}</div></div><div class="panel"><div class="muted">Доступно авто-выходов</div><div class="metric">${active.length} / ${auto.length}</div><div class="muted">резервов готово: ${ready.length}</div></div><div class="panel"><div class="muted">wg-easy показывает</div><div class="metric">${escapeHtml(wg)}</div><div class="muted">WireGuard-клиенты</div></div><div class="panel"><div class="muted">Hysteria Auto показывает</div><div class="metric">${escapeHtml(hy)}</div><div class="muted">${wg!=='n/a'&&wg===hy?'тот же путь':'отличается от wg-easy'}</div></div></div><div class="monitor-flow"><div class="monitor-card"><span class="muted">Входы</span><strong>WireGuard + Hysteria</strong><div class="muted">wg-easy: ${escapeHtml(wg)}<br>Hysteria: ${escapeHtml(hy)}</div></div><div class="arrow">→</div><div class="monitor-card"><span class="muted">Решение маршрута</span><strong>${escapeHtml(routeLabel(route))}</strong><div class="muted">RU/direct остаются на ingress, остальное идет в table 100</div></div><div class="arrow">→</div><div class="monitor-card"><span class="muted">Текущий выход</span><strong>${escapeHtml(activeName)}</strong><div class="muted">${escapeHtml(activeIp||'нет рабочего выхода')}</div></div></div><h2>Куда сейчас уходит трафик</h2><div class="monitor-exits">${exits.map(e=>monitorExitCard(e,totalWeight)).join('')||'<div class="empty">Exit-серверы не найдены в мониторинге.</div>'}</div><h2>Балансировка</h2><div class="monitor-exits">${auto.map(e=>monitorWeightCard(e)).join('')||'<div class="empty">Auto-выходы не найдены.</div>'}</div><details style="margin-top:12px"><summary>Технические детали</summary><pre>${escapeHtml(JSON.stringify({generated_at:data.generated_at,hostname:data.hostname,services:data.services,route_table_100:data.route_table_100,nft_counters:data.nft_counters},null,2))}</pre></details>`}
function exitHealthy(e){return !!(e&&e.in_route_table&&e.probe_result&&e.probe_result.ping_ok)}
function routeLabel(route){if(!route)return 'нет маршрута';if(route.includes('blackhole'))return 'fail-closed';return route.replaceAll('default dev ','').replaceAll('\n',' / ')}
function monitorExitCard(e,totalWeight){const healthy=exitHealthy(e), reserve=e.mode==='reserve', ready=reserve&&e.probe_result&&e.probe_result.ping_ok, cls=healthy?'live':(ready?'reserve':'offline'), share=healthy&&totalWeight?Math.round((Number(e.weight)||0)/totalWeight*100):0, peer=(e.wg?.peers||[])[0]||{}, hs=peer.handshake_age_sec==null?'нет':(peer.handshake_age_sec<60?peer.handshake_age_sec+'с':Math.round(peer.handshake_age_sec/60)+'м'), pub=e.probe_result?.public_ip||'нет ответа', status=healthy?'в маршруте':(ready?'резерв готов':'исключен');return `<article class="monitor-card ${cls}"><div class="exit-head"><div><strong>${escapeHtml(e.name||'-')}</strong><div class="muted">${escapeHtml(e.iface||'-')}</div></div><span class="badge ${healthy?'ok':(ready?'warn':'bad')}">${status}</span></div><div class="bar"><i style="width:${share}%"></i></div><div class="kv"><span>${reserve?'Режим':'Доля'}</span><span>${reserve?'ручной':share+'%'}</span><span>Handshake</span><span>${escapeHtml(hs)}</span><span>IP выхода</span><span>${escapeHtml(pub)}</span><span>Weight</span><span>${e.weight??0}</span></div></article>`}
function monitorWeightCard(e){return `<article class="monitor-card"><div class="exit-head"><div><strong>${escapeHtml(e.name||'-')}</strong><div class="muted">${escapeHtml(e.iface||'-')}</div></div><span class="badge ${Number(e.weight)===0?'warn':'ok'}">${Number(e.weight)===0?'выключен':'weight '+(e.weight??0)}</span></div><div class="kv"><span>Текущий вес</span><span>${e.weight??0}</span><span>По умолчанию</span><span>${e.default_weight??e.weight??0}</span><span>Режим</span><span>${escapeHtml(e.mode||'auto')}</span></div></article>`}
function savedServerPassword(name,host){const p=state.connection?.serverPasswords||{};return p[name]||p[host]||''}
function initSetupServers(reset=false){if(setupServers.length&&!reset)return;setupServers=[];const ing=state.manifest.ingress||{};setupServers.push({role:'ingress',name:ing.name||'ingress-1',host:ing.host||'',sshUser:ing.sshUser||'root',password:savedServerPassword(ing.name,ing.host),domain:ing.domain||'',publicInterface:ing.publicInterface||'eth0',wgEasyMode:'install'});(state.manifest.exits||[]).forEach((e,i)=>setupServers.push({role:'exit',name:e.name||'exit-'+(i+1),host:e.host||e.publicIp||'',sshUser:e.sshUser||'root',password:savedServerPassword(e.name,e.host||e.publicIp),domain:e.domain||'',publicInterface:e.publicInterface||'eth0',wgEasyMode:e.wgEasyMode||'install'}))}
function addSetupServer(role='exit'){if(role==='ingress')setupServers.forEach(s=>s.role='exit');setupServers.push({role,name:role+'-'+(setupServers.length+1),host:'',sshUser:'root',password:'',domain:'',publicInterface:'eth0',wgEasyMode:'install'});renderWizard()}
function removeSetupServer(i){setupServers.splice(i,1);if(!setupServers.some(s=>s.role==='ingress')&&setupServers[0])setupServers[0].role='ingress';renderWizard()}
function updateSetupServer(i,key,value){setupServers[i][key]=value;if(key==='role'&&value==='ingress')setupServers.forEach((s,idx)=>{if(idx!==i&&s.role==='ingress')s.role='exit'});applySetupServers()}
function setSetupRole(i,role){updateSetupServer(i,'role',role);renderWizard()}
function applySetupServers(){if(!setupServers.length)return;let ingress=setupServers.find(s=>s.role==='ingress')||setupServers[0];ingress.role='ingress';state.manifest.profileName=state.manifest.profileName||'New network';state.manifest.ingress.name=ingress.name||'ingress';state.manifest.ingress.host=ingress.host||'';state.manifest.ingress.sshUser=ingress.sshUser||'root';state.manifest.ingress.publicIp=ingress.host||'';state.manifest.ingress.domain=ingress.domain||'';state.manifest.ingress.publicInterface=ingress.publicInterface||'eth0';state.manifest.exits=setupServers.filter(s=>s!==ingress).map((s,i)=>({name:s.name||'exit-'+(i+1),mode:'auto',host:s.host||'',sshUser:s.sshUser||'root',publicIp:s.host||'',publicInterface:s.publicInterface||'eth0',wgEasyMode:s.wgEasyMode||'install',iface:'wg-exit-'+(s.name||('exit-'+(i+1))).toLowerCase().replace(/[^a-z0-9]+/g,''),ingressAddress:'10.77.'+(10+i+1)+'.1',exitAddress:'10.77.'+(10+i+1)+'.2',prefixLength:30,listenPort:51830+i,weight:10,uiPort:51831+i,hysteriaPort:8444+i}))}
function setupServerCard(s,i){const role=s.role||'exit', isIngress=role==='ingress';const domainField=isIngress?`<div class="field"><label>Домен входной ноды</label><input value="${escapeHtml(s.domain||'')}" oninput="updateSetupServer(${i},'domain',this.value)" placeholder="vpn.example.com"><div class="muted" style="font-size:12px;margin-top:4px">Если пусто, wg-easy будет открыт по HTTP с INSECURE=true.</div></div>`:'';const wgModeField=!isIngress?`<div class="field"><label>wg-easy на выходном</label><select onchange="updateSetupServer(${i},'wgEasyMode',this.value)"><option value="install" ${(s.wgEasyMode||'install')==='install'?'selected':''}>Установить новый</option><option value="existing" ${s.wgEasyMode==='existing'?'selected':''}>Уже есть, не трогать клиентов</option></select><div class="muted" style="font-size:12px;margin-top:4px">Existing-режим не меняет контейнер, volume и выданные профили.</div></div>`:'';return `<article class="setup-card ${isIngress?'ingress':'exit'}"><div class="setup-card-top"><div class="actions"><div class="setup-icon">${isIngress?'IN':'EX'}</div><div><div class="setup-title">${escapeHtml(s.name||'server')}</div><div class="setup-sub">${isIngress?'Входной сервер':'Выходной сервер'} · ssh</div></div></div><div class="role-tabs"><button class="${isIngress?'active':''}" onclick="setSetupRole(${i},'ingress')">Входной</button><button class="${!isIngress?'active':''}" onclick="setSetupRole(${i},'exit')">Выходной</button></div></div><div class="setup-fields"><div class="field"><label>Название</label><input value="${escapeHtml(s.name||'')}" oninput="updateSetupServer(${i},'name',this.value);document.querySelectorAll('.setup-title')[${i}].textContent=this.value||'server'"></div><div class="field"><label>IP / host VPS</label><input value="${escapeHtml(s.host||'')}" oninput="updateSetupServer(${i},'host',this.value)" placeholder="203.0.113.10"></div>${domainField}${wgModeField}<div class="field"><label>Root user</label><input value="${escapeHtml(s.sshUser||'root')}" oninput="updateSetupServer(${i},'sshUser',this.value)" placeholder="root"></div><div class="field"><label>Public interface</label><input value="${escapeHtml(s.publicInterface||'eth0')}" oninput="updateSetupServer(${i},'publicInterface',this.value)" placeholder="eth0"></div><div class="field"><label>Пароль root / sudo</label><input type="password" value="${escapeHtml(s.password||'')}" oninput="updateSetupServer(${i},'password',this.value)" placeholder="сохранится локально в .vpn-secrets"></div></div><div class="actions" style="justify-content:space-between;margin-top:12px"><div class="setup-note">${isIngress?'На него будут подключаться клиенты.':(s.wgEasyMode==='existing'?'Текущий wg-easy и клиенты будут сохранены.':'Через него будет выходить трафик.')}</div><button class="secondary" onclick="removeSetupServer(${i})" ${setupServers.length<=1?'disabled':''}>Удалить</button></div></article>`}
function setupServerTable(){initSetupServers();return `<div class="setup-head"><div class="field"><label>Название сети</label><input value="${escapeHtml(state.manifest.profileName||'New network')}" oninput="state.manifest.profileName=this.value" placeholder="Production VPN"></div><div class="actions"><button onclick="addSetupServer('ingress')">Добавить входной</button><button class="secondary" onclick="addSetupServer('exit')">Добавить выходной</button></div></div><div class="setup-grid">${setupServers.map(setupServerCard).join('')}</div>`}
function goWizardProtocols(){initSetupServers();const missing=setupServers.filter(s=>!String(s.name||'').trim()||!String(s.host||'').trim()||!String(s.sshUser||'').trim()||!String(s.password||'').trim());if(missing.length){alert('Заполните для каждого VPS: название, IP / host, root user и пароль.');return}if(!setupServers.some(s=>s.role==='ingress')){alert('Выберите один входной сервер.');return}applySetupServers();wizardStep=1;renderWizard()}
function markAdminConfigured(){state.manifest.admin.configured=true;state.manifest.admin.lastLogin=new Date().toISOString();saveAll()}
async function enterAdmin(){if(!state.profiles||state.profiles.length===0){alert('Сначала создайте и сохраните профиль сети. Минимально нужен один входной VPS. Exit-VPS нужны для балансировки и резервов.');return}const profile=state.profiles[0];const loaded=await api('/api/profile/load',{id:profile.id});state.manifest=loaded.manifest;state.profiles=loaded.profiles;state.manifest.admin.configured=true;await saveAll();document.getElementById('landing').classList.add('hidden');document.getElementById('appShell').classList.remove('locked');showTab('admin')}
async function enterNetwork(){if(state.profiles&&state.profiles.length){await enterAdmin();return}enterConnectServers()}
function enterConnectServers(){state.manifest.admin.configured=true;renderAll();document.getElementById('landing').classList.add('hidden');document.getElementById('appShell').classList.remove('locked');showTab('connect')}
function logout(){state.manifest.admin.configured=false;saveAll();document.getElementById('landing').classList.remove('hidden');document.getElementById('appShell').classList.add('locked')}
function startNewNetwork(){state.manifest={productVersion:1,admin:{configured:true,lastLogin:new Date().toISOString()},profileId:'',profileName:'New network',ingress:{name:'ingress-1',host:'',sshUser:'root',domain:'',publicIp:'',publicInterface:'eth0',clientSourceIp:'10.42.42.42',wgPort:51820,hysteriaUser:'hysteria'},routing:{tableId:100,reserveTableId:101,mark:'0x77',reserveMark:'0x78',directDomains:[],reserveDomains:[]},protocols:{wireguard:true,hysteria:true,mtproto:false,clientPortal:true,monitoring:true},users:[],exits:[]};setupServers=[];initSetupServers(true);wizardStep=0;renderAll();document.getElementById('landing').classList.add('hidden');document.getElementById('appShell').classList.remove('locked');showTab('wizard')}
function authWizardHtml(){const saved=state.connection?.ingressKeyPath||'.vpn-secrets\\ssh-key';return `<div class="field"><label>Способ входа на VPS</label><select id="wizardAuth" onchange="renderAuthMode()"><option value="key">SSH-ключ</option><option value="password">Пароль</option></select></div><div class="field"><label>Путь к SSH-ключу</label><input id="wizardKey" value="${escapeHtml(saved)}" placeholder=".vpn-secrets\\ssh-key"></div><div class="field" id="wizardPasswordField" style="display:none"><label>SSH password</label><input id="wizardPassword" type="password" autocomplete="current-password" placeholder="сохраняется в .vpn-secrets"></div>`}
function wizardStats(){
  initSetupServers();
  const ingress=setupServers.find(s=>s.role==='ingress')||{};
  const exits=setupServers.filter(s=>s.role!=='ingress');
  const ready=setupServers.filter(s=>String(s.host||'').trim()&&String(s.password||'').trim()).length;
  return `<div class="wizard-status"><div class="wizard-stat"><span class="muted">Вход</span><b>${escapeHtml(ingress.host||'не выбран')}</b></div><div class="wizard-stat"><span class="muted">Выходы</span><b>${exits.length}</b></div><div class="wizard-stat"><span class="muted">Доступы</span><b>${ready} / ${setupServers.length}</b></div></div>`
}
function wizardFrame(kicker,title,sub,content,actions=''){
  return `<div class="wizard-shell"><div class="wizard-inner"><div class="wizard-hero"><div><div class="wizard-kicker">${escapeHtml(kicker)}</div><h2>${escapeHtml(title)}</h2><div class="muted">${escapeHtml(sub)}</div></div>${wizardStats()}</div><div class="wizard-work">${content}</div>${actions?`<div class="wizard-actions">${actions}</div>`:''}</div></div>`
}
function protocolTile(key){
  const labels={wireguard:'WireGuard / wg-easy',hysteria:'Hysteria2 / Happ',mtproto:'Telegram MTProto',clientPortal:'Клиентский портал',monitoring:'Мониторинг'};
  const desc={wireguard:'Клиентские профили, веб-интерфейс и основной VPN-вход.',hysteria:'Резервный быстрый вход через Hysteria2.',mtproto:'Отдельный сценарий для Telegram-прокси.',clientPortal:'Страница для пользователей и выдачи доступов.',monitoring:'Read-only статус сети, выходов, маршрутов и сервисов.'};
  const icons={wireguard:'WG',hysteria:'HY',clientPortal:'UI',monitoring:'ST',mtproto:'TG'};
  const on=!!state.manifest.protocols[key];
  return `<label class="protocol-card ${on?'is-on':'is-off'}"><input type="checkbox" ${on?'checked':''} onchange="state.manifest.protocols['${key}']=this.checked;renderWizard()"><span class="proto-icon">${icons[key]}</span><span><strong>${labels[key]}</strong><small>${desc[key]}</small></span></label>`
}
function setupSummaryCard(){
  const p=state.manifest.protocols||{};
  const protocols=['wireguard','hysteria','mtproto','clientPortal','monitoring'].filter(k=>p[k]).length;
  const existing=(state.manifest.exits||[]).filter(e=>e.wgEasyMode==='existing').length;
  return `<div class="grid"><div class="wizard-panel"><span class="muted">Ingress</span><div class="metric">${escapeHtml(state.manifest.ingress.host||'-')}</div></div><div class="wizard-panel"><span class="muted">Exit VPS</span><div class="metric">${(state.manifest.exits||[]).length}</div></div><div class="wizard-panel"><span class="muted">Протоколы</span><div class="metric">${protocols}</div></div><div class="wizard-panel"><span class="muted">Existing wg-easy</span><div class="metric">${existing}</div></div></div>`
}
function installSequence(){
  const files=state.generatedFiles||[];
  const bootstrap=files.filter(f=>f.name&&f.name.startsWith('bootstrap-')).length;
  const ok=preflightResults.filter(r=>r.ok).length;
  const running=Object.values(activeJobs).filter(j=>j.status==='running').length;
  const done=Object.values(activeJobs).filter(j=>j.status==='completed').length;
  const failed=Object.values(activeJobs).filter(j=>j.status==='failed').length;
  const total=(installPlan?.steps||[]).length||bootstrap||setupServers.length;
  return `<div class="install-sequence"><div class="install-step prepare ${bootstrap?'done':'active'}"><i>1</i><div><b>Подготовить установку</b><div class="muted">Сохранить профиль и собрать bootstrap-скрипты.</div></div><span class="badge ${bootstrap?'ok':'warn'}">${bootstrap?bootstrap+' файлов':'ждет'}</span></div><div class="install-step check ${ok?'done':(bootstrap?'active':'')}"><i>2</i><div><b>Проверить серверы</b><div class="muted">Preflight покажет host key, ОС, root-доступ, Docker и возможные конфликты.</div></div><span class="badge ${ok?'ok':'warn'}">${ok} / ${total}</span></div><div class="install-step run ${failed?'problem':(running?'active':(done?'done':''))}"><i>3</i><div><b>Запустить очередь</b><div class="muted">Ingress выполняется первым, затем выходные серверы. При ошибке очередь остановится.</div></div><span class="badge ${failed?'bad':(done?'ok':'warn')}">${running?'идет':(failed?'ошибка':done?done+' готово':'не начато')}</span></div></div>`
}
function renderWizard(){
  if(!state)return;
  document.querySelectorAll('.step-pill').forEach(x=>x.classList.toggle('active',Number(x.dataset.wstep)===wizardStep));
  const body=document.getElementById('wizardBody');
  if(!body)return;
  if(wizardStep===0){
    body.innerHTML=wizardFrame('topology','Соберите карту сети','Минимум: названия серверов, IP, root-пользователь, пароль и роль каждого VPS.',setupServerTable(),`<button class="secondary" onclick="saveProfile()">Сохранить черновик</button><button onclick="goWizardProtocols()">Дальше</button>`);
  }else if(wizardStep===1){
    body.innerHTML=wizardFrame('protocols','Выберите модули сети','Оставьте только то, что реально нужно ставить на эти VPS.',`<div class="protocol-grid">${['wireguard','hysteria','clientPortal','monitoring','mtproto'].map(k=>protocolTile(k)).join('')}</div>`,`<button class="secondary" onclick="wizardStep=0;renderWizard()">Назад</button><button onclick="wizardStep=2;renderWizard()">Дальше</button>`);
  }else if(wizardStep===2){
    applySetupServers();
    const exits=(state.manifest.exits||[]).map((e,i)=>`<div class="wizard-panel"><div class="actions" style="justify-content:space-between;margin-bottom:10px"><h3>${escapeHtml(e.name||'Exit')}</h3><span class="badge ${e.mode==='reserve'?'warn':'ok'}">${e.mode==='reserve'?'резерв':'auto'}</span></div><div class="form">${exitField(i,'Имя','name')}${exitSelect(i)}${exitField(i,'Host/IP','host')}${exitField(i,'SSH user','sshUser')}${exitField(i,'Public interface','publicInterface')}${exitNum(i,'Port','listenPort')}${exitNum(i,'Weight','weight')}</div></div>`).join('')||'<div class="empty">Exit-VPS не добавлены. Это допустимо для минимального профиля без балансировки.</div>';
    body.innerHTML=wizardFrame('routing','Проверьте роли и балансировку','На этом шаге серверы еще не меняются. Вы только подтверждаете будущую схему.',`<div class="control-note">Preflight и установка запускаются отдельно на следующем шаге. Если на сервере уже есть wg-easy, выберите режим сохранения на карточке VPS.</div><div class="actions"><button onclick="addExit();renderWizard()">Добавить выходной VPS</button><button class="secondary" onclick="normalizeWeights();renderWizard()">Выровнять доли auto</button></div>${exits}`,`<button class="secondary" onclick="wizardStep=1;renderWizard()">Назад</button><button onclick="wizardStep=3;renderWizard()">Дальше</button>`);
  }else{
    applySetupServers();
    body.innerHTML=wizardFrame('install control','Установка под контролем','Сначала собираем скрипты, затем проверяем каждый VPS, потом запускаем очередь.',`${setupSummaryCard()}${installSequence()}<div class="control-note">После успешной установки приложение покажет попап с дальнейшим действием: открыть wg-easy, скопировать IP или перейти к подключению существующего wg-easy.</div>`,`<button class="secondary" onclick="wizardStep=2;renderWizard()">Назад</button><button class="btn-prepare" onclick="renderBootstrap()">1. Подготовить</button><button class="btn-check" onclick="preflightAllBootstrap();showTab('render')">2. Проверить</button><button class="btn-run danger" onclick="runAllBootstrap()">3. Запустить</button>`);
  }
}function renderSecrets(){const exits=state.manifest.exits||[];document.getElementById('secretForm').innerHTML=[secretInput('Ingress private key','wireguard.ingress.privateKey'),secretInput('Ingress public key','wireguard.ingress.publicKey'),secretInput('Telegram bot token','telegram.botToken'),secretInput('Telegram bot username','telegram.botUsername'),secretInput('Admin Telegram IDs','telegram.adminTelegramIds'),...exits.flatMap(e=>[secretInput(`${e.name} private key`,`wireguard.exits.${e.name}.privateKey`),secretInput(`${e.name} public key`,`wireguard.exits.${e.name}.publicKey`),secretInput(`${e.name} preshared key`,`wireguard.exits.${e.name}.presharedKey`)])].join('');const s=state.secretStatus;let cards=[statusCard('Ingress private key',s.ingressPrivateKey),statusCard('Ingress public key',s.ingressPublicKey),statusCard('Telegram bot token',s.telegramBotToken)];exits.forEach(e=>{const x=s.exits[e.name]||{};cards.push(statusCard(e.name+' private key',x.privateKey));cards.push(statusCard(e.name+' public key',x.publicKey))});document.getElementById('secretStatus').innerHTML=cards.join('')}
function secretInput(label,path){return `<div class="field"><label>${escapeHtml(label)}</label><input type="password" data-secret="${escapeHtml(path)}" placeholder="оставьте пустым, чтобы не менять"></div>`}
function statusCard(name,ok){return `<div class="panel"><b>${escapeHtml(name)}</b><div style="margin-top:8px"><span class="badge ${ok?'ok':'bad'}">${ok?'задан':'нет'}</span></div></div>`}
function checkBadge(status){return status==='ok'?'ok':(status==='bad'?'bad':'warn')}
function runningFileSet(){return new Set(Object.values(activeJobs).filter(j=>j.status==='running').map(j=>j.file))}
function stageInfo(stage){
  const order=['queued','upload-script','validate-root','validate-os','backup-created','install-packages','install-docker','enable-forwarding','configure-wg-easy','preserve-existing-wg-easy','configure-service-wireguard','inspect-hysteria','configure-hysteria','verify-services'];
  const labels={'queued':'Ожидает запуска','upload-script':'Загрузка скрипта','validate-root':'Проверка root-доступа','validate-os':'Проверка ОС','backup-created':'Создание backup','install-packages':'Установка пакетов','install-docker':'Установка Docker','enable-forwarding':'Включение маршрутизации','configure-wg-easy':'Настройка wg-easy','preserve-existing-wg-easy':'Сохранение существующего wg-easy','configure-service-wireguard':'Подключение служебного WireGuard','inspect-hysteria':'Проверка Hysteria','configure-hysteria':'Настройка Hysteria','verify-services':'Проверка сервисов'};
  const idx=Math.max(0,order.findIndex(x=>String(stage||'').startsWith(x)));
  return {label:labels[order[idx]]||stage||'Выполняется',pct:Math.min(96,Math.round((idx+1)/order.length*100))}
}
function humanPort(line){
  const port=(line.match(/[:*\\.](\d+)\s/)||[])[1]||'';
  const proto=line.includes('udp')?'UDP':(line.includes('tcp')?'TCP':'порт');
  const proc=(line.match(/users:\(\("([^"]+)"/)||[])[1]||'сервис';
  const map={51820:'WireGuard',51821:'wg-easy UI',51830:'WireGuard exit',51831:'wg-easy exit UI',8443:'Hysteria',8444:'Hysteria exit'};
  return port?`${map[port]||'Порт'} ${port}/${proto} занят процессом ${proc}`:line;
}
function humanCheckDetail(detail){
  return String(detail||'').replace(/\\n/g,'\n').split('\n').filter(Boolean).map(line=>{
    if(line.startsWith('port='))return humanPort(line.slice(5));
    if(line.startsWith('container=wg-easy'))return 'Найден контейнер wg-easy: '+line.replace('container=wg-easy','').trim();
    if(line.startsWith('docker_version='))return line.replace('docker_version=','Docker: ');
    if(line.startsWith('wg_easy_interface='))return 'wg-easy интерфейс: '+line.replace('wg_easy_interface=','');
    if(line.startsWith('wg_interface='))return 'WireGuard интерфейс: '+line.replace('wg_interface=','');
    if(line==='apt_get=present')return 'apt доступен';
    if(line==='docker=present')return 'Docker установлен';
    if(line==='docker=missing')return 'Docker не установлен, bootstrap поставит его';
    if(line==='root_writable=yes')return 'root-директория доступна для записи';
    return line;
  }).join('\n');
}
function formatLogLines(lines,error=''){
  const raw=[...(lines||[]), ...(error?[error]:[])].join('\n').replace(/\\n/g,'\n').split('\n').map(x=>x.trim()).filter(Boolean);
  if(!raw.length)return '<div class="empty">Лог пока пуст.</div>';
  return `<div class="pretty-log">${raw.slice(-180).map(line=>{const isStage=line.startsWith('[stage]'), isErr=/error|failed|denied|fatal|not found|permission/i.test(line);const text=isStage?stageInfo(line.replace('[stage]','').trim()).label:humanCheckDetail(line);return `<div class="log-line ${isStage?'stage':(isErr?'err':'')}"><span class="log-kind">${isStage?'этап':(isErr?'ошибка':'лог')}</span><span>${escapeHtml(text)}</span></div>`}).join('')}</div>`
}
function installCheckHtml(checks){
  return `<div class="check-grid">${(checks||[]).map(c=>`<div class="check-item"><b>${escapeHtml(c.name||'Проверка')}</b><span class="badge ${checkBadge(c.status)}">${escapeHtml(c.status||'')}</span><div class="muted" style="white-space:pre-line;margin-top:6px">${escapeHtml(humanCheckDetail(c.detail||''))}</div></div>`).join('')}</div>`
}
function installNoticeHtml(job){
  const ip=job.wgHost||job.host||'';
  const url=job.wgEasyUrl||`http://${ip}:${job.role==='ingress'?51821:51831}/`;
  if(job.nextAction==='connect-existing-wg-easy'){
    return `<h2>Существующий wg-easy сохранен</h2><div class="muted">${escapeHtml(job.server||job.file)} · ${escapeHtml(job.host||'')}</div><div class="notice">Клиентские профили и контейнер wg-easy не менялись. Для нашей сети создан отдельный служебный WireGuard-интерфейс; проверьте статус сервера и маршрут в мониторинге.</div><div class="kv"><span>IP сервера</span><span><b>${escapeHtml(ip)}</b></span><span>Web UI</span><span>${escapeHtml(url)}</span></div><div class="modal-actions"><button onclick="copyText('${escapeHtml(ip)}')">Скопировать IP</button><button class="secondary" onclick="window.open('${escapeHtml(url)}','_blank')">Открыть wg-easy</button><button onclick="confirmWgEasySetup()">Настройка завершена</button></div>`
  }
  const text=job.role==='exit'
    ? 'Откройте wg-easy на выходном сервере и завершите первичную настройку. IP уже скопирован: вставьте его в поле host/public endpoint, если интерфейс спросит адрес сервера.'
    : 'Откройте wg-easy на входном сервере и завершите первичную настройку. IP уже скопирован: он понадобится как публичный адрес сервера.';
  return `<h2>Установка завершена</h2><div class="muted">${escapeHtml(job.server||job.file)} · ${escapeHtml(job.host||'')}</div><div class="notice">${escapeHtml(text)}</div><div class="kv"><span>IP для wg-easy</span><span><b>${escapeHtml(ip)}</b></span><span>Web UI</span><span>${escapeHtml(url)}</span></div><div class="modal-actions"><button onclick="copyText('${escapeHtml(ip)}')">Скопировать IP</button><button class="secondary" onclick="window.open('${escapeHtml(url)}','_blank')">Открыть wg-easy</button><button onclick="confirmWgEasySetup()">Настройка завершена</button></div>`
}
function showInstallModal(html){document.getElementById('installModalBody').innerHTML=html;document.getElementById('installModal').classList.remove('hidden')}
function closeInstallModal(){document.getElementById('installModal').classList.add('hidden')}
function confirmWgEasySetup(){closeInstallModal();toast('Настройка подтверждена')}
async function copyText(text){try{await navigator.clipboard.writeText(text);toast('Скопировано: '+text)}catch(e){prompt('Скопируйте вручную',text)}}
async function copyTextSilent(text){try{await navigator.clipboard.writeText(text);toast('IP скопирован')}catch(e){}}
async function showPostInstallNotice(job){if(job.status!=='completed'||!['configure-wg-easy','connect-existing-wg-easy'].includes(job.nextAction))return;const ip=job.wgHost||job.host||'';await copyTextSilent(ip);showInstallModal(installNoticeHtml(job));if(job.wgEasyUrl)window.open(job.wgEasyUrl,'_blank')}
function showInstallError(job){showInstallModal(`<h2>Установка остановилась</h2><div class="muted">${escapeHtml(job.server||job.file||'server')} · ${escapeHtml(job.host||'')}</div><div class="notice">Очередь остановлена на этом сервере. Иногда помогает повторный запуск, но сначала посмотрите лог и preflight: часто причина в занятом порте, host key, нехватке места или уже установленном сервисе.</div>${formatLogLines(job.lines||[],job.error||'')}<div class="modal-actions"><button onclick="closeInstallModal();runBootstrapFile('${escapeHtml(job.file||'')}')">Повторить</button><button class="secondary" onclick="closeInstallModal();preflightBootstrapFile('${escapeHtml(job.file||'')}')">Проверить сервер</button><button class="secondary" onclick="closeInstallModal()">Закрыть</button></div>`)}
function showNetworkReadyModal(){showInstallModal(`<h2>Сеть установлена</h2><div class="notice">Все серверы из очереди завершили установку. Следующий шаг - проверить мониторинг входной ноды и добавить профиль в управление сетью.</div><div class="modal-actions"><button onclick="closeInstallModal();refreshMonitor()">Проверить мониторинг</button><button onclick="closeInstallModal();saveProfile().then(()=>enterAdmin())">Добавить в управление</button></div>`)}
function renderInstallPlan(){
  const root=document.getElementById('installPlan');if(!root)return;
  const plan=installPlan;const checksByFile={};preflightResults.forEach(r=>checksByFile[r.file]=r);
  if(!plan){root.innerHTML='<div class="empty">План еще не загружен. Сгенерируйте bootstrap или нажмите “Обновить план”.</div>';return}
  root.innerHTML=(plan.steps||[]).map(step=>{
    const pf=checksByFile[step.file];const blocked=(step.blockers||[]).length>0;
    const running=runningFileSet().has(step.file);
    const status=blocked?'bad':(pf?(pf.ok?'ok':'bad'):(step.generated?'warn':'bad'));
    const checks=pf?installCheckHtml(pf.checks||[]):'';
    const trust=pf&&pf.hostKeyError&&pf.hostKeyCandidate?`<div class="panel" style="margin-top:10px"><b>Новый SSH host key</b><div class="muted">После переустановки ОС fingerprint сервера меняется. Подтвердите его, если это точно ваш VPS.</div><pre>${escapeHtml(pf.hostKeyCandidate)}</pre><button onclick="trustHostKey('${escapeHtml(step.host)}','${escapeHtml(pf.hostKeyCandidate)}','${escapeHtml(step.file)}')">Доверять этому ключу</button></div>`:'';
    const notes=[...(step.blockers||[]).map(x=>'Блокер: '+x),...(step.warnings||[])].map(x=>`<div class="muted">${escapeHtml(x)}</div>`).join('');
    return `<div class="install-plan-card ${running?'warn':status}"><div class="actions" style="justify-content:space-between"><div><b>${step.order}. ${escapeHtml(step.server)} · ${escapeHtml(step.role)}</b><div class="muted">${escapeHtml(step.host||'host не указан')} · ${escapeHtml(step.file)}</div></div><span class="badge ${running?'warn':status}">${running?'установка идет':(blocked?'блокер':(pf?(pf.ok?'проверено':'есть проблема'):(step.generated?'ждет проверки':'нет файла')))}</span></div><div style="margin-top:10px">${notes}</div>${checks?`<div style="margin-top:10px">${checks}</div>`:''}${trust}<div class="actions" style="margin-top:12px"><button class="btn-check" ${running?'disabled':''} onclick="preflightBootstrapFile('${escapeHtml(step.file)}')">Проверить сервер</button><button class="btn-run danger" ${blocked||!step.generated||pf?.hostKeyError||running?'disabled':''} onclick="runBootstrapFile('${escapeHtml(step.file)}')">${running?'Выполняется...':'Запустить этот сервер'}</button></div></div>`
  }).join('')||'<div class="empty">В плане нет серверов.</div>'
}
async function refreshInstallPlan(){try{installPlan=await api('/api/bootstrap/plan',{});renderInstallPlan();toast('План установки обновлен')}catch(e){alert('Не удалось получить план:\\n'+e.message)}}
async function preflightAllBootstrap(){toast('Проверяю все серверы...');try{const r=await api('/api/bootstrap/preflight-all',{});installPlan=r.plan;preflightResults=r.results||[];renderInstallPlan();toast(r.ok?'Все проверки пройдены':'Есть проблемы preflight')}catch(e){alert('Preflight не запустился:\\n'+e.message)}}
function installQueueFiles(){const steps=(installPlan?.steps||[]).filter(s=>!(s.blockers||[]).length&&s.generated);const ok=new Set(preflightResults.filter(r=>r.ok).map(r=>r.file));return steps.filter(s=>ok.has(s.file)).map(s=>s.file)}
async function waitForJobDone(id){return new Promise(resolve=>{const tick=()=>{const j=activeJobs[id];if(j&&j.status&&j.status!=='running')resolve(j);else setTimeout(tick,1500)};tick()})}
async function runAllBootstrap(){if(!installPlan)await refreshInstallPlan();const files=installQueueFiles();if(!files.length){alert('Нет серверов, которые можно безопасно запустить. Сначала сгенерируйте bootstrap и пройдите preflight.');return}if(!confirm('Запустить установку по очереди для '+files.length+' сервер(ов)? Сначала ingress, затем exit. Это изменит VPS.'))return;showTab('render');let allOk=true;for(const file of files){const job=await runBootstrapFile(file,false);if(!job){allOk=false;break}const done=await waitForJobDone(job.id);if(done.status!=='completed'){allOk=false;showInstallError(done);break}}if(allOk)showNetworkReadyModal()}
function renderGenerated(){const files=state.generatedFiles||[];document.getElementById('generatedFiles').innerHTML=files.length?files.map(f=>`<div class="build-file-card" style="margin-bottom:12px"><div class="file-row"><b>${escapeHtml(f.name)}</b><span>${f.size} B</span><span class="badge ${f.hasMissingSecrets?'bad':'ok'}">${f.hasMissingSecrets?'есть пропущенные секреты':'готов'}</span></div><details style="margin-top:10px"><summary>Показать скрипт</summary><pre style="margin-top:10px">${escapeHtml(f.preview)}</pre></details></div>`).join(''):'<div class="empty">Скрипты еще не сгенерированы.</div>'}
function collectSecrets(){const out={ssh:{serverPasswords:{}},wireguard:{ingress:{},exits:{}},telegram:{}};setupServers.forEach(s=>{if(s.password){out.ssh.serverPasswords[s.name]=s.password;out.ssh.serverPasswords[s.host]=s.password}});document.querySelectorAll('[data-secret]').forEach(input=>{if(!input.value.trim())return;const parts=input.dataset.secret.split('.');let o=out;parts.slice(0,-1).forEach(k=>{o[k] ||= {}; o=o[k]});o[parts.at(-1)]=input.value.trim()});return out}
async function saveAll(){applySetupServers();await api('/api/save',{manifest:state.manifest,secrets:collectSecrets()});document.querySelectorAll('[data-secret]').forEach(i=>i.value='');await loadState();toast('Сохранено')}
async function saveProfile(){applySetupServers();if(!state.manifest.ingress.host.trim()){alert('Укажите SSH host/IP входного VPS. Для минимального профиля достаточно одного входного VPS.');return}const result=await api('/api/profile/save',{manifest:state.manifest,secrets:collectSecrets()});state.manifest=result.manifest;state.profiles=result.profiles;document.querySelectorAll('[data-secret]').forEach(i=>i.value='');await loadState();toast('Профиль сети сохранен')}
async function renderScripts(){await saveAll();const r=await api('/api/render',{});await loadState();if(!r.ok){toast('Ошибка сборки');alert((r.stderr||r.stdout||'Ошибка').slice(0,2000));return}const missing=(state.generatedFiles||[]).filter(f=>f.hasMissingSecrets).map(f=>f.name);if(missing.length){toast('Скрипты собраны с пропущенными секретами');alert('Скрипты созданы для просмотра, но применять их нельзя: есть пропущенные VPN-секреты (__MISSING_*). Заполните VPN-ключи и сгенерируйте заново. Файлы: '+missing.join(', '));return}toast('Скрипты собраны и готовы к проверке')}
async function renderBootstrap(){applySetupServers();await saveProfile();const r=await api('/api/bootstrap/render',{manifest:state.manifest});await loadState();showTab('render');await refreshInstallPlan();toast('Bootstrap-скрипты собраны: '+(r.files||[]).join(', '))}
async function preflightBootstrapFile(file){toast('Проверяю '+file+'...');try{const r=await api('/api/bootstrap/preflight',{file});preflightResults=preflightResults.filter(x=>x.file!==file);preflightResults.push({file,...r});renderInstallPlan();toast(r.ok?'Preflight пройден':'Preflight с проблемами')}catch(e){preflightResults=preflightResults.filter(x=>x.file!==file);preflightResults.push({file,ok:false,checks:[{name:'Preflight',status:'bad',detail:e.message}]});renderInstallPlan();alert('Preflight не прошел для '+file+':\\n'+e.message)}}
async function trustHostKey(host,hostKey,file){if(!confirm('Сохранить SSH host key для '+host+'? Делайте это только если сервер был переустановлен вами.'))return;try{await api('/api/ssh/trust-host-key',{host,hostKey});toast('Host key сохранен');await preflightBootstrapFile(file)}catch(e){alert('Не удалось сохранить host key:\\n'+e.message)}}
function renderJobs(){const root=document.getElementById('jobProgress');if(!root)return;const jobs=Object.values(activeJobs);root.innerHTML=jobs.length?jobs.map(j=>{const info=stageInfo(j.stage);const pct=j.status==='completed'?100:(j.status==='failed'?100:info.pct);const cls=j.status==='completed'?'completed':(j.status==='failed'?'failed':'running');const setup=j.status==='completed'&&['configure-wg-easy','connect-existing-wg-easy'].includes(j.nextAction)?`<div class="notice"><b>${j.nextAction==='connect-existing-wg-easy'?'Существующий wg-easy сохранен':'Нужно действие в браузере'}</b><div class="muted">${j.nextAction==='connect-existing-wg-easy'?'Клиентские профили не менялись. Откройте инструкцию по подключению к сети.':'Откройте wg-easy и завершите первичную настройку.'}</div><div class="actions" style="margin-top:10px"><button onclick="showPostInstallNotice(activeJobs['${escapeHtml(j.id)}'])">Открыть инструкцию</button></div></div>`:'';return `<div class="panel install-card ${cls}"><div class="actions" style="justify-content:space-between"><div><b>${escapeHtml(j.file||'-')}</b><div class="muted">${escapeHtml(j.server||j.host||'')} · ${escapeHtml(j.status||'')} · ${escapeHtml(info.label)}</div></div><span class="badge ${j.status==='completed'?'ok':(j.status==='failed'?'bad':'warn')}">${j.status==='running'?'идет установка':escapeHtml(j.status||'running')}</span></div><div class="progress"><i style="width:${pct}%"></i></div>${setup}${formatLogLines(j.lines||[],j.error||'')}</div>`}).join(''):'<div class="empty">Установки еще не запускались.</div>';renderInstallPlan()}
async function pollJob(id){try{const r=await api('/api/job',{id});const before=activeJobs[id]?.status;activeJobs[id]=r.job;renderJobs();if(r.job.status==='running')setTimeout(()=>pollJob(id),1200);else{toast(r.job.status==='completed'?'Установка завершена':'Установка завершилась ошибкой');if(before==='running'&&r.job.status==='completed')showPostInstallNotice(r.job);if(before==='running'&&r.job.status==='failed')showInstallError(r.job)}}catch(e){activeJobs[id]={id,status:'failed',error:e.message,lines:[]};renderJobs();showInstallError(activeJobs[id])}}
async function runBootstrapFile(file,confirmRun=true){if(confirmRun&&!confirm('Запустить '+file+' на VPS? Это установит/изменит Docker, wg-easy, Hysteria и systemd-сервисы на выбранном сервере.'))return null;if(runningFileSet().has(file)){toast('Этот сервер уже устанавливается');return null}toast('Запускаю '+file+'...');showTab('render');try{const r=await api('/api/bootstrap/run',{file});activeJobs[r.job.id]=r.job;renderJobs();pollJob(r.job.id);return r.job}catch(e){const job={file,status:'failed',error:e.message,lines:[]};showInstallError(job);return null}}
const terminalSets=[
['> IGNA v2.4.7','> Secure shell initialized','> Loading network profile cache...','> Vault status: empty','> Route planner online','> WireGuard module: ready','> Hysteria module: ready','> Bootstrap runner armed','> nftables planner: idle','> password vault: local-only','> telemetry: disabled','> operator initials: IG','> Фонд Свободного интернета имени ИИгоря','> no vendor lock-in detected','> _'],
['> import ig.network as freedom','> const fund = "Фонд Свободного интернета имени ИИгоря"','> await fund.support("open-routes")','> ig.sign(packet)','> routes.filter(x => x.free)','> wg.peers.sync({owner:"IG"})','> hysteria.mode = "fast-and-clear"','> ssh.keychain.unlock("local-only")','> bootstrap.plan.validate()','> exits.balance({fair:true})','> reserves.standby()','> return internet.withoutBorders()','> _'],
['> namespace IG.FreeInternet','> class NetworkAdmin extends Operator','> def create_network(vps, protocols):','>   ingress = choose(vps, role="entry")','>   exits = choose(vps, role="exit")','>   fund = "имени ИИгоря"','>   wireguard.enable()','>   hysteria.enable()','>   monitoring.attach(ingress)','>   install.safe_mode = True','>   no_dark_patterns = True','>   ship(product=True)','> _']
];
let terminalSetIndex=0;
function startTerminalStream(){const root=document.getElementById('terminalStream');if(!root)return;let token=0;async function typeSet(lines){const local=++token;root.innerHTML='';for(const line of lines){if(local!==token)return;const row=document.createElement('span');root.appendChild(row);for(let i=0;i<=line.length;i++){if(local!==token)return;row.textContent=line.slice(0,i);await new Promise(r=>setTimeout(r,14));}}}async function cycle(){await typeSet(terminalSets[terminalSetIndex%terminalSets.length]);terminalSetIndex++;setTimeout(cycle,6500)}cycle()}
loadState().catch(e=>alert(e.message));
startTerminalStream();
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        return

    def send_bytes(self, status, body, content_type):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status=200):
        self.send_bytes(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def read_body(self):
        length = int(self.headers.get("content-length", "0") or "0")
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_bytes(200, html_page().encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/state":
            manifest = load_manifest()
            profiles = load_profiles()
            if not profiles:
                manifest.setdefault("admin", {})["configured"] = False
            secrets = load_secrets()
            self.send_json({
                "manifest": manifest,
                "profiles": profiles,
                "secretStatus": secret_status(secrets, manifest),
                "generatedFiles": generated_files(),
                "connection": {
                    "ingressKeyPath": secrets.get("ssh", {}).get("ingressKeyPath", ""),
                    "serverPasswords": secrets.get("ssh", {}).get("serverPasswords", {}),
                },
                "paths": {
                    "manifest": str(MANIFEST_PATH),
                    "secrets": str(SECRETS_PATH),
                    "outputDir": str(OUTPUT_DIR),
                },
            })
            return
        if path == "/api/jobs":
            self.send_json({"ok": True, "jobs": list_jobs()})
            return
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_body()
            if path == "/api/save":
                manifest = normalize_manifest(body.get("manifest") or default_manifest())
                secrets = merge_secret_values(load_secrets(), body.get("secrets") or {})
                write_json(MANIFEST_PATH, manifest)
                write_json(SECRETS_PATH, secrets)
                self.send_json({"ok": True})
                return
            if path == "/api/discover/ingress":
                host = str(body.get("host", "")).strip()
                ssh_user = str(body.get("sshUser", "root")).strip() or "root"
                key_path = str(body.get("keyPath", "")).strip()
                password = str(body.get("password", ""))
                discovery = discover_ingress(host, ssh_user, key_path, password)
                manifest = normalize_manifest(default_manifest())
                manifest["profileName"] = discovery.get("hostname") or host
                manifest["ingress"]["name"] = discovery.get("hostname") or "primary-ingress"
                manifest["ingress"]["host"] = host
                manifest["ingress"]["sshUser"] = ssh_user
                manifest["ingress"]["publicIp"] = discovery.get("publicIp") or host
                manifest["ingress"]["publicInterface"] = discovery.get("publicInterface") or "eth0"
                manifest["ingress"]["domain"] = discovery.get("domain") or ""
                services = discovery.get("services", {})
                manifest["protocols"]["clientPortal"] = services.get("client-portal.service") == "active"
                manifest["protocols"]["monitoring"] = services.get("cascade-monitor.service") == "active"
                manifest["protocols"]["hysteria"] = services.get("hysteria-server.service") == "active"
                manifest["protocols"]["wireguard"] = bool(discovery.get("wgEasy")) or services.get("docker.service") == "active"
                manifest["admin"]["configured"] = True
                secret_patch = {"ssh": {}}
                if key_path:
                    secret_patch["ssh"]["ingressKeyPath"] = key_path
                if password:
                    secret_patch["ssh"]["serverPasswords"] = {
                        manifest["ingress"]["name"]: password,
                        host: password,
                    }
                secrets = merge_secret_values(load_secrets(), secret_patch)
                profile = save_network_profile(manifest)
                write_json(MANIFEST_PATH, manifest)
                write_json(SECRETS_PATH, secrets)
                self.send_json({"ok": True, "discovery": discovery, "profile": profile, "profiles": load_profiles(), "manifest": manifest})
                return
            if path == "/api/monitor/ingress":
                host = str(body.get("host", "")).strip()
                ssh_user = str(body.get("sshUser", "root")).strip() or "root"
                key_path = str(body.get("keyPath", "")).strip()
                password = str(body.get("password", ""))
                monitor = fetch_ingress_monitor(host, ssh_user, key_path, password)
                self.send_json({"ok": True, **monitor})
                return
            if path == "/api/monitor/sync":
                result = sync_manifest_from_monitor(body)
                self.send_json(result)
                return
            if path == "/api/profile/save":
                manifest = normalize_manifest(body.get("manifest") or default_manifest())
                secrets = merge_secret_values(load_secrets(), body.get("secrets") or {})
                profile = save_network_profile(manifest)
                manifest["admin"]["configured"] = True
                write_json(MANIFEST_PATH, manifest)
                write_json(SECRETS_PATH, secrets)
                self.send_json({"ok": True, "profile": profile, "profiles": load_profiles(), "manifest": manifest})
                return
            if path == "/api/profile/load":
                manifest = load_network_profile(str(body.get("id", "")))
                if not manifest:
                    self.send_json({"error": "profile not found"}, 404)
                    return
                self.send_json({"ok": True, "profiles": load_profiles(), "manifest": manifest})
                return
            if path == "/api/render":
                result = run_render()
                self.send_json(result, 200 if result["ok"] else 500)
                return
            if path == "/api/bootstrap/render":
                manifest = normalize_manifest(body.get("manifest") or load_manifest())
                files = render_bootstrap_files(manifest)
                write_json(MANIFEST_PATH, manifest)
                self.send_json({"ok": True, "files": files})
                return
            if path == "/api/bootstrap/plan":
                self.send_json(installation_plan())
                return
            if path == "/api/bootstrap/preflight-all":
                result = preflight_all_bootstrap()
                self.send_json(result)
                return
            if path == "/api/bootstrap/run":
                result = start_bootstrap_file(str(body.get("file", "")))
                self.send_json({"ok": True, "job": result})
                return
            if path == "/api/bootstrap/preflight":
                debug_log(f"http preflight request file={body.get('file', '')}")
                result = preflight_bootstrap_file(str(body.get("file", "")))
                debug_log(f"http preflight response file={body.get('file', '')} ok={result.get('ok')}")
                self.send_json(result)
                return
            if path == "/api/ssh/trust-host-key":
                host = str(body.get("host", "")).strip()
                host_key = str(body.get("hostKey", "")).strip()
                if not host or not host_key.startswith("SHA256:"):
                    self.send_json({"error": "host and SHA256 hostKey are required"}, 400)
                    return
                secrets = load_secrets()
                secrets.setdefault("ssh", {}).setdefault("hostKeys", {})[host] = host_key
                write_json(SECRETS_PATH, secrets)
                self.send_json({"ok": True, "host": host, "hostKey": host_key})
                return
            if path == "/api/job":
                job = get_job(str(body.get("id", "")))
                if not job:
                    self.send_json({"error": "job not found"}, 404)
                    return
                self.send_json({"ok": True, "job": job})
                return
            self.send_json({"error": "not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)


def main():
    host = "127.0.0.1"
    port = int(os.environ.get("VPN_MANAGER_PORT", "8765"))
    print(f"VPN Manager: http://{host}:{port}/", flush=True)
    debug_log(f"main serve start {host}:{port}")
    try:
        ThreadingHTTPServer((host, port), Handler).serve_forever()
    except BaseException as exc:
        debug_log(f"main serve exception {type(exc).__name__}: {exc}")
        raise
    finally:
        debug_log("main serve stopped")


if __name__ == "__main__":
    main()











