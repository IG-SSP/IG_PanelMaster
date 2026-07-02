#!/usr/bin/env python3
import html
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

WG_DB = "/var/lib/docker/volumes/wg-easy_etc_wireguard/_data/wg-easy.db"
PORTAL_DB = "/opt/client-portal/portal.db"
HOST = "space.indiangolf.ru"
WG_PORT = 51820
PUBLIC_PREFIX = os.environ.get("PUBLIC_PREFIX", "/portal").rstrip("/")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "")
ADMIN_IDS = {int(x) for x in os.environ.get("ADMIN_TELEGRAM_IDS", "").replace(",", " ").split() if x.isdigit()}
SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "30"))
SESSION_TTL = SESSION_DAYS * 86400
MAX_PROFILES_PER_USERNAME = 25
HAPP_SOURCE_RAW_URL = os.environ.get(
    "HAPP_SOURCE_RAW_URL",
    "https://space.indiangolf.ru/happ/196dcc3a9c8a39daed715389e5686baab9b5",
)
HAPP_SOURCE_B64_URL = os.environ.get(
    "HAPP_SOURCE_B64_URL",
    "https://space.indiangolf.ru/happ/196dcc3a9c8a39daed715389e5686baab9b5.b64",
)


def run(cmd, input_text=None, timeout=10):
    return subprocess.run(cmd, input=input_text, text=True, capture_output=True, timeout=timeout)


def wg_keygen():
    private = run(["wg", "genkey"]).stdout.strip()
    public = run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
    return private, public


def wg_psk():
    return run(["wg", "genpsk"]).stdout.strip()


def norm_username(value):
    value = (value or "").strip()
    if value.startswith("@"):
        value = value[1:]
    if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", value):
        return ""
    return value.lower()


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def public_url(path, params=None):
    if not path.startswith("/"):
        path = "/" + path
    url = (PUBLIC_PREFIX + path) if PUBLIC_PREFIX else path
    if params:
        url += "?" + urlencode(params)
    return url


def abs_public_url(path, params=None):
    return f"https://{HOST}{public_url(path, params)}"


def telegram_api(method, payload=None, timeout=12):
    if not BOT_TOKEN:
        return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["content-type"] = "application/json"
    req = Request(url, data=data, headers=headers, method="POST" if payload is not None else "GET")
    with urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode())


def verify_telegram_login(params):
    if not BOT_TOKEN:
        return None
    data = {k: v[0] for k, v in params.items() if v}
    supplied_hash = data.pop("hash", "")
    if not supplied_hash:
        return None
    auth_date = int(data.get("auth_date", "0") or "0")
    if abs(int(time.time()) - auth_date) > 86400:
        return None
    check_string = "\n".join(f"{k}={data[k]}" for k in sorted(data))
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    digest = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, supplied_hash):
        return None
    username = norm_username(data.get("username", ""))
    if not username:
        return None
    return {
        "telegram_id": int(data["id"]),
        "username": username,
        "first_name": data.get("first_name", ""),
    }


def verify_webapp_init_data(init_data):
    if not BOT_TOKEN or not init_data:
        return None
    parsed = parse_qs(init_data, strict_parsing=False)
    data = {k: v[0] for k, v in parsed.items() if v}
    supplied_hash = data.pop("hash", "")
    if not supplied_hash:
        return None
    auth_date = int(data.get("auth_date", "0") or "0")
    if abs(int(time.time()) - auth_date) > 86400:
        return None
    check_string = "\n".join(f"{k}={data[k]}" for k in sorted(data))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, supplied_hash):
        return None
    try:
        user = json.loads(data.get("user", "{}"))
    except json.JSONDecodeError:
        return None
    username = norm_username(user.get("username", ""))
    return {
        "telegram_id": int(user["id"]),
        "username": username,
        "first_name": user.get("first_name", ""),
    }


def create_session(identity):
    sid = secrets.token_urlsafe(32)
    role = "admin" if identity["telegram_id"] in ADMIN_IDS else "user"
    expires_at = int(time.time()) + SESSION_TTL
    username_verified = 1 if identity.get("username_verified", True) else 0
    with portal_db() as db:
        db.execute(
            "insert into sessions(sid,telegram_id,username,first_name,role,expires_at,created_at,username_verified) values(?,?,?,?,?,?,?,?)",
            (sid, identity["telegram_id"], identity["username"], identity.get("first_name", ""), role, expires_at, now(), username_verified),
        )
    return sid


def get_session(sid):
    if not sid:
        return None
    with portal_db() as db:
        row = db.execute("select * from sessions where sid=? and expires_at>?", (sid, int(time.time()))).fetchone()
        return row


def update_session_username(sid, username, username_verified):
    username = norm_username(username)
    if not sid or not username:
        return False
    with portal_db() as db:
        db.execute(
            "update sessions set username=?, username_verified=? where sid=?",
            (username, 1 if username_verified else 0, sid),
        )
    return True


def delete_session(sid):
    if sid:
        with portal_db() as db:
            db.execute("delete from sessions where sid=?", (sid,))


def create_login_nonce():
    nonce = secrets.token_urlsafe(18)
    with portal_db() as db:
        db.execute(
            "insert into login_nonces(nonce,expires_at,created_at) values(?,?,?)",
            (nonce, int(time.time()) + 600, now()),
        )
    return nonce


def get_login_nonce(nonce):
    if not nonce:
        return None
    with portal_db() as db:
        return db.execute(
            "select * from login_nonces where nonce=? and expires_at>?",
            (nonce, int(time.time())),
        ).fetchone()


def complete_login_nonce(nonce, telegram_id, username, first_name):
    username = norm_username(username)
    if not username:
        return False
    with portal_db() as db:
        row = db.execute(
            "select nonce from login_nonces where nonce=? and status='pending' and expires_at>?",
            (nonce, int(time.time())),
        ).fetchone()
        if not row:
            return False
        db.execute(
            "update login_nonces set telegram_id=?, username=?, first_name=?, status='confirmed' where nonce=?",
            (telegram_id, username, first_name or "", nonce),
        )
    return True


def get_state(key, default="0"):
    with portal_db() as db:
        row = db.execute("select value from app_state where key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_state(key, value):
    with portal_db() as db:
        db.execute(
            "insert into app_state(key,value) values(?,?) on conflict(key) do update set value=excluded.value",
            (key, str(value)),
        )


def init_db():
    os.makedirs(os.path.dirname(PORTAL_DB), exist_ok=True)
    with sqlite3.connect(PORTAL_DB) as db:
        db.execute(
            """
            create table if not exists telegram_users (
              username text primary key,
              telegram_id integer,
              max_profiles integer not null,
              note text default '',
              created_at text not null,
              updated_at text not null
            )
            """
        )
        db.execute(
            """
            create table if not exists issued_profiles (
              id integer primary key autoincrement,
              username text not null,
              wg_client_id integer not null unique,
              name text not null,
              created_at text not null,
              foreign key(username) references telegram_users(username)
            )
            """
        )
        db.execute(
            """
            create table if not exists sessions (
              sid text primary key,
              telegram_id integer not null,
              username text not null,
              first_name text default '',
              role text not null,
              expires_at integer not null,
              created_at text not null,
              username_verified integer not null default 1
            )
            """
        )
        db.execute(
            """
            create table if not exists pending_requests (
              id integer primary key autoincrement,
              telegram_id integer not null,
              username text not null,
              first_name text default '',
              requested_profiles integer not null,
              status text not null default 'pending',
              admin_message_id integer,
              created_at text not null,
              updated_at text not null
            )
            """
        )
        columns = {row[1] for row in db.execute("pragma table_info(telegram_users)").fetchall()}
        if "telegram_id" not in columns:
            db.execute("alter table telegram_users add column telegram_id integer")
        columns = {row[1] for row in db.execute("pragma table_info(sessions)").fetchall()}
        if "username_verified" not in columns:
            db.execute("alter table sessions add column username_verified integer not null default 1")
        columns = {row[1] for row in db.execute("pragma table_info(issued_profiles)").fetchall()}
        if "happ_token" not in columns:
            db.execute("alter table issued_profiles add column happ_token text")
        db.execute(
            """
            create table if not exists app_state (
              key text primary key,
              value text not null
            )
            """
        )
        db.execute(
            """
            create table if not exists login_nonces (
              nonce text primary key,
              telegram_id integer,
              username text,
              first_name text default '',
              status text not null default 'pending',
              expires_at integer not null,
              created_at text not null
            )
            """
        )


def portal_db():
    db = sqlite3.connect(PORTAL_DB)
    db.row_factory = sqlite3.Row
    return db


def wg_db():
    db = sqlite3.connect(WG_DB)
    db.row_factory = sqlite3.Row
    return db


def get_user(username):
    with portal_db() as db:
        return db.execute("select * from telegram_users where username=?", (username,)).fetchone()


def get_user_for_session(session):
    username = session["username"]
    with portal_db() as db:
        if int(session["username_verified"] or 0):
            return db.execute("select * from telegram_users where username=?", (username,)).fetchone()
        if int(session["telegram_id"] or 0) == 0:
            return db.execute(
                "select * from telegram_users where username=? and telegram_id is null",
                (username,),
            ).fetchone()
        return db.execute(
            "select * from telegram_users where username=? and telegram_id=?",
            (username, session["telegram_id"]),
        ).fetchone()


def issued_count(username):
    with portal_db() as db:
        return db.execute("select count(*) from issued_profiles where username=?", (username,)).fetchone()[0]


def list_users():
    with portal_db() as db:
        return db.execute(
            """
            select u.username, u.max_profiles, u.note, u.updated_at,
                   count(p.id) as issued
            from telegram_users u
            left join issued_profiles p on p.username = u.username
            group by u.username
            order by u.username
            """
        ).fetchall()


def get_pending_request(telegram_id):
    with portal_db() as db:
        return db.execute(
            "select * from pending_requests where telegram_id=? and status='pending' order by id desc limit 1",
            (telegram_id,),
        ).fetchone()


def get_pending_request_for_identity(identity):
    telegram_id = int(identity.get("telegram_id") or 0)
    username = identity.get("username", "")
    with portal_db() as db:
        if telegram_id:
            return db.execute(
                "select * from pending_requests where telegram_id=? and status='pending' order by id desc limit 1",
                (telegram_id,),
            ).fetchone()
        return db.execute(
            "select * from pending_requests where telegram_id=0 and username=? and status='pending' order by id desc limit 1",
            (username,),
        ).fetchone()


def create_pending_request(identity, requested_profiles):
    requested_profiles = max(1, min(int(requested_profiles or 1), MAX_PROFILES_PER_USERNAME))
    telegram_id = int(identity.get("telegram_id") or 0)
    with portal_db() as db:
        if telegram_id:
            existing = db.execute(
                "select * from pending_requests where telegram_id=? and status='pending' order by id desc limit 1",
                (telegram_id,),
            ).fetchone()
        else:
            existing = db.execute(
                "select * from pending_requests where telegram_id=0 and username=? and status='pending' order by id desc limit 1",
                (identity["username"],),
            ).fetchone()
        if existing:
            db.execute(
                "update pending_requests set username=?, first_name=?, requested_profiles=?, updated_at=? where id=?",
                (identity["username"], identity.get("first_name", ""), requested_profiles, now(), existing["id"]),
            )
            request_id = existing["id"]
        else:
            db.execute(
                """
                insert into pending_requests(telegram_id,username,first_name,requested_profiles,status,created_at,updated_at)
                values(?,?,?,?, 'pending', ?, ?)
                """,
                (telegram_id, identity["username"], identity.get("first_name", ""), requested_profiles, now(), now()),
            )
            request_id = db.execute("select last_insert_rowid()").fetchone()[0]
    notify_admin_request(request_id)
    return request_id


def list_pending_requests():
    with portal_db() as db:
        return db.execute("select * from pending_requests order by id desc limit 50").fetchall()


def delete_pending_request(request_id):
    with portal_db() as db:
        row = db.execute("select * from pending_requests where id=?", (request_id,)).fetchone()
        if not row:
            return None
        db.execute("delete from pending_requests where id=?", (request_id,))
        return row


def update_user_limit(username, max_profiles):
    username = norm_username(username)
    max_profiles = max(0, min(int(max_profiles or 0), MAX_PROFILES_PER_USERNAME))
    if not username:
        return False
    with portal_db() as db:
        row = db.execute("select username from telegram_users where username=?", (username,)).fetchone()
        if not row:
            return False
        db.execute(
            "update telegram_users set max_profiles=?, updated_at=? where username=?",
            (max_profiles, now(), username),
        )
    return True


def list_profiles(username=None):
    sql = """
      select p.*, c.ipv4_address, c.ipv6_address, c.enabled
      from issued_profiles p
      join clients_table c on c.id = p.wg_client_id
    """
    args = ()
    if username:
        sql += " where p.username=?"
        args = (username,)
    sql += " order by p.id desc"
    with portal_db() as pdb, wg_db() as wdb:
        pdb_rows = pdb.execute("select * from issued_profiles" + (" where username=?" if username else "") + " order by id desc", args).fetchall()
        result = []
        for row in pdb_rows:
            c = wdb.execute("select id,name,ipv4_address,ipv6_address,enabled from clients_table where id=?", (row["wg_client_id"],)).fetchone()
            item = dict(row)
            if c:
                item.update({"ipv4_address": c["ipv4_address"], "ipv6_address": c["ipv6_address"], "enabled": c["enabled"]})
            result.append(item)
        return result


def portal_stats():
    with portal_db() as db:
        return {
            "users": db.execute("select count(*) from telegram_users").fetchone()[0],
            "pending": db.execute("select count(*) from pending_requests where status='pending'").fetchone()[0],
            "requests": db.execute("select count(*) from pending_requests").fetchone()[0],
            "issued": db.execute("select count(*) from issued_profiles").fetchone()[0],
        }


def ensure_profile_happ_token(profile_id):
    with portal_db() as db:
        row = db.execute("select happ_token from issued_profiles where id=?", (profile_id,)).fetchone()
        if not row:
            return ""
        if row["happ_token"]:
            return row["happ_token"]
        token = secrets.token_urlsafe(24)
        db.execute("update issued_profiles set happ_token=? where id=?", (token, profile_id))
        return token


def get_profile_by_happ_token(token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,80}", token or ""):
        return None
    with portal_db() as db:
        return db.execute("select * from issued_profiles where happ_token=?", (token,)).fetchone()


def request_keyboard(request_id, requested):
    choices = [requested, 1, 2, 3, 5]
    unique = []
    for value in choices:
        if value not in unique and 1 <= value <= 10:
            unique.append(value)
    buttons = [[{"text": f"Выдать {value}", "callback_data": f"approve:{request_id}:{value}"}] for value in unique]
    buttons.append([{"text": "Отказать", "callback_data": f"deny:{request_id}:0"}])
    return {"inline_keyboard": buttons}


def notify_admin_request(request_id):
    if not ADMIN_IDS or not BOT_TOKEN:
        return
    with portal_db() as db:
        req = db.execute("select * from pending_requests where id=?", (request_id,)).fetchone()
    if not req:
        return
    text = (
        "Запрос доступа к VPN\n"
        f"Username: @{req['username']}\n"
        f"Источник: {'браузерный портал' if int(req['telegram_id'] or 0) == 0 else 'Telegram'}\n"
        f"Telegram ID: {req['telegram_id'] or '-'}\n"
        f"Имя: {req['first_name'] or '-'}\n"
        f"Запрошено профилей: {req['requested_profiles']}"
    )
    for admin_id in ADMIN_IDS:
        try:
            result = telegram_api(
                "sendMessage",
                {
                    "chat_id": admin_id,
                    "text": text,
                    "reply_markup": request_keyboard(request_id, req["requested_profiles"]),
                },
            )
            message_id = result.get("result", {}).get("message_id") if result else None
            if message_id:
                with portal_db() as db:
                    db.execute("update pending_requests set admin_message_id=? where id=?", (message_id, request_id))
        except Exception:
            pass


def approve_request(request_id, max_profiles):
    max_profiles = max(1, min(int(max_profiles or 1), MAX_PROFILES_PER_USERNAME))
    with portal_db() as db:
        req = db.execute("select * from pending_requests where id=?", (request_id,)).fetchone()
        if not req or req["status"] != "pending":
            return None
        db.execute(
            """
            insert into telegram_users(username,telegram_id,max_profiles,note,created_at,updated_at)
            values(?,?,?,?,?,?)
            on conflict(username) do update set
              telegram_id=excluded.telegram_id,
              max_profiles=excluded.max_profiles,
              note=excluded.note,
              updated_at=excluded.updated_at
            """,
            (
                req["username"],
                req["telegram_id"] if int(req["telegram_id"] or 0) else None,
                max_profiles,
                f"approved by bot for {'browser request' if int(req['telegram_id'] or 0) == 0 else 'tg_id ' + str(req['telegram_id'])}",
                now(),
                now(),
            ),
        )
        db.execute("update pending_requests set status='approved', requested_profiles=?, updated_at=? where id=?", (max_profiles, now(), request_id))
        return req


def deny_request(request_id):
    with portal_db() as db:
        req = db.execute("select * from pending_requests where id=?", (request_id,)).fetchone()
        if not req or req["status"] != "pending":
            return None
        db.execute("update pending_requests set status='denied', updated_at=? where id=?", (now(), request_id))
        return req


def portal_inline_keyboard(url=None):
    buttons = [[{"text": "Открыть личный кабинет", "url": url or abs_public_url("/")}]]
    buttons.append([{"text": "Войти по username", "url": abs_public_url("/manual")}])
    return {"inline_keyboard": buttons}


def public_site_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "Открыть сайт VPN", "url": abs_public_url("/")}],
            [{"text": "Войти по username", "url": abs_public_url("/manual")}],
        ]
    }


def safe_next_path(value):
    if not value:
        return public_url("/")
    parsed = urlparse(value)
    path = parsed.path or "/"
    if parsed.scheme or parsed.netloc:
        return public_url("/")
    if path.startswith(public_url("/monitor")) or path.startswith("/monitor"):
        return "/monitor/"
    if path.startswith(public_url("/admin")):
        return public_url("/admin")
    if path.startswith(public_url("/")):
        return path
    return public_url("/")


def create_bot_login_url(sender, next_path=None):
    username = norm_username(sender.get("username", ""))
    if not username:
        return "", ""
    nonce = create_login_nonce()
    ok = complete_login_nonce(nonce, int(sender.get("id", 0)), username, sender.get("first_name", ""))
    if not ok:
        return "", username
    params = {"nonce": nonce}
    if next_path:
        params["next"] = safe_next_path(next_path)
    return abs_public_url("/login/check", params), username


def bot_command_parts(text):
    head, _, tail = (text or "").strip().partition(" ")
    command = head.split("@", 1)[0].lower()
    return command, tail.strip()


def bot_start_text(sender):
    username = norm_username(sender.get("username", ""))
    if username:
        return (
            "VPN выдаётся через сайт.\n\n"
            "Что нужно сделать:\n"
            "1. Откройте сайт по кнопке ниже.\n"
            "2. Введите Telegram username.\n"
            "3. Отправьте заявку на нужное число профилей.\n"
            "4. После одобрения здесь придёт кнопка входа в личный кабинет.\n\n"
            f"Ваш username для копирования: @{username}"
        )
    return (
        "VPN выдаётся через сайт.\n\n"
        "На сайте нужно будет ввести Telegram username, чтобы администратор понял, "
        "кому выдавать доступ. Сейчас у вашего Telegram-аккаунта username не виден.\n\n"
        "Задайте username в настройках Telegram, затем вернитесь сюда или откройте сайт "
        "и отправьте заявку вручную."
    )


def handle_bot_callback(callback):
    user = callback.get("from", {})
    if int(user.get("id", 0)) not in ADMIN_IDS:
        telegram_api("answerCallbackQuery", {"callback_query_id": callback["id"], "text": "Нет доступа", "show_alert": True})
        return
    data = callback.get("data", "")
    parts = data.split(":")
    if len(parts) != 3:
        return
    action, request_id, count = parts[0], int(parts[1]), int(parts[2])
    if action == "approve":
        req = approve_request(request_id, count)
        if req:
            telegram_api("answerCallbackQuery", {"callback_query_id": callback["id"], "text": f"Выдано: {count}"})
            telegram_api(
                "editMessageText",
                {
                    "chat_id": callback["message"]["chat"]["id"],
                    "message_id": callback["message"]["message_id"],
                    "text": f"Одобрено: @{req['username']}, лимит профилей {count}",
                },
            )
            if int(req["telegram_id"] or 0):
                login_url, _username = create_bot_login_url(
                    {
                        "id": req["telegram_id"],
                        "username": req["username"],
                        "first_name": req["first_name"] or "",
                    }
                )
                telegram_api(
                    "sendMessage",
                    {
                        "chat_id": req["telegram_id"],
                        "text": (
                            f"Доступ к VPN одобрен. Лимит профилей: {count}.\n\n"
                            "Откройте личный кабинет в браузере: там будут WireGuard QR, .conf, "
                            "инструкция для Amnezia и личная Happ-ссылка."
                        ),
                        "reply_markup": portal_inline_keyboard(login_url or abs_public_url("/")),
                    },
                )
        else:
            telegram_api("answerCallbackQuery", {"callback_query_id": callback["id"], "text": "Заявка уже обработана", "show_alert": True})
    elif action == "deny":
        req = deny_request(request_id)
        if req:
            telegram_api("answerCallbackQuery", {"callback_query_id": callback["id"], "text": "Отказано"})
            telegram_api(
                "editMessageText",
                {
                    "chat_id": callback["message"]["chat"]["id"],
                    "message_id": callback["message"]["message_id"],
                    "text": f"Отказано: @{req['username']}",
                },
            )
            if int(req["telegram_id"] or 0):
                telegram_api("sendMessage", {"chat_id": req["telegram_id"], "text": "Заявка на VPN отклонена."})
        else:
            telegram_api("answerCallbackQuery", {"callback_query_id": callback["id"], "text": "Заявка уже обработана", "show_alert": True})


def handle_bot_message(message):
    text = (message.get("text") or "").strip()
    chat_id = message.get("chat", {}).get("id")
    command, payload = bot_command_parts(text)
    sender = message.get("from", {})
    if command in ("/admin", "/monitor") and chat_id:
        if int(sender.get("id", 0)) not in ADMIN_IDS:
            telegram_api(
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": "Этот раздел доступен только администратору.",
                    "reply_markup": public_site_keyboard(),
                },
            )
            return
        target = "/monitor/" if command == "/monitor" else public_url("/admin")
        login_url, username = create_bot_login_url(sender, target)
        if not login_url:
            telegram_api(
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": "Для админского входа нужен Telegram username. Задайте username в настройках Telegram и повторите команду.",
                },
            )
            return
        title = "мониторинг" if command == "/monitor" else "админку"
        telegram_api(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": f"Вход для @{username} подтверждён. Откройте {title} по кнопке ниже.",
                "reply_markup": {
                    "inline_keyboard": [[{"text": f"Открыть {title}", "url": login_url}]]
                },
            },
        )
        return
    if command in ("/start", "/help") and chat_id and not payload.startswith("login_"):
        telegram_api(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": bot_start_text(message.get("from", {})),
                "reply_markup": public_site_keyboard(),
            },
        )
        return
    if command != "/start" or not payload.startswith("login_"):
        return
    nonce = payload.split("login_", 1)[1].split()[0].strip()
    username = norm_username(sender.get("username", ""))
    if not username:
        if chat_id:
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "Для входа нужен Telegram username. Задайте username в настройках Telegram и повторите вход."})
        return
    ok = complete_login_nonce(nonce, int(sender.get("id", 0)), username, sender.get("first_name", ""))
    if chat_id:
        if ok:
            telegram_api(
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": (
                        f"Вход подтвержден для @{username}.\n\n"
                        "Нажмите кнопку ниже, чтобы открыть личный кабинет в браузере."
                    ),
                    "reply_markup": portal_inline_keyboard(abs_public_url("/login/check", {"nonce": nonce})),
                },
            )
        else:
            telegram_api(
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": "Код входа устарел или уже использован. Откройте портал и попробуйте снова.",
                    "reply_markup": portal_inline_keyboard(abs_public_url("/")),
                },
            )


def bot_poll_loop():
    if not BOT_TOKEN:
        return
    offset = int(get_state("telegram_update_offset", "0") or "0")
    while True:
        try:
            result = telegram_api("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": ["callback_query", "message"]}, timeout=35)
            for update in result.get("result", []) if result else []:
                offset = max(offset, update["update_id"] + 1)
                if "callback_query" in update:
                    handle_bot_callback(update["callback_query"])
                if "message" in update:
                    handle_bot_message(update["message"])
            set_state("telegram_update_offset", offset)
        except Exception:
            time.sleep(5)


def setup_bot_menu():
    if not BOT_TOKEN:
        return
    try:
        telegram_api(
            "setMyCommands",
            {
                "commands": [
                    {"command": "start", "description": "Открыть сайт VPN и отправить заявку"},
                    {"command": "help", "description": "Как получить доступ к VPN"},
                    {"command": "monitor", "description": "Открыть мониторинг для администратора"},
                    {"command": "admin", "description": "Открыть админку для администратора"},
                ]
            },
        )
        telegram_api(
            "setChatMenuButton",
            {
                "menu_button": {
                    "type": "commands",
                }
            },
        )
    except Exception:
        pass


def next_client_number(db):
    rows = db.execute("select ipv4_address from clients_table").fetchall()
    used = set()
    for row in rows:
        m = re.fullmatch(r"10\.8\.0\.(\d+)", row["ipv4_address"])
        if m:
            used.add(int(m.group(1)))
    for n in range(2, 255):
        if n not in used:
            return n
    raise RuntimeError("No free IPv4 addresses in 10.8.0.0/24")


def sync_peer(public_key, pre_shared_key, ipv4, ipv6):
    allowed = f"{ipv4}/32,{ipv6}/128"
    cmd = [
        "docker",
        "exec",
        "-i",
        "wg-easy",
        "sh",
        "-c",
        'cat > /tmp/client.psk; wg set wg0 peer "$1" preshared-key /tmp/client.psk allowed-ips "$2"; rm -f /tmp/client.psk',
        "sh",
        public_key,
        allowed,
    ]
    p = run(cmd, input_text=pre_shared_key + "\n", timeout=10)
    if p.returncode != 0:
        raise RuntimeError(p.stderr or p.stdout or "wg set failed")


def create_profile(username, suffix):
    private_key, public_key = wg_keygen()
    psk = wg_psk()
    created = now()
    with wg_db() as db:
        iface = db.execute("select * from interfaces_table where name='wg0'").fetchone()
        cfg = db.execute("select * from user_configs_table where id='wg0'").fetchone()
        user_id = db.execute("select id from users_table order by id limit 1").fetchone()["id"]
        num = next_client_number(db)
        ipv4 = f"10.8.0.{num}"
        ipv6 = f"fdcc:ad94:bacf:61a4::cafe:{num:x}"
        name = f"TG_{username}_{suffix}"
        db.execute(
            """
            insert into clients_table (
              user_id, interface_id, name, ipv4_address, ipv6_address,
              pre_up, post_up, pre_down, post_down,
              private_key, public_key, pre_shared_key, expires_at,
              allowed_ips, server_allowed_ips, persistent_keepalive,
              mtu, dns, server_endpoint, enabled, created_at, updated_at,
              j_c, j_min, j_max, i1, i2, i3, i4, i5, firewall_ips
            ) values (?, 'wg0', ?, ?, ?, '', '', '', '', ?, ?, ?, null,
              null, '[]', ?, ?, null, '', 1, ?, ?, 7, 10, 1000, '', '', '', '', '', null)
            """,
            (
                user_id,
                name,
                ipv4,
                ipv6,
                private_key,
                public_key,
                psk,
                cfg["default_persistent_keepalive"],
                cfg["default_mtu"],
                created,
                created,
            ),
        )
        client_id = db.execute("select last_insert_rowid()").fetchone()[0]
        db.commit()
    sync_peer(public_key, psk, ipv4, ipv6)
    with portal_db() as pdb:
        pdb.execute(
            "insert into issued_profiles(username,wg_client_id,name,happ_token,created_at) values(?,?,?,?,?)",
            (username, client_id, name, secrets.token_urlsafe(24), created),
        )
    return client_id


def get_client(client_id):
    with wg_db() as db:
        client = db.execute("select * from clients_table where id=?", (client_id,)).fetchone()
        iface = db.execute("select * from interfaces_table where name=?", (client["interface_id"],)).fetchone() if client else None
        cfg = db.execute("select * from user_configs_table where id=?", (client["interface_id"],)).fetchone() if client else None
        return client, iface, cfg


def client_config(client_id):
    client, iface, cfg = get_client(client_id)
    if not client:
        return ""
    dns = "1.1.1.1, 2606:4700:4700::1111"
    endpoint = client["server_endpoint"] or f"{cfg['host']}:{cfg['port']}"
    allowed = "0.0.0.0/0, ::/0"
    keepalive = client["persistent_keepalive"]
    lines = [
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        f"Address = {client['ipv4_address']}/32, {client['ipv6_address']}/128",
        f"DNS = {dns}",
        f"MTU = {client['mtu']}",
        "",
        "[Peer]",
        f"PublicKey = {iface['public_key']}",
        f"PresharedKey = {client['pre_shared_key']}",
        f"AllowedIPs = {allowed}",
        f"Endpoint = {endpoint}",
    ]
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def qr_svg(text):
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        p = run(["qrencode", "-t", "SVG", "-r", path], timeout=10)
        if p.returncode != 0:
            return "<svg xmlns='http://www.w3.org/2000/svg'></svg>"
        return p.stdout
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def page(title, body):
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{color-scheme:dark}}body{{margin:0;background:#0d1012;color:#edf2f5;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}}body:before{{content:"";position:fixed;inset:0;background:radial-gradient(circle at 20% 0%,rgba(57,120,242,.18),transparent 32%),linear-gradient(180deg,#12181d 0%,#0d1012 48%,#0d1012 100%);pointer-events:none}}main{{position:relative;max-width:1080px;margin:0 auto;padding:32px}}h1{{margin:0 0 10px;font-size:34px;letter-spacing:0}}h2{{font-size:20px;margin:24px 0 10px}}h3{{font-size:16px;margin:16px 0 8px}}p{{line-height:1.55}}form,.card,table{{background:rgba(23,28,33,.92);border:1px solid #2b3742;border-radius:8px;padding:18px;box-shadow:0 14px 34px rgba(0,0,0,.22)}}.support{{background:rgba(20,38,31,.9);border-color:#315545;margin-bottom:16px}}.support b{{color:#a8f2c4}}.hero{{display:grid;grid-template-columns:1.35fr .85fr;gap:16px;align-items:stretch;margin-bottom:16px}}.status{{background:linear-gradient(135deg,rgba(20,30,40,.96),rgba(18,27,32,.96));border-color:#35506a}}.steps,.guide-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}}.step,.guide-card{{background:#11171d;border:1px solid #2b3742;border-radius:8px;padding:14px}}.step b,.guide-card b{{display:block;margin-bottom:6px;color:#f4f8fa}}.guide{{margin:18px 0}}.guide-card .num{{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;background:#3978f2;color:#fff;font-weight:700;margin-bottom:10px}}.pill{{display:inline-block;border-radius:999px;background:#223448;color:#b9d8ff;padding:5px 10px;font-size:13px}}.actions{{display:flex;flex-wrap:wrap;gap:10px;align-items:center}}label{{display:block;color:#bac5cd;margin:12px 0 6px}}input,textarea,select{{width:100%;box-sizing:border-box;border:1px solid #3b4955;border-radius:8px;background:#0d1216;color:#eef2f4;padding:12px;font:inherit}}button,.btn{{display:inline-block;border:0;border-radius:8px;background:#3978f2;color:white;padding:11px 15px;font:inherit;font-weight:650;text-decoration:none;cursor:pointer;margin-top:12px}}button:hover,.btn:hover{{filter:brightness(1.08)}}.btn.secondary{{background:#2b333b}}.btn.good{{background:#23845a}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}.profiles{{display:grid;grid-template-columns:1fr;gap:16px}}.profile{{display:grid;grid-template-columns:270px minmax(0,1fr);gap:18px}}.qr-box{{display:grid;place-items:center;background:#fff;border-radius:8px;padding:12px;margin:10px 0}}.profile img{{width:100%;max-width:230px}}.instructions{{margin:10px 0 0;padding-left:20px;color:#c7d0d7}}.instructions li{{margin:7px 0}}.copy{{word-break:break-all;background:#0d1216;border:1px solid #2d3943;border-radius:8px;padding:11px;color:#dbe7ee}}table{{width:100%;border-collapse:collapse;padding:0;overflow:hidden}}td,th{{padding:10px;border-bottom:1px solid #2a333c;text-align:left}}.muted{{color:#a5b0b8}}.ok{{color:#90e0ae}}.bad{{color:#ffaaa1}}svg{{max-width:230px;height:auto;background:white}}@media(max-width:860px){{main{{padding:18px}}h1{{font-size:29px}}.hero,.grid,.profile,.steps,.guide-grid{{grid-template-columns:1fr}}}}
.hero{{grid-template-columns:.78fr 1.22fr}}.hero .status{{min-height:210px;position:relative;overflow:hidden}}.hero .status:after{{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 0%,rgba(125,176,255,.08) 42%,transparent 64%);transform:translateX(-100%);animation:sheen 5s ease-in-out infinite;pointer-events:none}}.steps{{grid-template-columns:repeat(3,minmax(120px,1fr))}}.step{{min-height:126px}}.hero-visual{{display:grid;gap:12px}}.protocol-choice{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}}.protocol-option{{position:relative;display:block;background:#11171d;border:1px solid #2b3742;border-radius:8px;padding:14px;cursor:pointer}}.protocol-option input{{position:absolute;opacity:0;pointer-events:none}}.protocol-option:has(input:checked){{border-color:#6aa0ff;background:#142033;box-shadow:0 0 0 1px rgba(106,160,255,.32) inset}}.protocol-option b{{display:block;margin:8px 0 5px}}.protocol-icon,.app-icon{{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:8px;background:#26384b;color:#d9ecff;font-weight:800}}.app-icon{{width:46px;height:46px;font-size:22px;margin-bottom:10px}}.guide-card{{min-height:190px}}.guide-card p{{margin:8px 0 0}}.guide-card .hint{{margin-top:10px;color:#d9e7ef;font-size:14px}}.protocol-section{{margin:20px 0}}.protocol-head{{display:flex;align-items:center;gap:10px;margin-bottom:12px}}.protocol-head h2{{margin:0}}.protocol-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}.protocol-card{{background:rgba(17,23,29,.95);border:1px solid #2b3742;border-radius:8px;padding:16px}}.qr-box img{{display:block}}.mini-actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}}.pending-box{{border-color:#54749b;background:linear-gradient(135deg,#142033,#11171d);box-shadow:0 0 0 1px rgba(125,176,255,.08),0 14px 34px rgba(0,0,0,.26);animation:rise .28s ease both,pulseBorder 2.2s ease-in-out infinite}}.pending-line{{display:flex;align-items:center;gap:12px}}.spinner{{width:22px;height:22px;border:3px solid #334252;border-top-color:#7db0ff;border-radius:50%;animation:spin .9s linear infinite}}@keyframes spin{{to{{transform:rotate(360deg)}}}}@keyframes rise{{from{{opacity:0;transform:translateY(8px)}}to{{opacity:1;transform:none}}}}@keyframes sheen{{0%,55%{{transform:translateX(-100%)}}85%,100%{{transform:translateX(100%)}}}}@keyframes pulseBorder{{0%,100%{{border-color:#54749b}}50%{{border-color:#7db0ff}}}}.card,form,.metric,.protocol-card,.guide-card{{animation:rise .28s ease both}}button,.btn,.protocol-option{{transition:transform .16s ease,filter .16s ease,border-color .16s ease,background .16s ease,box-shadow .16s ease}}button:hover,.btn:hover,.protocol-option:hover{{transform:translateY(-1px);box-shadow:0 10px 22px rgba(0,0,0,.18)}}.btn[aria-busy="true"],button[aria-busy="true"]{{opacity:.78;pointer-events:none}}.btn[aria-busy="true"]::before,button[aria-busy="true"]::before{{content:"";display:inline-block;width:13px;height:13px;margin-right:8px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;vertical-align:-2px;animation:spin .8s linear infinite}}button.secondary{{background:#2b333b}}.admin-top{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0}}.metric{{background:#11171d;border:1px solid #2b3742;border-radius:8px;padding:14px}}.metric b{{display:block;font-size:26px;margin-top:6px}}.admin-grid{{display:grid;grid-template-columns:.82fr 1.18fr;gap:16px;align-items:start}}.request-card{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;margin-bottom:10px}}.request-card form{{box-shadow:none;padding:0;border:0;background:transparent}}.request-actions{{display:flex;gap:8px;align-items:end;flex-wrap:wrap}}.inline-form{{display:flex;gap:8px;align-items:end;flex-wrap:wrap}}.inline-form input{{width:88px}}.table-wrap{{overflow:auto;border:1px solid #2b3742;border-radius:8px}}.table-wrap table{{border:0;box-shadow:none}}details.card summary{{cursor:pointer;font-weight:800}}@media(max-width:860px){{.hero,.protocol-choice,.protocol-grid,.admin-top,.admin-grid{{grid-template-columns:1fr}}.request-card{{grid-template-columns:1fr}}}}
</style></head><body><main>{body}</main><script>
document.querySelectorAll('a.btn').forEach((link) => {{
  link.addEventListener('click', () => {{
    const label = link.dataset.loading || 'Загружаю...';
    link.textContent = label;
    link.setAttribute('aria-busy', 'true');
  }});
}});
document.querySelectorAll('form').forEach((form) => {{
  form.addEventListener('submit', () => {{
    const button = form.querySelector('button[type="submit"], button:not([type])');
    if (!button) return;
    button.dataset.oldText = button.textContent;
    button.textContent = button.dataset.loading || 'Сохраняю...';
    button.setAttribute('aria-busy', 'true');
  }});
}});
</script></body></html>"""


def support_block():
    return """<div class="card support"><b>Фонд свободного интернета им. ИИгоря</b><p class="muted">Этот сервис работает за счет добровольной поддержки: она помогает оплачивать серверы, держать резервные каналы и развивать стабильный доступ к свободному интернету. Если VPN помогает вам, поддержите фонд финансово.</p></div>"""


def instruction_block():
    return """<section class="guide">
<h2>Как подключиться</h2>
<div class="guide-grid">
  <div class="guide-card"><span class="app-icon">WG</span><b>WireGuard</b><p class="muted">Самый простой вариант для телефона и компьютера.</p><ol class="instructions"><li>Установите WireGuard.</li><li>Нажмите `+`.</li><li>Сканируйте QR или импортируйте `.conf`.</li><li>Включите туннель.</li></ol><div class="hint">Если QR не читается, скачайте файл конфигурации.</div></div>
  <div class="guide-card"><span class="app-icon">AZ</span><b>Amnezia</b><p class="muted">Подходит, если клиент уже пользуется Amnezia.</p><ol class="instructions"><li>Откройте Amnezia VPN.</li><li>Выберите добавление подключения.</li><li>Импортируйте `.conf` как WireGuard.</li><li>Сохраните и подключитесь.</li></ol><div class="hint">Используется тот же WireGuard-файл.</div></div>
  <div class="guide-card"><span class="app-icon">H2</span><b>Happ</b><p class="muted">Отдельная подписка Hysteria2 для Happ.</p><ol class="instructions"><li>Откройте Happ.</li><li>Добавьте подписку.</li><li>Вставьте личную ссылку из карточки.</li><li>Обновите список и подключитесь.</li></ol><div class="hint">Ссылку лучше копировать целиком.</div></div>
</div>
</section>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        return

    def cookie_sid(self):
        cookie = SimpleCookie(self.headers.get("cookie", ""))
        return cookie["vpn_session"].value if "vpn_session" in cookie else ""

    def cookie_login_nonce(self):
        cookie = SimpleCookie(self.headers.get("cookie", ""))
        return cookie["vpn_login"].value if "vpn_login" in cookie else ""

    def session(self):
        return get_session(self.cookie_sid())

    def set_session_cookie(self, sid):
        self.send_header("set-cookie", f"vpn_session={sid}; Max-Age={SESSION_TTL}; Path=/; HttpOnly; Secure; SameSite=Lax")

    def set_login_cookie(self, nonce):
        self.send_header("set-cookie", f"vpn_login={nonce}; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax")

    def clear_session_cookie(self):
        self.send_header("set-cookie", "vpn_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")

    def clear_login_cookie(self):
        self.send_header("set-cookie", "vpn_login=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")

    def send_html(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload, status=200, sid=None):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        if sid:
            self.set_session_cookie(sid)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path):
        self.send_response(303)
        self.send_header("location", path)
        self.end_headers()

    def redirect_with_cookie(self, path, sid):
        self.send_response(303)
        self.send_header("location", path)
        self.set_session_cookie(sid)
        self.clear_login_cookie()
        self.end_headers()

    def logout(self):
        delete_session(self.cookie_sid())
        self.send_response(303)
        self.send_header("location", public_url("/"))
        self.clear_session_cookie()
        self.end_headers()

    def body_params(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode()
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if path.startswith("/monitor"):
            self.proxy_monitor(path)
        elif path == "/app":
            self.redirect(public_url("/"))
        elif path in ("/", ""):
            body = self.client_home()
            if body is not None:
                self.send_html(body)
        elif path == "/login":
            self.handle_login(qs)
        elif path == "/login/check":
            self.handle_login_check(qs)
        elif path == "/manual":
            self.send_manual_page()
        elif path == "/logout":
            self.logout()
        elif path == "/claim":
            body = self.client_home()
            if body is not None:
                self.send_html(body)
        elif path == "/config":
            self.send_config(qs)
        elif path == "/qr":
            self.send_qr(qs)
        elif path.startswith("/happ-sub/"):
            self.send_happ_subscription(path)
        elif path == "/admin":
            body = self.admin_home("")
            if body is not None:
                self.send_html(body)
        elif path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
        else:
            self.send_html(page("Not found", "<h1>404</h1>"), 404)

    def do_POST(self):
        path = urlparse(self.path).path
        params = self.body_params()
        if path.startswith("/monitor"):
            self.proxy_monitor(path, method="POST", params=params)
        elif path == "/app/auth":
            self.handle_app_auth(params)
        elif path == "/app/request-access":
            self.handle_app_request_access(params)
        elif path == "/manual":
            self.handle_manual(params)
        elif path == "/claim":
            count = int(params.get("count", "0") or "0")
            self.handle_claim(count, params.get("bundle", "full"))
        elif path == "/admin/user":
            session = self.session()
            if not session or session["role"] != "admin":
                self.send_login_page("Нужен вход администратора.", 401)
                return
            username = norm_username(params.get("username", ""))
            max_profiles = int(params.get("max_profiles", "0") or "0")
            max_profiles = min(max_profiles, MAX_PROFILES_PER_USERNAME)
            note = params.get("note", "").strip()[:500]
            if username and max_profiles >= 0:
                with portal_db() as db:
                    db.execute(
                        """
                        insert into telegram_users(username,telegram_id,max_profiles,note,created_at,updated_at)
                        values(?,?,?,?,?,?)
                        on conflict(username) do update set
                          telegram_id=coalesce(telegram_users.telegram_id, excluded.telegram_id),
                          max_profiles=excluded.max_profiles,
                          note=excluded.note,
                          updated_at=excluded.updated_at
                        """,
                        (username, None, max_profiles, note, now(), now()),
                    )
            self.redirect(public_url("/admin"))
        elif path == "/admin/user/limit":
            session = self.session()
            if not session or session["role"] != "admin":
                self.send_login_page("Нужен вход администратора.", 401)
                return
            username = norm_username(params.get("username", ""))
            max_profiles = int(params.get("max_profiles", "0") or "0")
            update_user_limit(username, max_profiles)
            self.redirect(public_url("/admin"))
        elif path == "/admin/request/delete":
            session = self.session()
            if not session or session["role"] != "admin":
                self.send_login_page("Нужен вход администратора.", 401)
                return
            request_id = int(params.get("id", "0") or "0")
            delete_pending_request(request_id)
            self.redirect(public_url("/admin"))
        elif path == "/admin/request/approve":
            session = self.session()
            if not session or session["role"] != "admin":
                self.send_login_page("Нужен вход администратора.", 401)
                return
            request_id = int(params.get("id", "0") or "0")
            count = int(params.get("count", "1") or "1")
            approve_request(request_id, count)
            self.redirect(public_url("/admin"))
        elif path == "/admin/request/deny":
            session = self.session()
            if not session or session["role"] != "admin":
                self.send_login_page("Нужен вход администратора.", 401)
                return
            request_id = int(params.get("id", "0") or "0")
            deny_request(request_id)
            self.redirect(public_url("/admin"))
        else:
            self.send_html(page("Not found", "<h1>404</h1>"), 404)

    def send_login_page(self, message="", status=200):
        body = "<h1>VPN доступ</h1>" + support_block()
        if message:
            body += f"<p class='bad'>{html.escape(message)}</p>"
        body += f"""
<section class="hero">
  <div class="card status">
    <span class="pill">Браузерный портал</span>
    <h2>Получение профилей на сайте</h2>
    <p class="muted">Введите свой Telegram username в браузере. Если доступ уже одобрен, портал сразу покажет профили. Если доступа еще нет, заявка уйдет администратору, а на этой странице будет видно, что она ожидает подтверждения.</p>
    <div class="steps">
      <div class="step"><b>1. Вход</b><span class="muted">Укажите @username.</span></div>
      <div class="step"><b>2. Заявка</b><span class="muted">Администратор выдает лимит профилей.</span></div>
      <div class="step"><b>3. Кабинет</b><span class="muted">После одобрения здесь появятся профили.</span></div>
    </div>
    <p><a class="btn good" href="{public_url('/manual')}">Продолжить в браузере</a></p>
  </div>
  <div class="card">
    <h2>Что делать сейчас</h2>
    <p class="muted">Если доступ ещё не выдан, отправьте заявку. Подробные инструкции по приложениям появятся после одобрения, рядом с вашими профилями.</p>
  </div>
</section>
"""
        if BOT_USERNAME:
            nonce = self.cookie_login_nonce()
            row = get_login_nonce(nonce)
            if not row or row["status"] != "pending":
                nonce = create_login_nonce()
            link = f"https://t.me/{BOT_USERNAME}?start=login_{nonce}"
            body += f"""<div class="card"><h2>Дополнительно: вход через Telegram</h2><p class="muted">Нужен в основном администраторам и тем, кто хочет привязать сессию к Telegram ID. Обычным клиентам достаточно браузерного входа выше.</p>
<div class="actions"><a class="btn secondary" href="{html.escape(link)}" target="_blank" rel="noopener">Открыть Telegram</a>
<a class="btn secondary" href="{public_url('/login/check')}">Я подтвердил вход</a></div></div>"""
            page_html = page("Вход", body)
            data = page_html.encode()
            self.send_response(status)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self.set_login_cookie(nonce)
            self.end_headers()
            self.wfile.write(data)
            return
        else:
            body += "<p class='bad'>Telegram bot username не настроен.</p>"
        self.send_html(page("Вход", body), status)

    def send_manual_page(self, message="", status=200):
        body = "<h1>Вход в браузере</h1>" + support_block()
        if message:
            cls = "ok" if "Заявка отправлена" in message else "bad"
            body += f"<p class='{cls}'>{html.escape(message)}</p>"
        body += f"""
<form method="post" action="{public_url('/manual')}">
  <h2>Получить профили или отправить заявку</h2>
  <p class="muted">Введите Telegram username вручную. Регистр не важен: @User и @user считаются одним username. Если заявка уже одобрена, вы сразу попадете в личный кабинет.</p>
  <label>Telegram username</label>
  <input name="username" placeholder="@username" required>
  <label>Сколько профилей нужно, если доступа еще нет</label>
  <input name="count" type="number" min="1" max="{MAX_PROFILES_PER_USERNAME}" value="1">
  <button>Продолжить</button>
</form>
<p><a class="btn secondary" href="{public_url('/')}">Назад</a></p>
"""
        self.send_html(page("Вход по username", body), status)

    def mini_app_page(self):
        return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Mini App</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
body{{margin:0;background:#0f1215;color:#eef2f4;font-family:system-ui,-apple-system,Segoe UI,sans-serif}}main{{padding:18px;max-width:760px;margin:0 auto}}h1{{font-size:24px;margin:0 0 12px}}.card{{background:#171c21;border:1px solid #2a333c;border-radius:8px;padding:14px;margin:12px 0}}.support{{background:#16211c;border-color:#315545}}.support b{{color:#a8f2c4}}.muted{{color:#9aa5ad}}.btn{{display:block;border:0;border-radius:8px;background:#3d7eff;color:white;padding:13px 14px;text-decoration:none;text-align:center;margin-top:10px;font-weight:650}}.secondary{{background:#2b333b}}.bad{{color:#ffaaa1}}.ok{{color:#90e0ae}}
label{{display:block;margin-top:12px;color:#cdd6dc;font-size:14px}}input{{box-sizing:border-box;width:100%;margin-top:6px;padding:12px;border-radius:8px;border:1px solid #34424d;background:#0f1419;color:#eef2f4;font-size:16px}}button.btn{{width:100%;cursor:pointer}}.btn[aria-busy="true"]{{opacity:.75;pointer-events:none}}.loader{{display:flex;align-items:center;gap:10px}}.spinner{{width:18px;height:18px;border:2px solid #3b4650;border-top-color:#83aaff;border-radius:50%;animation:spin .8s linear infinite}}@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style></head><body><main>
<h1>VPN</h1>
<div class="card support"><b>Фонд свободного интернета им. ИИгоря</b><p class="muted">Сервис живет на добровольную поддержку: она оплачивает серверы, резервные каналы и развитие доступа к свободному интернету.</p></div>
<div id="app" class="card"><div class="loader"><span class="spinner"></span><span>Запускаю Mini App...</span></div><p class="muted">Проверяю Telegram-сессию и доступы.</p></div>
</main>
<script>
const tg = window.Telegram && window.Telegram.WebApp;
if (tg) {{
  tg.ready();
  tg.expand();
}}
const root = document.getElementById('app');
let initData = '';
function setLoading(text, hint = '') {{
  root.innerHTML = `<div class="loader"><span class="spinner"></span><span>${{text}}</span></div>${{hint ? `<p class="muted">${{hint}}</p>` : ''}}`;
}}
function setButtonLoading(button, text) {{
  if (!button) return;
  button.dataset.oldText = button.textContent;
  button.textContent = text;
  button.setAttribute('aria-busy', 'true');
}}
function clearButtonLoading(button) {{
  if (!button) return;
  button.textContent = button.dataset.oldText || button.textContent;
  button.removeAttribute('aria-busy');
}}
function renderError(text) {{
  root.innerHTML = `<p class="bad">${{text}}</p><p class="muted">Откройте этот экран из Telegram-бота @{html.escape(BOT_USERNAME)}.</p>`;
}}
function renderActions(data) {{
  const admin = data.role === 'admin';
  const username = data.username ? `@${{data.username}}` : 'username не получен';
  const accessText = data.access
    ? `Доступ активен. Осталось профилей: ${{data.remaining}} из ${{data.max_profiles}}.`
    : (data.pending ? `Заявка ожидает подтверждения. Запрошено профилей: ${{data.requested_profiles || 1}}.` : 'Доступ пока не выдан.');
  root.innerHTML = `
    <p class="ok">Вход выполнен: ${{username}}</p>
    <p class="muted">${{accessText}}</p>
    <a class="btn" data-loading="Открываю профили..." href="{public_url('/')}">Профили и заявки</a>
    ${{!data.access ? `<button class="btn secondary" id="requestBtn" type="button">Запросить доступ</button>` : ''}}
    ${{admin ? `<a class="btn secondary" data-loading="Открываю админку..." href="{public_url('/admin')}">Админка</a><a class="btn secondary" data-loading="Загружаю мониторинг..." href="https://{HOST}/monitor/">Мониторинг</a>` : ''}}
  `;
  const requestBtn = document.getElementById('requestBtn');
  if (requestBtn) requestBtn.addEventListener('click', () => renderRequestForm(data.username || ''));
  bindLoadingLinks();
}}
function renderRequestForm(username = '') {{
  root.innerHTML = `
    <h2>Запросить доступ</h2>
    <p class="muted">Если Telegram не передал username автоматически, введите его вручную. Регистр не важен: Telegram usernames не различают большие и маленькие буквы.</p>
    <label>Telegram username</label>
    <input id="manualUsername" value="${{username ? '@' + username : ''}}" placeholder="@username" autocomplete="username">
    <label>Сколько профилей нужно</label>
    <input id="profileCount" type="number" min="1" max="{MAX_PROFILES_PER_USERNAME}" value="1">
    <button class="btn" id="sendRequest" type="button">Отправить заявку</button>
    <button class="btn secondary" id="backBtn" type="button">Назад</button>
  `;
  document.getElementById('sendRequest').addEventListener('click', sendAccessRequest);
  document.getElementById('backBtn').addEventListener('click', boot);
}}
async function sendAccessRequest(event) {{
  const button = event.currentTarget;
  const username = document.getElementById('manualUsername').value.trim();
  const count = document.getElementById('profileCount').value || '1';
  setButtonLoading(button, 'Отправляю заявку...');
  const body = new URLSearchParams();
  body.set('init_data', initData);
  body.set('username', username);
  body.set('count', count);
  const res = await fetch('{public_url('/app/request-access')}', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body
  }});
  const data = await res.json().catch(() => null);
  clearButtonLoading(button);
  if (!res.ok || !data || !data.ok) {{
    renderError(data && data.error ? data.error : 'Не удалось отправить заявку.');
    return;
  }}
  renderActions(data);
}}
function bindLoadingLinks() {{
  document.querySelectorAll('[data-loading]').forEach((link) => {{
    link.addEventListener('click', () => {{
      link.textContent = link.dataset.loading;
      link.setAttribute('aria-busy', 'true');
    }});
  }});
}}
async function boot() {{
  if (!tg || !tg.initData) {{
    renderError('Нет данных Telegram WebApp.');
    return;
  }}
  initData = tg.initData;
  setLoading('Проверяю Telegram-сессию...', 'Обычно это занимает пару секунд.');
  const body = new URLSearchParams();
  body.set('init_data', initData);
  const res = await fetch('{public_url('/app/auth')}', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
    body
  }});
  const data = await res.json().catch(() => null);
  if (!res.ok || !data || !data.ok) {{
    renderError(data && data.error ? data.error : 'Не удалось выполнить вход.');
    return;
  }}
  if (data.need_username) {{
    renderRequestForm('');
    return;
  }}
  renderActions(data);
}}
boot();
</script></body></html>"""

    def handle_app_auth(self, params):
        identity = verify_webapp_init_data(params.get("init_data", ""))
        if not identity:
            self.send_json({"ok": False, "error": "Telegram WebApp подпись не прошла проверку."}, 401)
            return
        role = "admin" if identity["telegram_id"] in ADMIN_IDS else "user"
        if not identity["username"]:
            self.send_json(
                {
                    "ok": True,
                    "need_username": True,
                    "telegram_id": identity["telegram_id"],
                    "first_name": identity.get("first_name", ""),
                    "role": role,
                }
            )
            return
        identity["username_verified"] = True
        sid = create_session(identity)
        user = get_user(identity["username"])
        pending = get_pending_request(identity["telegram_id"])
        issued = issued_count(identity["username"]) if user else 0
        self.send_json(
            {
                "ok": True,
                "username": identity["username"],
                "telegram_id": identity["telegram_id"],
                "role": role,
                "access": bool(user),
                "pending": bool(pending),
                "max_profiles": user["max_profiles"] if user else 0,
                "issued": issued,
                "remaining": max(0, user["max_profiles"] - issued) if user else 0,
            },
            sid=sid,
        )

    def handle_app_request_access(self, params):
        identity = verify_webapp_init_data(params.get("init_data", ""))
        if not identity:
            self.send_json({"ok": False, "error": "Telegram WebApp подпись не прошла проверку."}, 401)
            return
        username = norm_username(params.get("username", "") or identity.get("username", ""))
        if not username:
            self.send_json({"ok": False, "error": "Введите Telegram username: 5-32 символа, латиница, цифры или underscore."}, 400)
            return
        count = max(1, min(int(params.get("count", "1") or "1"), MAX_PROFILES_PER_USERNAME))
        username_verified = bool(identity.get("username") and identity["username"] == username)
        session_identity = {
            "telegram_id": identity["telegram_id"],
            "username": username,
            "first_name": identity.get("first_name", ""),
            "username_verified": username_verified,
        }
        sid = create_session(session_identity)
        session = get_session(sid)
        user = get_user_for_session(session)
        pending = get_pending_request(identity["telegram_id"])
        if not user:
            if not pending:
                create_pending_request(session_identity, count)
            else:
                create_pending_request(session_identity, count)
            pending = get_pending_request(identity["telegram_id"])
        issued = issued_count(username) if user else 0
        self.send_json(
            {
                "ok": True,
                "username": username,
                "username_verified": username_verified,
                "access": bool(user),
                "pending": bool(pending) and not bool(user),
                "requested_profiles": pending["requested_profiles"] if pending and not user else count,
                "max_profiles": user["max_profiles"] if user else 0,
                "issued": issued,
                "remaining": max(0, user["max_profiles"] - issued) if user else 0,
            },
            sid=sid,
        )

    def handle_login(self, qs):
        identity = verify_telegram_login(qs)
        if not identity:
            self.send_login_page("Telegram-подпись не прошла проверку.", 401)
            return
        sid = create_session(identity)
        self.redirect_with_cookie(public_url("/"), sid)

    def handle_login_check(self, qs=None):
        nonce = ""
        if qs:
            nonce = qs.get("nonce", [""])[0]
        if not nonce:
            nonce = self.cookie_login_nonce()
        row = get_login_nonce(nonce)
        if not row or row["status"] != "confirmed":
            self.send_login_page("Подтверждение еще не получено. Откройте Telegram и нажмите Start у бота.")
            return
        sid = create_session({"telegram_id": row["telegram_id"], "username": row["username"], "first_name": row["first_name"]})
        with portal_db() as db:
            db.execute("delete from login_nonces where nonce=?", (nonce,))
        next_path = safe_next_path(qs.get("next", [""])[0] if qs else "")
        self.redirect_with_cookie(next_path, sid)

    def handle_manual(self, params):
        username = norm_username(params.get("username", ""))
        count = max(1, min(int(params.get("count", "1") or "1"), MAX_PROFILES_PER_USERNAME))
        if not username:
            self.send_manual_page("Введите Telegram username: 5-32 символа, латиница, цифры или underscore.", 400)
            return
        identity = {
            "telegram_id": 0,
            "username": username,
            "first_name": "browser",
            "username_verified": False,
        }
        with portal_db() as db:
            user = db.execute(
                "select * from telegram_users where username=? and telegram_id is null",
                (username,),
            ).fetchone()
            locked_user = db.execute(
                "select * from telegram_users where username=? and telegram_id is not null",
                (username,),
            ).fetchone()
        if user:
            sid = create_session(identity)
            self.redirect_with_cookie(public_url("/"), sid)
            return
        if locked_user:
            self.send_manual_page(
                "Этот username уже привязан к Telegram-входу. Для браузерного входа админ должен добавить отдельный ручной доступ.",
                403,
            )
            return
        pending = get_pending_request_for_identity(identity)
        if not pending:
            create_pending_request(identity, count)
        self.send_manual_page("Заявка отправлена администратору. После одобрения вернитесь сюда и введите username снова.")

    def client_home(self):
        session = self.session()
        if not session:
            self.send_login_page()
            return None
        username = session["username"]
        admin_links = ""
        if session["role"] == "admin":
            admin_links = f"""<div class="actions"><a class="btn secondary" data-loading="Открываю админку..." href="{public_url('/admin')}">Админка</a><a class="btn secondary" data-loading="Загружаю мониторинг..." href="/monitor/">Мониторинг</a></div>"""
        content = f"""<h1>VPN профили</h1>{support_block()}
<section class="hero">
  <div class="card status">
    <span class="pill">Личный кабинет</span>
    <h2>Все идет по плану</h2>
    <p class="muted">Вы вошли как @{html.escape(username)}. Слева собран статус доступа, справа - что именно выдать клиенту и как он будет подключаться.</p>
    {admin_links}
  </div>
  <div class="card">
    <h2>Что делает клиент</h2>
    <div class="steps">
      <div class="step"><span class="protocol-icon">1</span><b>Получает доступ</b><span class="muted">Создаём профиль или ссылку.</span></div>
      <div class="step"><span class="protocol-icon">2</span><b>Добавляет в приложение</b><span class="muted">QR, `.conf` или Happ subscription.</span></div>
      <div class="step"><span class="protocol-icon">3</span><b>Проверяет</b><span class="muted">Включает VPN и открывает любой сайт.</span></div>
    </div>
    <p><a class='btn secondary' href='{public_url('/logout')}'>Выйти</a></p>
  </div>
</section>"""
        user = get_user_for_session(session)
        if not user:
            pending = get_pending_request_for_identity(session)
            if pending:
                content += f"""<div class='card pending-box'><div class="pending-line"><span class="spinner"></span><div><h2>Заявка на подтверждении</h2><p class="muted">Запрошено профилей: <b>{pending['requested_profiles']}</b>. Администратор уже получил заявку. Страница сама обновится, и когда доступ будет одобрен, здесь появится выдача профилей.</p></div></div><p class="muted">Проверяю статус каждые 10 секунд. Можно оставить вкладку открытой.</p><script>setTimeout(() => window.location.reload(), 10000);</script></div>"""
            else:
                content += f"""<form method="post" action="{public_url('/claim')}"><h2>Запросить доступ</h2><p class="muted">@{html.escape(username)} пока не добавлен в список доступа. Укажите, сколько профилей нужно, и заявка уйдет администратору.</p><label>Сколько профилей нужно</label><input type="number" min="1" max="{MAX_PROFILES_PER_USERNAME}" name="count" value="1"><button>Отправить заявку</button></form>"""
        else:
            issued = issued_count(username)
            remaining = max(0, user["max_profiles"] - issued)
            content += f"<div class='card'><h2>@{html.escape(username)}</h2><p>Доступно профилей: <b>{remaining}</b> из {user['max_profiles']}. Уже выдано: {issued}.</p>"
            if remaining > 0:
                content += f"""<form method="post" action="{public_url('/claim')}"><h3>Что выдать сейчас</h3><p class="muted">Выберите, какой тип доступа нужен клиенту. WireGuard и Amnezia используют один и тот же `.conf`; Happ выдаётся отдельной ссылкой подписки.</p>
<div class="protocol-choice">
  <label class="protocol-option"><input type="radio" name="bundle" value="wireguard" checked><span class="protocol-icon">WG</span><b>WireGuard / Amnezia</b><span class="muted">QR и файл `.conf`.</span></label>
  <label class="protocol-option"><input type="radio" name="bundle" value="happ"><span class="protocol-icon">H2</span><b>Happ</b><span class="muted">Личная ссылка подписки.</span></label>
  <label class="protocol-option"><input type="radio" name="bundle" value="full"><span class="protocol-icon">ALL</span><b>Оба варианта</b><span class="muted">WireGuard/Amnezia и Happ.</span></label>
</div>
<label>Сколько профилей создать сейчас</label><input type="number" min="1" max="{remaining}" name="count" value="1"><button>Создать выбранный доступ</button></form>"""
            content += "</div>"
            content += instruction_block()
            content += self.profile_cards(username)
        return page("VPN профили", content)

    def profile_cards(self, username):
        profiles = list_profiles(username)
        if not profiles:
            return ""
        wg = "<section class='protocol-section'><div class='protocol-head'><span class='protocol-icon'>WG</span><h2>WireGuard и Amnezia</h2></div><div class='protocol-grid'>"
        happ = "<section class='protocol-section'><div class='protocol-head'><span class='protocol-icon'>H2</span><h2>Happ / Hysteria2</h2></div><div class='protocol-grid'>"
        for p in profiles:
            params = {"id": p["wg_client_id"], "username": username}
            qr = public_url("/qr", params)
            config = public_url("/config", params)
            happ_token = p.get("happ_token") or ensure_profile_happ_token(p["id"])
            happ_link = abs_public_url(f"/happ-sub/{happ_token}")
            wg += f"""<div class="protocol-card"><h3>{html.escape(p['name'])}</h3><p class="muted">IP профиля: {html.escape(p.get('ipv4_address',''))}</p><div class="qr-box"><img src="{qr}" alt="QR для WireGuard"></div><div class="mini-actions"><a class="btn" href="{config}">Скачать .conf</a><a class="btn secondary" href="{qr}">Открыть QR</a></div><ol class="instructions"><li>WireGuard: нажмите `+` и сканируйте QR.</li><li>Amnezia: импортируйте скачанный `.conf` как WireGuard.</li></ol></div>"""
            happ += f"""<div class="protocol-card"><h3>{html.escape(p['name'])}</h3><p class="muted">Личная ссылка подписки для Happ. Её можно отправить клиенту отдельно от WireGuard.</p><p class="copy">{html.escape(happ_link)}</p><div class="mini-actions"><a class="btn secondary" href="{html.escape(happ_link)}">Открыть ссылку</a></div><ol class="instructions"><li>В Happ откройте добавление подписки.</li><li>Вставьте эту ссылку целиком.</li><li>Обновите список серверов и подключитесь.</li></ol></div>"""
        wg += "</div></section>"
        happ += "</div></section>"
        return "<h2>Выданные доступы</h2>" + wg + happ

    def handle_claim(self, count, bundle="full"):
        session = self.session()
        if not session:
            self.send_login_page()
            return
        username = session["username"]
        user = get_user_for_session(session)
        if not user:
            create_pending_request({"telegram_id": session["telegram_id"], "username": username, "first_name": session["first_name"]}, count)
            self.redirect(public_url("/"))
            return
        remaining = max(0, user["max_profiles"] - issued_count(username))
        count = max(0, min(count, remaining, MAX_PROFILES_PER_USERNAME))
        for i in range(count):
            suffix = issued_count(username) + 1
            create_profile(username, suffix)
        self.redirect(public_url("/claim", {"username": username}))

    def admin_home(self, message):
        session = self.session()
        if not session or session["role"] != "admin":
            self.send_login_page("Нужен вход администратора.", 401)
            return None
        rows = list_users()
        stats = portal_stats()
        requests = list_pending_requests()
        pending = [r for r in requests if r["status"] == "pending"]
        body = f"""<h1>Админка VPN</h1><p class='muted'>Вход: @{html.escape(session['username'])} · <a class='btn secondary' data-loading='Открываю кабинет...' href='{public_url('/')}'>Кабинет</a> <a class='btn secondary' data-loading='Загружаю мониторинг...' href='/monitor/'>Мониторинг</a> <a class='btn secondary' href='{public_url('/logout')}'>Выйти</a></p>
<section class="admin-top">
  <div class="metric"><span class="muted">Ожидают решения</span><b>{stats['pending']}</b></div>
  <div class="metric"><span class="muted">Пользователи</span><b>{stats['users']}</b></div>
  <div class="metric"><span class="muted">Выдано профилей</span><b>{stats['issued']}</b></div>
  <div class="metric"><span class="muted">Всего заявок</span><b>{stats['requests']}</b></div>
</section>
<section class="admin-grid">
  <form method="post" action="{public_url('/admin/user')}"><h2>Доступ пользователя</h2><p class="muted">Добавьте username, измените лимит или временно поставьте `0`, чтобы новые профили не создавались.</p><label>Telegram username</label><input name="username" placeholder="@username" required><label>Максимум профилей</label><input name="max_profiles" type="number" min="0" max="{MAX_PROFILES_PER_USERNAME}" value="1"><p class="muted">Жесткий максимум: {MAX_PROFILES_PER_USERNAME}</p><label>Заметка</label><textarea name="note" rows="3" placeholder="Кто это, когда оплачен, что выдано"></textarea><button>Сохранить доступ</button></form>
  <div class="card"><h2>Новые заявки</h2>"""
        if pending:
            for r in pending:
                suggested = max(1, min(int(r["requested_profiles"] or 1), MAX_PROFILES_PER_USERNAME))
                body += f"""<div class="request-card"><div><b>@{html.escape(r['username'])}</b><p class="muted">Запрошено: {r['requested_profiles']} · Источник: {'браузер' if int(r['telegram_id'] or 0) == 0 else 'Telegram'} · {html.escape(r['created_at'])}</p></div><div class="request-actions"><form class="inline-form" method="post" action="{public_url('/admin/request/approve')}"><input type="hidden" name="id" value="{r['id']}"><label>Лимит<input name="count" type="number" min="1" max="{MAX_PROFILES_PER_USERNAME}" value="{suggested}"></label><button>Одобрить</button></form><form method="post" action="{public_url('/admin/request/deny')}"><input type="hidden" name="id" value="{r['id']}"><button class="secondary">Отказать</button></form><form method="post" action="{public_url('/admin/request/delete')}" onsubmit="return confirm('Удалить заявку @{html.escape(r['username'])}?')"><input type="hidden" name="id" value="{r['id']}"><button class="secondary">Удалить</button></form></div></div>"""
        else:
            body += "<p class='muted'>Новых заявок нет.</p>"
        body += "</div></section>"
        body += "<h2>Пользователи</h2><section class='profiles'>"
        for r in rows:
            remaining = max(0, int(r["max_profiles"] or 0) - int(r["issued"] or 0))
            user_profiles = list_profiles(r["username"])
            body += f"""<details class="card"><summary>@{html.escape(r['username'])} · выдано {r['issued']} из {r['max_profiles']} · осталось {remaining}</summary>
<div class="request-card"><div><p class="muted">{html.escape(r['note'] or 'Без заметки')}</p></div><form class="inline-form" method="post" action="{public_url('/admin/user/limit')}"><input type="hidden" name="username" value="{html.escape(r['username'])}"><label>Новый лимит<input name="max_profiles" type="number" min="0" max="{MAX_PROFILES_PER_USERNAME}" value="{r['max_profiles']}"></label><button>Сохранить лимит</button></form></div>"""
            if user_profiles:
                body += "<div class='table-wrap'><table><thead><tr><th>Профиль</th><th>WireGuard IP</th><th>WireGuard</th><th>Happ</th><th>Создан</th></tr></thead><tbody>"
                for p in user_profiles:
                    params = {"id": p["wg_client_id"], "username": r["username"]}
                    config = public_url("/config", params)
                    qr = public_url("/qr", params)
                    happ_token = p.get("happ_token") or ensure_profile_happ_token(p["id"])
                    happ_link = abs_public_url(f"/happ-sub/{happ_token}")
                    body += f"""<tr><td>{html.escape(p['name'])}</td><td>{html.escape(p.get('ipv4_address',''))}</td><td><a class="btn secondary" href="{config}">.conf</a> <a class="btn secondary" href="{qr}">QR</a></td><td><a class="btn secondary" href="{html.escape(happ_link)}">Happ</a></td><td>{html.escape(p['created_at'])}</td></tr>"""
                body += "</tbody></table></div>"
            else:
                body += "<p class='muted'>Профили пока не созданы.</p>"
            body += "</details>"
        body += "</section>"
        return page("Админка VPN", body)

    def send_config(self, qs):
        client_id = int(qs.get("id", ["0"])[0] or "0")
        username = norm_username(qs.get("username", [""])[0])
        session = self.session()
        if not session or (session["role"] != "admin" and session["username"] != username):
            self.send_response(403)
            self.end_headers()
            return
        with portal_db() as db:
            ok = db.execute("select 1 from issued_profiles where username=? and wg_client_id=?", (username, client_id)).fetchone()
        if not ok:
            self.send_response(404)
            self.end_headers()
            return
        config = client_config(client_id).encode()
        self.send_response(200)
        self.send_header("content-type", "application/x-wireguard-config")
        self.send_header("content-disposition", f'attachment; filename="wg-{username}-{client_id}.conf"')
        self.send_header("content-length", str(len(config)))
        self.end_headers()
        self.wfile.write(config)

    def send_qr(self, qs):
        client_id = int(qs.get("id", ["0"])[0] or "0")
        username = norm_username(qs.get("username", [""])[0])
        session = self.session()
        if not session or (session["role"] != "admin" and session["username"] != username):
            self.send_response(403)
            self.end_headers()
            return
        with portal_db() as db:
            ok = db.execute("select 1 from issued_profiles where username=? and wg_client_id=?", (username, client_id)).fetchone()
        if not ok:
            self.send_response(404)
            self.end_headers()
            return
        svg = qr_svg(client_config(client_id)).encode()
        self.send_response(200)
        self.send_header("content-type", "image/svg+xml")
        self.send_header("content-length", str(len(svg)))
        self.end_headers()
        self.wfile.write(svg)

    def send_happ_subscription(self, path):
        name = path.rsplit("/", 1)[-1]
        b64 = False
        if name.endswith(".b64"):
            b64 = True
            name = name[:-4]
        profile = get_profile_by_happ_token(name)
        if not profile:
            self.send_response(404)
            self.end_headers()
            return
        source = HAPP_SOURCE_B64_URL if b64 else HAPP_SOURCE_RAW_URL
        try:
            req = Request(source, headers={"user-agent": "client-portal/1.0"})
            with urlopen(req, timeout=12) as response:
                data = response.read()
        except Exception:
            self.send_html(page("Happ unavailable", "<h1>Happ подписка временно недоступна</h1><p class='muted'>Попробуйте открыть ссылку позже.</p>"), 502)
            return
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def proxy_monitor(self, path, method="GET", params=None):
        session = self.session()
        if not session or session["role"] != "admin":
            self.send_login_page("Для мониторинга нужен вход администратора.", 401)
            return
        suffix = path[len("/monitor"):] or "/"
        query = urlparse(self.path).query
        target = "http://127.0.0.1:8090" + suffix + (("?" + query) if query else "")
        try:
            request = target
            if method == "POST":
                data = urlencode(params or {}).encode()
                request = Request(target, data=data, headers={"content-type": "application/x-www-form-urlencoded"}, method="POST")
            with urlopen(request, timeout=30) as response:
                data = response.read()
                content_type = response.headers.get("content-type", "text/html; charset=utf-8")
            if "text/html" in content_type.lower():
                button = f"""<style>
.portal-back{{position:fixed;right:18px;bottom:18px;z-index:2147483647;display:inline-flex;align-items:center;gap:8px;padding:11px 15px;border-radius:8px;background:#3978f2;color:#fff;text-decoration:none;font:650 15px system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 12px 28px rgba(0,0,0,.35);transition:transform .16s ease,filter .16s ease}}
.portal-back:hover{{transform:translateY(-1px);filter:brightness(1.08)}}
</style><a class="portal-back" href="{public_url('/')}">← В кабинет</a>"""
                text = data.decode("utf-8", errors="replace")
                if "</body>" in text:
                    text = text.replace("</body>", button + "</body>", 1)
                else:
                    text += button
                data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self.send_html(page("Monitor unavailable", "<h1>Мониторинг временно недоступен</h1>"), 502)


if __name__ == "__main__":
    init_db()
    setup_bot_menu()
    threading.Thread(target=bot_poll_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 8091), Handler).serve_forever()
