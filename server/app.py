"""Read-only monitoring receiver for Python WSGI hosting."""
import base64
import gzip
from contextlib import contextmanager
import hashlib
import hmac
import io
from http import HTTPStatus
from http.cookies import SimpleCookie
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from redis_cache import RedisCache
from encryption import SealedData
from i18n import EN, language, render_html, translate

VERSION = "1.0.81"
SOURCE_RELEASE = Path(__file__).resolve().parents[1].name
MAX_BODY = 8 * 1024 * 1024
WEB = Path(__file__).resolve().parent / "web"
os.umask(0o077)


def private_config():
    path = Path(os.environ.get("WM_PUBLIC_CONFIG", Path.home() / ".w-monitor/config.json"))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError("Private owner-only configuration required")
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise RuntimeError("Configuration too large")
    config = json.loads(raw)
    public = urlsplit(config["public_url"])
    if (public.scheme != "https" and not (public.scheme == "http" and public.hostname in ("127.0.0.1", "localhost", "::1"))) or not public.hostname or public.username or public.password or public.query or public.fragment or public.path not in ("", "/"):
        raise RuntimeError("A fixed HTTPS public origin is required")
    if not re.fullmatch(r"[a-f0-9]{64}", config.get("instance_secret", "")):
        raise RuntimeError("A random instance secret is required")
    data = Path(config["data_dir"])
    if not data.is_absolute() or data.is_symlink():
        raise RuntimeError("Private absolute data directory required")
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = data.stat()
    if data.resolve() != data or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError("Data directory must be real and owner-only")
    if data.is_relative_to(WEB) or data == WEB:
        raise RuntimeError("Data must stay outside the web root")
    web_root = Path(config.get("web_root", Path.home() / "public_html")).resolve()
    if data.is_relative_to(web_root) or path.resolve().is_relative_to(web_root):
        raise RuntimeError("Private data/configuration cannot be web-accessible")
    interval = config.get("report_interval_ms", 60000)
    if type(interval) is not int or not 5000 <= interval <= 300000:
        raise RuntimeError("Invalid reporting interval")
    issuer = config.get("oidc_base_url", "").rstrip("/")
    if issuer:
        parsed = urlsplit(issuer)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise RuntimeError("Invalid identity origin")
    return config, data, config["public_url"].rstrip("/"), interval, issuer


CONFIG, DATA, ORIGIN, INTERVAL, ISSUER = private_config()
BOX = SealedData(CONFIG["instance_secret"])
DATABASE = DATA / "monitor.sqlite3"
CACHE = RedisCache(CONFIG.get("redis_socket", ""))
NAMESPACE = "wm-public:" + hashlib.sha256(CONFIG["instance_secret"].encode()).hexdigest()[:16] + ":"
DYNAMIC = NAMESPACE + "reports"
LINK = r"wm1_[A-Za-z0-9_-]{40,320}"
COOKIE = "__Host-wm_public" if ORIGIN.startswith("https:") else "wm_public_dev"


@contextmanager
def database():
    if DATABASE.is_symlink():
        raise RuntimeError("Database cannot be a symlink")
    connection = sqlite3.connect(DATABASE, timeout=1, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=1000")
    connection.execute("PRAGMA journal_size_limit=8388608")
    connection.execute("PRAGMA wal_autocheckpoint=128")
    try:
        yield connection
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


with database() as _db:
    _db.execute("PRAGMA journal_mode=WAL")
    _db.execute("PRAGMA journal_size_limit=8388608")
    _db.executescript("""
    CREATE TABLE IF NOT EXISTS spaces(
      id TEXT PRIMARY KEY, title TEXT NOT NULL, recovery_hash TEXT UNIQUE NOT NULL,
      bootstrap_hash TEXT UNIQUE NOT NULL, owner TEXT, created_at INTEGER NOT NULL,
      revision INTEGER NOT NULL DEFAULT 0, channel TEXT NOT NULL,
      email TEXT, notifications_enabled INTEGER NOT NULL DEFAULT 0,
      notification_locale TEXT NOT NULL DEFAULT 'en', auto_page TEXT);
    CREATE INDEX IF NOT EXISTS space_owner ON spaces(owner);
    CREATE TABLE IF NOT EXISTS sessions(
      hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, space_id TEXT REFERENCES spaces(id),
      subject TEXT, label TEXT, expires INTEGER NOT NULL,
      oauth_state TEXT, oauth_verifier TEXT, oauth_expires INTEGER, verified_email TEXT);
    CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires);
    CREATE TABLE IF NOT EXISTS devices(
      id TEXT PRIMARY KEY, space_id TEXT NOT NULL REFERENCES spaces(id),
      agent_id TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      created_at INTEGER NOT NULL, UNIQUE(space_id,agent_id));
    CREATE INDEX IF NOT EXISTS device_space ON devices(space_id);
    CREATE TABLE IF NOT EXISTS pages(
      id TEXT PRIMARY KEY, space_id TEXT NOT NULL REFERENCES spaces(id),
      slug_hash TEXT UNIQUE NOT NULL, slug_ciphertext TEXT NOT NULL,
      title TEXT NOT NULL, enabled INTEGER NOT NULL,
      selection TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS page_space ON pages(space_id);
    CREATE TABLE IF NOT EXISTS notification_state(
      device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
      state TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS notification_outbox(
      id INTEGER PRIMARY KEY AUTOINCREMENT, space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      revision INTEGER NOT NULL, state TEXT NOT NULL, recipient TEXT NOT NULL,
      created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0, attempted_at INTEGER,
      UNIQUE(device_id,revision));
    CREATE INDEX IF NOT EXISTS notification_pending ON notification_outbox(status,created_at);

    """)


class Rejected(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def secret(prefix):
    return prefix + secrets.token_hex(32)


def limited(identity, limit, seconds):
    now = int(time.time())
    key = hmac.new(CONFIG["instance_secret"].encode(), identity.encode(), hashlib.sha256).hexdigest()
    result = CACHE.rate(NAMESPACE + "rate:" + str(seconds) + ":" + str(now // seconds), key, limit, seconds)
    if result is None:
        raise Rejected(503, "实时服务暂不可用，请稍后再试")
    if result != 1:
        raise Rejected(429, "操作过于频繁，请稍后再试")


def body(environ, maximum=256 * 1024):
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        raise Rejected(400, "无效请求长度") from None
    if length < 0 or length > maximum:
        raise Rejected(413, "请求超过大小限制")
    encoding = environ.get("HTTP_CONTENT_ENCODING", "identity")
    if environ.get("CONTENT_TYPE", "").split(";", 1)[0].lower() != "application/json" or encoding not in ("identity", "gzip") or (encoding == "gzip" and maximum != MAX_BODY):
        raise Rejected(415, "请发送 JSON（上报支持 gzip 压缩）")
    try:
        def invalid_constant(_value):
            raise ValueError()
        raw = environ["wsgi.input"].read(length)
        if encoding == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(maximum + 1)
            if len(raw) > maximum:
                raise Rejected(413, "请求超过大小限制")
        value = json.loads(raw, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError, gzip.BadGzipFile, EOFError, zlib.error):
        raise Rejected(400, "无效 JSON") from None
    if not isinstance(value, dict):
        raise Rejected(400, "JSON 必须是对象")
    return value


def cookie_header(token):
    return ("Set-Cookie", f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800" + ("; Secure" if ORIGIN.startswith("https:") else ""))


def browser_session(db, environ, create=False):
    raw = environ.get("HTTP_COOKIE", "")
    if len(raw) > 8192:
        raise Rejected(400, "请求头过大")
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        raise Rejected(400, "无效会话") from None
    token = jar[COOKIE].value if COOKIE in jar else ""
    session = db.execute("SELECT * FROM sessions WHERE hash=? AND expires>?", (digest(token), int(time.time()))).fetchone() if re.fullmatch(r"wms_[a-f0-9]{64}", token) else None
    if session:
        return dict(session), []
    if not create:
        raise Rejected(401, "请创建、恢复或登录监控空间")
    limited("session:" + environ.get("REMOTE_ADDR", ""), 60, 3600)
    now = int(time.time())
    db.execute("DELETE FROM sessions WHERE hash IN (SELECT hash FROM sessions WHERE expires<? LIMIT 128)", (now,))
    token = secret("wms_")
    session = {"hash": digest(token), "csrf": secrets.token_hex(32), "space_id": None, "subject": None, "label": None, "expires": now + 604800}
    db.execute("INSERT INTO sessions(hash,csrf,expires) VALUES(?,?,?)", (session["hash"], session["csrf"], session["expires"]))
    return session, [cookie_header(token)]


def write_guard(environ, session):
    if environ.get("HTTP_ORIGIN") != ORIGIN or not hmac.compare_digest(environ.get("HTTP_X_CSRF_TOKEN", ""), session["csrf"]):
        raise Rejected(403, "请求来源或会话验证失败，请刷新页面")


def current_space(db, session):
    row = db.execute("SELECT * FROM spaces WHERE id=?", (session["space_id"],)).fetchone()
    if not row:
        raise Rejected(403, "请先创建或恢复监控空间")
    return dict(row)


def begin_browser_write(db, session, space_id=None):
    db.execute("BEGIN IMMEDIATE")
    active = db.execute("SELECT * FROM sessions WHERE hash=? AND expires>?", (session["hash"], int(time.time()))).fetchone()
    if not active or (space_id and active["space_id"] != space_id):
        raise Rejected(401, "会话已失效，请重新恢复或登录")
    return active


def space_summary(row):
    return {"id": row["id"], "title": row["title"], "claimed": bool(row["owner"])}


def percent(value):
    return round(value, 2) if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100 else None


def scalar(collectors, name):
    value = collectors.get(name, {})
    if not isinstance(value, dict):
        return {}
    return value.get("data", value) if isinstance(value.get("data", value), dict) else {}


def link_payload(purpose, token):
    try:
        value = BOX.open(purpose, token)
        if not isinstance(value, dict) or not re.fullmatch(r"[a-f0-9]{32}", value.get("id", "")):
            raise ValueError()
        return value["id"]
    except (ValueError, TypeError):
        raise Rejected(404, "地址无效或已被更换") from None


def operation_guard(environ, space):
    if link_payload("manage", environ.get("HTTP_X_OPERATION_TOKEN", "")) != space["id"]:
        raise Rejected(403, "管理地址不属于当前监控空间")


def live_metadata(rows):
    ids = [row["id"] for row in rows]
    values = []
    for offset in range(0, len(ids), 512):
        batch = CACHE.command("HMGET", DYNAMIC, *("meta:" + item for item in ids[offset:offset + 512]))
        if batch is None:
            return {}, False
        values.extend(batch)
    result = {}
    for device, raw in zip(ids, values):
        if raw:
            try:
                result[device] = BOX.open("metrics:" + device, raw)
            except ValueError:
                pass
    return result, True


def projection(row, meta=None, public=False, available=True):
    received = meta.get("received_at") if isinstance(meta, dict) else None
    online = received >= time.time() - max(60, INTERVAL / 1000 * 2.1) if type(received) is int else None
    result = {"name": meta.get("name", row["name"]) if isinstance(meta, dict) else row["name"], "online": online, "last_seen": received, "data_status": "available" if received else "awaiting_report" if available else "unavailable", "cpu_percent": meta.get("cpu") if online else None, "memory_percent": meta.get("memory") if online else None, "disk_percent": meta.get("disk") if online else None}
    if not public:
        result["id"] = row["id"]
        result["agent_id"] = row["agent_id"]
    return result


def page_number(environ):
    raw = parse_qs(environ.get("QUERY_STRING", "")).get("page", ["0"])[0]
    if not re.fullmatch(r"[0-9]{1,10}", raw):
        raise Rejected(400, "无效页码")
    return int(raw)


def snapshot(db, space=None, slug=None, number=0):
    if slug:
        page_id = link_payload("public", slug)
        page = db.execute("SELECT p.*,s.revision FROM pages p JOIN spaces s ON s.id=p.space_id WHERE p.id=? AND p.slug_hash=? AND p.enabled=1", (page_id, digest(slug))).fetchone()
        if not page:
            raise Rejected(404, "此分享链接已停用或不存在")
        selection_raw = page["selection"]
        scope, title, space_id, revision = page["id"], page["title"], page["space_id"], page["revision"]
    else:
        scope, title, space_id, revision = space["id"], space["title"], space["id"], space["revision"]
        selection_raw = None
    key = NAMESPACE + "view:" + ("public:" if slug else "space:") + scope + ":" + str(number)
    cached_view = CACHE.read_view(DYNAMIC, key, space_id)
    # A five-second shared snapshot matches browser refresh cadence. Per-report
    # invalidation would rebuild every page of a large fleet dozens of times a
    # second. Ownership/revocation/publication still come from SQLite each read.
    fingerprint = digest(json.dumps([revision, cached_view[:1] if cached_view else None, title, digest(selection_raw) if selection_raw else None, int(time.time()) // 5]))
    if cached_view and cached_view[2]:
        try:
            cached = BOX.open("view:" + digest(key), json.loads(cached_view[2]))
            if cached.get("fingerprint") == fingerprint and isinstance(cached.get("snapshot"), str):
                return cached["snapshot"].encode()
        except (ValueError, TypeError, KeyError):
            pass
    rows = db.execute("SELECT id,agent_id,name FROM devices WHERE space_id=? ORDER BY name,id", (space_id,)).fetchall()
    selected = set(json.loads(selection_raw)) if selection_raw is not None else None
    rows = [row for row in rows if selected is None or row["id"] in selected]
    total = len(rows)
    rows = rows[number * 100:(number + 1) * 100]
    metadata, available = live_metadata(rows)
    result = {"title": title, "devices": [projection(row, metadata.get(row["id"]), bool(slug), available) for row in rows], "read_only": True, "realtime": CONFIG.get("enable_events") is True, "data_available": available, "page": number, "page_size": 100, "total": total}
    payload = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if available:
        CACHE.put(key, BOX.seal("view:" + digest(key), {"fingerprint": fingerprint, "snapshot": payload.decode()}), NAMESPACE + "views")
    return payload


def receive(db, environ):
    limited("report:" + environ.get("REMOTE_ADDR", ""), 3000, 60)
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer ") or len(auth) > 256:
        raise Rejected(401, "需要设备上报凭据")
    credential = digest(auth[7:])
    report = body(environ, MAX_BODY)
    agent = report.get("agent_id", "")
    if not isinstance(agent, str) or not 1 <= len(agent.encode()) <= 255 or agent != agent.strip() or any(ord(c) < 32 or ord(c) == 127 for c in agent):
        raise Rejected(400, "无效设备标识")
    if report.get("version") != "1.0" or not isinstance(report.get("collectors"), dict) or ("compact" in report and not isinstance(report["compact"], dict)):
        raise Rejected(400, "需要 v1.0 完整采集快照")
    machine = db.execute("SELECT * FROM devices WHERE token_hash=?", (credential,)).fetchone()
    # Registration serializes durable ownership/token writes. Steady-state
    # telemetry never takes the SQLite writer lock or rewrites the device row.
    if not machine:
        db.execute("BEGIN IMMEDIATE")
    space = db.execute("SELECT * FROM spaces WHERE bootstrap_hash=?", (credential,)).fetchone() if not machine else None
    if machine and machine["agent_id"] != agent:
        raise Rejected(403, "设备凭据只允许上报它自身")
    if not machine and not space:
        raise Rejected(401, "上报凭据无效或已吊销")
    space_id = machine["space_id"] if machine else space["id"]
    # Stable per-device staggering spreads a fleet's subsequent reports without
    # adding an Agent update/control mechanism.
    interval = max(10000, min(300000, INTERVAL + int(digest(agent)[:8], 16) % max(1, INTERVAL // 5) - INTERVAL // 10))
    reply = {"status": "ok", "agent_id": agent, "commands": [], "report_role": "primary", "report_interval_ms": interval, "scope": "telemetry"}
    if report.get("compact", {}).get("mode") == "delta":
        db.rollback()
        return {**reply, "request_full_report": True}
    existing = machine or db.execute("SELECT * FROM devices WHERE space_id=? AND agent_id=?", (space_id, agent)).fetchone()
    name = report.get("hostname", agent)
    name = name[:120] if isinstance(name, str) and name.strip() else agent[:120]
    collectors = report["collectors"]
    cpu, memory, disk = (scalar(collectors, key) for key in ("cpu", "memory", "disk"))
    device_id = existing["id"] if existing else secrets.token_hex(16)
    machine_token = "sat_" + secrets.token_hex(16) if not machine else None
    token_hash = digest(machine_token) if machine_token else machine["token_hash"]
    if not machine:
        db.execute("INSERT INTO devices VALUES(?,?,?,?,?,?) ON CONFLICT(space_id,agent_id) DO UPDATE SET token_hash=excluded.token_hash", (device_id, space_id, agent, token_hash, name, int(time.time())))
        if space["auto_page"]:
            # Explicit one-click setup publishes only its first real device.
            # Later registrations never add devices to this page automatically.
            db.execute("UPDATE pages SET selection=? WHERE id=? AND space_id=? AND enabled=1", (json.dumps([device_id]), space["auto_page"], space_id))
            db.execute("UPDATE spaces SET auto_page=NULL WHERE id=?", (space_id,))
    metadata = {"name": name, "received_at": int(time.time()), "cpu": percent(cpu.get("usage_percent", cpu.get("usage"))), "memory": percent(memory.get("usage_percent")), "disk": percent(disk.get("usage_percent"))}
    stored = CACHE.store_report(DYNAMIC, device_id, space_id, BOX.seal_report("report:" + device_id, report), BOX.seal("metrics:" + device_id, metadata), secrets.token_hex(16))
    if stored != 1:
        raise Rejected(503, "实时数据存储暂不可用；本次上报未确认")
    try:
        db.commit()
    except sqlite3.Error:
        db.rollback()
        if not existing:
            CACHE.remove_reports(DYNAMIC, [device_id], space_id)
        raise
    if machine_token:
        reply["agent_token"] = machine_token
    return reply


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def identity_request(path, form=None, bearer=None):
    headers = {"Accept": "application/json", "User-Agent": "W-Monitor-Public/" + VERSION}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = Request(ISSUER + path, data=urlencode(form).encode() if form is not None else None, headers=headers)
    try:
        with build_opener(NoRedirect()).open(request, timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (HTTPError, URLError, OSError, ValueError):
        raise Rejected(502, "身份服务暂时不可用，请重新登录") from None


def events(environ, slug=None):
    if CONFIG.get("enable_events") is not True:
        raise Rejected(404, "此部署使用定时刷新")
    lease = secrets.token_hex(16)
    with database() as db:
        session = browser_session(db, environ)[0] if not slug else None
        space = current_space(db, session) if session else None
        snapshot(db, space, slug)
        observed_space = space["id"] if space else db.execute("SELECT space_id FROM pages WHERE slug_hash=?", (digest(slug),)).fetchone()[0]
        scope = slug or space["id"]
        now = int(time.time())
        scope_hash = digest(scope)
        lease = scope_hash + ":" + lease
        accepted = CACHE.lease(NAMESPACE + "streams", lease, scope_hash, now)
        if accepted != 1:
            raise Rejected(429 if accepted == 0 else 503, "实时连接暂不可用，页面将使用轮询")


    def stream():
        previous = None
        try:
            yield ("retry: 3000\n:" + " " * 2048 + "\n\n").encode()
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                try:
                    with database() as db:
                        active = browser_session(db, environ)[0] if not slug else None
                        if active and active["space_id"] != space["id"]:
                            raise Rejected(403, "空间已切换")
                        view = snapshot(db, current_space(db, active) if active else None, slug)
                    revision = digest(view.decode() + ":" + str(CACHE.command("HGET", DYNAMIC, "rev:" + observed_space)))
                    if revision != previous:
                        yield ("event: changed\ndata: " + json.dumps({"revision": revision}) + "\n\n").encode()
                        previous = revision
                    else:
                        yield b": keepalive\n\n"
                    time.sleep(1)
                except (Rejected, sqlite3.Error):
                    yield b"event: revoked\ndata: {}\n\n"
                    break
        finally:
            CACHE.command("ZREM", NAMESPACE + "streams", lease)
    return stream()


def route(db, environ):
    method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
    locale = language(environ.get("HTTP_ACCEPT_LANGUAGE", ""))
    if method == "GET" and path == "/health":
        return 200, {"status": "ok", "version": VERSION, "release_tag": SOURCE_RELEASE if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", SOURCE_RELEASE) else None, "mode": "public", "host_control_enabled": False, "agent_updates": "manual", "cache": "redis" if CACHE.healthy() else "unavailable", "realtime": "sse" if CONFIG.get("enable_events") is True else "polling"}, []
    if method == "GET" and path == "/api/platform-load":
        raw = CACHE.command("GET", NAMESPACE + "platform-load")
        if raw:
            try:
                value = BOX.open("platform-load", raw)
                if time.time() - value["collected_at"] <= 180:
                    return 200, value, []
            except (ValueError, TypeError, KeyError):
                pass
        return 200, {"available": False}, []
    if method == "POST" and path == "/api/v1/report":
        return 200, receive(db, environ), []
    if method == "GET" and re.fullmatch(r"/api/public/status/" + LINK, path):
        return 200, snapshot(db, slug=path.rsplit("/", 1)[1], number=page_number(environ)), []
    session, headers = browser_session(db, environ, create=path == "/api/session" and method == "GET")
    if method == "GET" and path == "/api/session":
        space = db.execute("SELECT * FROM spaces WHERE id=?", (session["space_id"],)).fetchone()
        owned = db.execute("SELECT * FROM spaces WHERE owner=? ORDER BY created_at", (session["subject"],)).fetchall() if session["subject"] else []
        return 200, {"csrf": session["csrf"], "space": space_summary(space) if space else None, "manage_token": BOX.seal("manage", {"id": space["id"]}) if space else None, "ingest_url": ORIGIN + "/api/v1/report" if space else None, "spaces": [space_summary(row) for row in owned], "login": {"available": bool(ISSUER and CONFIG.get("oidc_client_id") and CONFIG.get("oidc_client_secret")), "authenticated": bool(session["subject"]), "label": session["label"]}}, headers
    if method == "GET" and path == "/auth/callback":
        query = parse_qs(environ.get("QUERY_STRING", ""))
        state, code = query.get("state", [""])[0], query.get("code", [""])[0]
        if not session.get("oauth_state") or not hmac.compare_digest(digest(state), session["oauth_state"]) or not session.get("oauth_expires") or session["oauth_expires"] < time.time() or not 1 <= len(code) <= 2048 or query.get("error"):
            raise Rejected(403, "登录验证已过期，请重新登录")
        db.execute("UPDATE sessions SET oauth_state=NULL,oauth_verifier=NULL,oauth_expires=NULL WHERE hash=?", (session["hash"],))
        tokens = identity_request("/oauth/token", {"grant_type": "authorization_code", "client_id": CONFIG["oidc_client_id"], "client_secret": CONFIG["oidc_client_secret"], "code": code, "redirect_uri": ORIGIN + "/auth/callback", "code_verifier": session["oauth_verifier"]})
        access = tokens.get("access_token", "")
        if not isinstance(access, str) or not 1 <= len(access) <= 8192 or "\r" in access or "\n" in access:
            raise Rejected(502, "身份服务未返回有效凭据")
        identity = identity_request("/oauth/userinfo", bearer=access)
        subject = identity.get("sub", "")
        if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
            raise Rejected(502, "身份服务未返回有效身份")
        token = secret("wms_")
        label = identity.get("name", translate("已登录用户", locale))
        owner = digest(ISSUER + "\0" + subject)
        db.execute("BEGIN IMMEDIATE")
        email = identity.get("email")
        verified_email = BOX.seal("verified-email:" + owner, email) if identity.get("email_verified") is True and isinstance(email, str) and len(email) <= 254 and "@" in email and "\r" not in email and "\n" not in email else None
        owned = db.execute("SELECT id FROM spaces WHERE owner=? ORDER BY created_at LIMIT 1", (owner,)).fetchone()
        db.execute("UPDATE sessions SET hash=?,csrf=?,subject=?,label=?,expires=?,space_id=COALESCE(space_id,?),verified_email=? WHERE hash=?", (digest(token), secrets.token_hex(32), owner, label[:80] if isinstance(label, str) else "已登录用户", int(time.time()) + 604800, owned["id"] if owned else None, verified_email, session["hash"]))
        db.commit()
        return 303, b"", [("Location", "/"), cookie_header(token)]
    if method == "GET" and path == "/api/devices":
        space = current_space(db, session)
        operation_guard(environ, space)
        return 200, snapshot(db, space, number=page_number(environ)), headers
    if method == "GET" and path == "/api/device-options":
        space = current_space(db, session)
        operation_guard(environ, space)
        rows = db.execute("SELECT id,name FROM devices WHERE space_id=? ORDER BY name,id", (space["id"],)).fetchall()
        return 200, {"devices": [dict(row) for row in rows]}, headers
    if method == "GET" and re.fullmatch(r"/api/devices/[a-f0-9]{32}", path):
        space = current_space(db, session)
        operation_guard(environ, space)
        row = db.execute("SELECT id FROM devices WHERE id=? AND space_id=?", (path.rsplit("/", 1)[1], space["id"])).fetchone()
        if not row:
            raise Rejected(404, "设备不存在")
        raw = CACHE.command("GET", DYNAMIC + ":snapshot:" + row["id"])
        if raw is None:
            raise Rejected(503, "实时快照暂不可用，请等待设备重新上报")
        try:
            report = BOX.open_report("report:" + row["id"], raw)
        except ValueError:
            raise Rejected(503, "实时快照校验失败，请等待设备重新上报") from None
        return 200, {"report": report, "read_only": True}, headers
    if method == "GET" and path == "/api/email":
        space = current_space(db, session)
        operation_guard(environ, space)
        address = BOX.open("notification-email:" + space["id"], space["email"]) if space["email"] else None
        return 200, {"email": address, "enabled": bool(space["notifications_enabled"]), "can_bind": bool(session.get("verified_email")), "delivery_available": bool(CONFIG.get("smtp_host") and CONFIG.get("smtp_user") and CONFIG.get("smtp_password") and CONFIG.get("smtp_from"))}, headers
    if method == "GET" and path == "/api/pages":
        space = current_space(db, session)
        operation_guard(environ, space)
        rows = db.execute("SELECT id,title,slug_ciphertext,enabled,selection FROM pages WHERE space_id=? ORDER BY id", (space["id"],)).fetchall()
        return 200, {"pages": [{"id": row["id"], "title": row["title"], "slug": BOX.open("stored-link:" + row["id"], row["slug_ciphertext"]), "enabled": bool(row["enabled"]), "selection": json.loads(row["selection"])} for row in rows]}, headers
    if method != "POST":
        raise Rejected(404, "接口不存在")
    write_guard(environ, session)
    limited("write:" + session["hash"], 120, 60)
    value = body(environ)
    if path == "/api/login":
        if not ISSUER or not CONFIG.get("oidc_client_id") or not CONFIG.get("oidc_client_secret"):
            raise Rejected(503, "此部署尚未配置登录服务，仍可使用匿名恢复口令")
        state = secrets.token_hex(32)
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        db.execute("UPDATE sessions SET oauth_state=?,oauth_verifier=?,oauth_expires=? WHERE hash=?", (digest(state), verifier, int(time.time()) + 300, session["hash"]))
        return 200, {"url": ISSUER + "/oauth/authorize?" + urlencode({"response_type": "code", "client_id": CONFIG["oidc_client_id"], "redirect_uri": ORIGIN + "/auth/callback", "scope": "openid profile email", "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})}, headers
    if path == "/api/logout":
        db.execute("DELETE FROM sessions WHERE hash=?", (session["hash"],))
        return 200, {"ok": True}, headers
    if path == "/api/spaces/create":
        limited("create:" + environ.get("REMOTE_ADDR", ""), 5, 3600)
        title = value.get("title", translate("我的监控空间", locale))
        automatic = value.get("auto_public_page", False)
        if type(automatic) is not bool:
            raise Rejected(400, "无效部署设置")
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 80:
            raise Rejected(400, "空间名称需要 1–80 个字符")
        recovery, bootstrap, space_id = secret("wmr_"), secret("wmb_"), secrets.token_hex(16)
        begin_browser_write(db, session)
        channel = ""  # Retained storage column for existing databases; no ingest links.
        db.execute("INSERT INTO spaces(id,title,recovery_hash,bootstrap_hash,owner,created_at,channel) VALUES(?,?,?,?,?,?,?)", (space_id, title.strip(), digest(recovery), digest(bootstrap), session["subject"], int(time.time()), channel))
        result = {"recovery": recovery, "bootstrap_key": bootstrap}
        if automatic:
            page_id = secrets.token_hex(16)
            slug = BOX.seal("public", {"id": page_id})
            db.execute("INSERT INTO pages VALUES(?,?,?,?,?,?,?)", (page_id, space_id, digest(slug), BOX.seal("stored-link:" + page_id, slug), title.strip(), 1, "[]"))
            db.execute("UPDATE spaces SET auto_page=? WHERE id=?", (page_id, space_id))
            result.update({"status_url": ORIGIN + "/status/" + slug, "manage_url": ORIGIN + "/manage/" + BOX.seal("manage", {"id": space_id}), "ingest_url": ORIGIN + "/api/v1/report"})
        db.execute("UPDATE sessions SET space_id=? WHERE hash=?", (space_id, session["hash"]))
        db.commit()
        return 200, result, headers
    if path == "/api/spaces/restore":
        limited("restore:" + environ.get("REMOTE_ADDR", ""), 10, 60)
        recovery = value.get("recovery", "")
        if not isinstance(recovery, str) or not re.fullmatch(r"wmr_[a-f0-9]{64}", recovery):
            raise Rejected(401, "恢复口令无效")
        row = db.execute("SELECT id FROM spaces WHERE recovery_hash=?", (digest(recovery),)).fetchone()
        if not row:
            raise Rejected(401, "恢复口令无效或已轮换")
        db.execute("UPDATE sessions SET space_id=? WHERE hash=?", (row["id"], session["hash"]))
        return 200, {"ok": True}, headers
    if path == "/api/spaces/select":
        row = db.execute("SELECT id FROM spaces WHERE id=? AND owner=?", (value.get("id"), session["subject"])).fetchone() if session["subject"] else None
        if not row:
            raise Rejected(403, "空间不属于当前登录账号")
        db.execute("UPDATE sessions SET space_id=? WHERE hash=?", (row["id"], session["hash"]))
        return 200, {"ok": True}, headers
    space = current_space(db, session)
    operation_guard(environ, space)
    if path == "/api/email/bind":
        active = begin_browser_write(db, session, space["id"])
        if not active["subject"] or not active["verified_email"]:
            raise Rejected(403, "请先正常登录并验证账号邮箱，再绑定通知")
        enabled = value.get("enabled", True)
        if type(enabled) is not bool:
            raise Rejected(400, "无效通知设置")
        if enabled and not (CONFIG.get("smtp_host") and CONFIG.get("smtp_user") and CONFIG.get("smtp_password") and CONFIG.get("smtp_from")):
            raise Rejected(503, "此部署尚未配置通知发送服务")
        address = BOX.open("verified-email:" + active["subject"], active["verified_email"])
        db.execute("UPDATE spaces SET email=?,notifications_enabled=?,notification_locale=? WHERE id=?", (BOX.seal("notification-email:" + space["id"], address), int(enabled), locale, space["id"]))
        db.execute("DELETE FROM notification_outbox WHERE space_id=? AND status='pending'", (space["id"],))
        db.execute("DELETE FROM notification_state WHERE device_id IN (SELECT id FROM devices WHERE space_id=?)", (space["id"],))
        db.commit()
        return 200, {"ok": True}, headers
    if path == "/api/email/unbind":
        begin_browser_write(db, session, space["id"])
        db.execute("UPDATE spaces SET email=NULL,notifications_enabled=0 WHERE id=?", (space["id"],))
        db.execute("DELETE FROM notification_outbox WHERE space_id=? AND status='pending'", (space["id"],))
        db.commit()
        return 200, {"ok": True}, headers
    if path == "/api/email/settings":
        enabled = value.get("enabled")
        if type(enabled) is not bool or (enabled and not space["email"]):
            raise Rejected(400, "请先绑定已验证邮箱")
        if enabled and not CONFIG.get("smtp_host"):
            raise Rejected(503, "通知发送服务暂不可用")
        begin_browser_write(db, session, space["id"])
        db.execute("UPDATE spaces SET notifications_enabled=?,notification_locale=? WHERE id=?", (int(enabled), locale, space["id"]))
        if not enabled:
            db.execute("DELETE FROM notification_outbox WHERE space_id=? AND status='pending'", (space["id"],))
        db.commit()
        return 200, {"ok": True}, headers
    if path == "/api/spaces/delete":
        if value.get("title") != space["title"]:
            raise Rejected(400, "请完整输入空间名称以删除")
        begin_browser_write(db, session, space["id"])
        device_ids = [row[0] for row in db.execute("SELECT id FROM devices WHERE space_id=?", (space["id"],))]
        db.execute("DELETE FROM sessions WHERE space_id=?", (space["id"],))
        db.execute("DELETE FROM pages WHERE space_id=?", (space["id"],))
        db.execute("DELETE FROM devices WHERE space_id=?", (space["id"],))
        db.execute("DELETE FROM spaces WHERE id=?", (space["id"],))
        db.commit()
        CACHE.remove_reports(DYNAMIC, device_ids, space["id"], forget_space=True)
        return 200, {"ok": True}, headers
    if path in ("/api/spaces/claim", "/api/recovery/rotate"):
        recovery, bootstrap = secret("wmr_"), secret("wmb_")
        active = begin_browser_write(db, session, space["id"])
        # Claim and revocation serialize with each other; never decide ownership
        # using the snapshot taken before acquiring the write transaction.
        space = db.execute("SELECT * FROM spaces WHERE id=?", (space["id"],)).fetchone()
        if not active or not space:
            raise Rejected(401, "会话已失效")
        if path.endswith("claim") and (not active["subject"] or (space["owner"] and space["owner"] != active["subject"])):
            raise Rejected(403, "需要正常登录，且不能领用其他账号的空间")
        owner = session["subject"] if path.endswith("claim") else space["owner"]
        db.execute("UPDATE spaces SET owner=?,recovery_hash=?,bootstrap_hash=? WHERE id=?", (owner, digest(recovery), digest(bootstrap), space["id"]))
        db.execute("DELETE FROM sessions WHERE space_id=? AND hash!=?", (space["id"], session["hash"]))
        db.commit()
        return 200, {"recovery": recovery, "bootstrap_key": bootstrap}, headers
    if path == "/api/bootstrap/rotate":
        key = secret("wmb_")
        begin_browser_write(db, session, space["id"])
        db.execute("UPDATE spaces SET bootstrap_hash=? WHERE id=?", (digest(key), space["id"]))
        db.commit()
        return 200, {"bootstrap_key": key}, headers
    if path == "/api/devices/revoke":
        begin_browser_write(db, session, space["id"])
        row = db.execute("SELECT id FROM devices WHERE id=? AND space_id=?", (value.get("id"), space["id"])).fetchone()
        db.execute("DELETE FROM devices WHERE id=? AND space_id=?", (value.get("id"), space["id"]))
        db.execute("UPDATE spaces SET revision=revision+1 WHERE id=?", (space["id"],))
        db.commit()
        if row:
            CACHE.remove_reports(DYNAMIC, [row["id"]], space["id"])
        return 200, {"ok": True}, headers
    if path.startswith("/api/pages/"):
        page_id = value.get("id")
        begin_browser_write(db, session, space["id"])
        if path == "/api/pages/create":
            page_id = secrets.token_hex(16)
        elif not isinstance(page_id, str) or not db.execute("SELECT id FROM pages WHERE id=? AND space_id=?", (page_id, space["id"])).fetchone():
            raise Rejected(404, "分享页不存在")
        if path in ("/api/pages/create", "/api/pages/update"):
            title, selection, enabled = value.get("title"), value.get("device_ids"), value.get("enabled", True)
            if not isinstance(title, str) or not 1 <= len(title.strip()) <= 80 or not isinstance(selection, list) or type(enabled) is not bool or any(not isinstance(item, str) for item in selection):
                raise Rejected(400, "请填写名称并选择自己的设备")
            owned = {row[0] for row in db.execute("SELECT id FROM devices WHERE space_id=?", (space["id"],))}
            if len(set(selection)) != len(selection) or not set(selection).issubset(owned):
                raise Rejected(403, "只能分享当前空间的设备")
            if path.endswith("create"):
                token = BOX.seal("public", {"id": page_id})
                db.execute("INSERT INTO pages VALUES(?,?,?,?,?,?,?)", (page_id, space["id"], digest(token), BOX.seal("stored-link:" + page_id, token), title.strip(), int(enabled), json.dumps(selection)))
            else:
                db.execute("UPDATE pages SET title=?,enabled=?,selection=? WHERE id=? AND space_id=?", (title.strip(), int(enabled), json.dumps(selection), page_id, space["id"]))
        elif path == "/api/pages/rotate":
            token = BOX.seal("public", {"id": page_id})
            db.execute("UPDATE pages SET slug_hash=?,slug_ciphertext=? WHERE id=? AND space_id=?", (digest(token), BOX.seal("stored-link:" + page_id, token), page_id, space["id"]))
        elif path == "/api/pages/delete":
            db.execute("DELETE FROM pages WHERE id=? AND space_id=?", (page_id, space["id"]))
        else:
            raise Rejected(404, "接口不存在")
        db.commit()
        return 200, {"ok": True}, headers
    raise Rejected(404, "接口不存在")


def application(environ, start_response):
    started = time.perf_counter_ns()
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    locale = language(environ.get("HTTP_ACCEPT_LANGUAGE", ""))
    headers = [("Cache-Control", "no-store, private"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("X-Robots-Tag", "noindex, nofollow"), ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]
    headers += [("Content-Language", locale), ("Vary", "Accept-Language")]
    try:
        if len(path) > 512 or len(environ.get("QUERY_STRING", "")) > 8192:
            raise Rejected(414, "请求地址过长")
        if method == "GET" and path.startswith("/manage/"):
            link_payload("manage", path.rsplit("/", 1)[1])
            path = "/"
        if method == "GET" and (path == "/" or re.fullmatch(r"/status/" + LINK, path) or path in ("/app.js", "/style.css")):
            file = "index.html" if path == "/" or path.startswith("/status/") else path[1:]
            payload = (WEB / file).read_bytes()
            if file == "index.html":
                payload = render_html(payload.decode(), locale).encode()
            content = "text/html; charset=utf-8" if file.endswith("html") else "text/javascript; charset=utf-8" if file.endswith("js") else "text/css; charset=utf-8"
            status, extra = 200, []
        elif method == "GET" and path == "/i18n.js":
            payload = ("window.WM_I18N=" + json.dumps({"locale": locale, "messages": EN if locale == "en" else {}}, ensure_ascii=False) + ";").encode()
            content, status, extra = "text/javascript; charset=utf-8", 200, []
        elif method == "GET" and path == "/openapi.json":
            payload = (WEB.parent / "openapi.json").read_bytes()
            content, status, extra = "application/json; charset=utf-8", 200, []
        elif method == "GET" and (path == "/events/space" or re.fullmatch(r"/events/status/" + LINK, path)):
            result = events(environ, path.rsplit("/", 1)[1] if path.startswith("/events/status/") else None)
            start_response("200 OK", headers + [("Content-Type", "text/event-stream"), ("X-Accel-Buffering", "no")])
            return result
        else:
            with database() as db:
                status, data, extra = route(db, environ)
            payload = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
            content = "application/json; charset=utf-8"
            if status == 200 and method == "GET" and (path == "/api/devices" or path.startswith("/api/public/status/")):
                etag = '"' + hashlib.sha256(payload).hexdigest() + '"'
                extra.append(("ETag", etag))
                if environ.get("HTTP_IF_NONE_MATCH") == etag:
                    status, payload = 304, b""
    except Rejected as error:
        status, payload, extra, content = error.status, json.dumps({"error": translate(error.message, locale)}, ensure_ascii=False).encode(), [], "application/json; charset=utf-8"
    except (sqlite3.Error, OSError):
        status, payload, extra, content = 503, json.dumps({"error": translate("存储暂时不可用", locale)}, ensure_ascii=False).encode(), [], "application/json; charset=utf-8"
    except Exception:
        # Never log request bodies, bearer tokens, recovery phrases or OAuth data.
        print("W Monitor Public: request rejected by internal validation", file=environ.get("wsgi.errors", __import__("sys").stderr))
        status, payload, extra, content = 500, json.dumps({"error": translate("无法处理此请求", locale)}, ensure_ascii=False).encode(), [], "application/json; charset=utf-8"
    if path.startswith("/api/") and path != "/api/platform-load":
        CACHE.record_request(NAMESPACE, status, (time.perf_counter_ns() - started) // 1000)
    start_response(f"{status} {HTTPStatus(status).phrase}", headers + extra + [("Content-Type", content), ("Content-Length", str(len(payload)))])
    return [payload]
