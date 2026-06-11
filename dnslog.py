#!/usr/bin/env python3
"""DNSlog Web Platform - Named log tail + Web UI + REST API + WebSocket"""

import asyncio
import configparser
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, jsonify, render_template, request
import websockets

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.path.join(APP_DIR, "dnslog.conf")

cfg = configparser.ConfigParser()
cfg.read(CONF_PATH)

DB_PATH = os.path.join(APP_DIR, cfg.get("database", "path", fallback="dnslog.db"))
NAMED_LOG = cfg.get("dnslog", "named_log", fallback="/var/log/named/query.log")
DOMAIN = cfg.get("dnslog", "domain", fallback="log.example.com")
SERVER_IP = cfg.get("dnslog", "server_ip", fallback="127.0.0.1")
WEB_PORT = cfg.getint("web", "port", fallback=9090)
WS_PORT = cfg.getint("web", "ws_port", fallback=9091)
ACCESS_CODE = cfg.get("web", "access_code", fallback="")
MAX_RECORDS = cfg.getint("database", "max_records", fallback=5000)
NAMED_IDLE_TIMEOUT = cfg.getint("dnslog", "named_idle_timeout", fallback=0)
MAX_WS_CLIENTS = 100

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # S10: 1MB body limit

db_lock = threading.Lock()

LOG_PATTERN = re.compile(
    r'(\d{2}-\w{3}-\d{4}\s+\d+:\d+:\d+\.\d+)\s+\w+:\s+client @0x[0-9a-f]+\s+([\d.]+)#\d+\s+\(([^)]+)\):\s+query:\s+(\S+)\s+IN\s+(\w+)'
)

ws_clients = set()
ws_lock = threading.Lock()
ws_loop = None
last_token_time = 0
named_lock = threading.RLock()
_exit_event = threading.Event()

# S1: auth rate limit
_auth_attempts = defaultdict(lambda: deque(maxlen=5))
_auth_lock = threading.Lock()


def _check_code(code):
    if not ACCESS_CODE:
        return False
    return hmac.compare_digest(code, ACCESS_CODE)


def require_access_code(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        code = request.headers.get("X-Access-Code", "").strip()
        if not _check_code(code):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def named_ensure_running():
    if NAMED_IDLE_TIMEOUT <= 0:
        return
    with named_lock:
        try:
            r = subprocess.run(["sudo", "systemctl", "is-active", "named"],
                               capture_output=True, text=True)
            if r.stdout.strip() != "active":
                subprocess.run(["sudo", "systemctl", "start", "named"],
                               capture_output=True)
                print("[NAMED] started (token requested)")
        except Exception as e:
            print(f"[NAMED] start error: {e}")


def named_stop():
    if NAMED_IDLE_TIMEOUT <= 0:
        return
    with named_lock:
        try:
            subprocess.run(["sudo", "systemctl", "stop", "named"],
                           capture_output=True)
            print("[NAMED] stopped (idle timeout)")
        except Exception as e:
            print(f"[NAMED] stop error: {e}")


def named_watchdog():
    global last_token_time
    if NAMED_IDLE_TIMEOUT <= 0:
        return
    while True:
        if _exit_event.wait(30):
            return
        with named_lock:
            if last_token_time > 0 and time.time() - last_token_time > NAMED_IDLE_TIMEOUT:
                try:
                    subprocess.run(["sudo", "systemctl", "stop", "named"],
                                   capture_output=True)
                    print("[NAMED] stopped (idle timeout)")
                except Exception as e:
                    print(f"[NAMED] stop error: {e}")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            qtype TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("UPDATE records SET domain=LOWER(domain) WHERE domain != LOWER(domain)")
    conn.commit()
    conn.close()


def trim_records():
    if MAX_RECORDS <= 0:
        return
    with db_lock:
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        if count > MAX_RECORDS:
            cutoff = conn.execute(
                "SELECT id FROM records ORDER BY id DESC LIMIT 1 OFFSET ?",
                (MAX_RECORDS,)
            ).fetchone()
            if cutoff:
                conn.execute("DELETE FROM records WHERE id <= ?", (cutoff['id'],))
                deleted = count - conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
                conn.commit()
                if deleted:
                    print(f"[DB] trimmed {deleted} records (limit {MAX_RECORDS})")
        conn.close()


def notify_ws_clients():
    if ws_loop is None:
        return
    with ws_lock:
        dead = []
        for ws in ws_clients:
            try:
                # S8: add timeout to prevent slow clients blocking event loop
                fut = asyncio.run_coroutine_threadsafe(
                    asyncio.wait_for(ws.send("update"), timeout=3), ws_loop
                )
                fut.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
            except Exception:
                dead.append(ws)
        for ws in dead:
            ws_clients.discard(ws)


def insert_record(domain, qtype_name, src_ip):
    with db_lock:
        try:
            conn = get_db()
            domain_lower = domain.lower()
            last = conn.execute(
                "SELECT id FROM records WHERE domain=? AND src_ip=? ORDER BY id DESC LIMIT 1",
                (domain_lower, src_ip)
            ).fetchone()
            if last:
                conn.close()
                return
            conn.execute(
                "INSERT INTO records (domain, qtype, src_ip) VALUES (?, ?, ?)",
                (domain_lower, qtype_name, src_ip),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] {e}")
    trim_records()
    notify_ws_clients()


def tail_named_log():
    print(f"[TAIL] watching {NAMED_LOG}")
    while True:
        proc = None
        try:
            proc = subprocess.Popen(
                ["tail", "-n", "+1", "-F", NAMED_LOG],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                line = line.strip()
                if DOMAIN.lower() not in line.lower():
                    continue
                match = LOG_PATTERN.search(line)
                if match:
                    src_ip = match.group(2)
                    domain = match.group(4).rstrip(".")
                    qtype = match.group(5)
                    insert_record(domain, qtype, src_ip)
        except Exception as e:
            print(f"[TAIL] error: {e}")
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    pass
            time.sleep(2)


async def websocket_handler(websocket):
    if not ACCESS_CODE:
        await websocket.close(1008, "no access code configured")
        return
    # S3: max connection limit
    with ws_lock:
        if len(ws_clients) >= MAX_WS_CLIENTS:
            await websocket.close(1013, "too many connections")
            return
    try:
        msg = await asyncio.wait_for(websocket.recv(), timeout=5)
        data = json.loads(msg)
        if not _check_code(data.get("code", "")):
            await websocket.close(1008, "unauthorized")
            return
    except Exception:
        await websocket.close(1008, "unauthorized")
        return
    with ws_lock:
        ws_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        with ws_lock:
            ws_clients.discard(websocket)


def start_websocket():
    global ws_loop
    loop = asyncio.new_event_loop()
    ws_loop = loop
    asyncio.set_event_loop(loop)

    async def serve():
        # S3/S12: ping keepalive to detect zombie connections
        async with websockets.serve(
            websocket_handler, "0.0.0.0", WS_PORT,
            ping_interval=20, ping_timeout=10,
            max_size=4096, close_timeout=5,
        ):
            print(f"[WS] listening on 0.0.0.0:{WS_PORT}")
            await asyncio.Future()

    loop.run_until_complete(serve())


@app.after_request
def add_security_headers(resp):
    if request.path in ("/", "/api/docs"):
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        # S2: security headers
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src ws: wss: 'self'"
    return resp


@app.route("/")
def index():
    return render_template("index.html", domain=DOMAIN)


@app.route("/api/docs")
def api_docs():
    return render_template("docs.html", domain=DOMAIN, web_port=WEB_PORT, ws_port=WS_PORT)


@app.route("/api/auth", methods=["POST"])
def api_auth():
    # S1: rate limit by IP
    ip = request.remote_addr
    with _auth_lock:
        now = time.time()
        attempts = _auth_attempts[ip]
        if len(attempts) >= 5 and now - attempts[0] < 60:
            return jsonify({"error": "rate limited"}), 429
        attempts.append(now)
    data = request.get_json(silent=True) or {}
    if _check_code(data.get("code", "").strip()):
        return jsonify({"ok": True})
    return jsonify({"error": "wrong code"}), 403


@app.route("/api/status")
@require_access_code
def api_status():
    named_active = False
    try:
        r = subprocess.run(["sudo", "systemctl", "is-active", "named"],
                           capture_output=True, text=True)
        named_active = r.stdout.strip() == "active"
    except Exception:
        pass
    remaining = 0
    if named_active and last_token_time > 0:
        remaining = max(0, int(NAMED_IDLE_TIMEOUT - (time.time() - last_token_time)))
    return jsonify({
        "named": named_active,
        "remaining": remaining,
        "timeout": NAMED_IDLE_TIMEOUT
    })


@app.route("/api/named/<action>", methods=["POST"])
@require_access_code
def api_named_control(action):
    if NAMED_IDLE_TIMEOUT <= 0:
        return jsonify({"error": "named auto-control disabled"}), 400
    global last_token_time
    if action == "start":
        named_ensure_running()
        last_token_time = time.time()
        return jsonify({"ok": True})
    elif action == "stop":
        named_stop()
        last_token_time = 0
        return jsonify({"ok": True})
    return jsonify({"error": "invalid action"}), 400


@app.route("/api/records")
@require_access_code
def api_records():
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"records": [], "total": 0})
    # S4: clamp page and limit
    page = max(1, request.args.get("page", 1, type=int))
    limit = max(1, min(200, request.args.get("limit", 20, type=int)))
    offset = (page - 1) * limit
    safe = token.replace("%", r"\%").replace("_", r"\_")
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) FROM records WHERE domain LIKE ? ESCAPE '\\'",
        (f"%.{safe}.%",)
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM records WHERE domain LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ? OFFSET ?",
        (f"%.{safe}.%", limit, offset),
    ).fetchall()
    conn.close()
    return jsonify({"records": [dict(r) for r in rows], "total": total})


@app.route("/api/records", methods=["DELETE"])
@require_access_code
def api_clear():
    token = request.args.get("token", "").strip()
    with db_lock:
        conn = get_db()
        if token:
            safe = token.replace("%", r"\%").replace("_", r"\_")
            conn.execute("DELETE FROM records WHERE domain LIKE ? ESCAPE '\\'", (f"%.{safe}.%",))
        else:
            conn.execute("DELETE FROM records")
        conn.commit()
        conn.close()
    notify_ws_clients()
    return jsonify({"ok": True})


@app.route("/api/random")
@require_access_code
def api_random():
    global last_token_time
    named_ensure_running()
    last_token_time = time.time()
    s = secrets.token_urlsafe(6)[:8]
    return jsonify({"domain": f"{s}.{DOMAIN}"})


def main():
    init_db()
    if not os.path.isfile(NAMED_LOG):
        print(f"[CONF] WARNING: named_log not found: {NAMED_LOG}")
    print(f"[CONF] domain={DOMAIN} max_records={MAX_RECORDS}")

    ws_thread = threading.Thread(target=start_websocket, daemon=True)
    ws_thread.start()

    tailer = threading.Thread(target=tail_named_log, daemon=True)
    tailer.start()

    if NAMED_IDLE_TIMEOUT > 0:
        wd = threading.Thread(target=named_watchdog, daemon=True)
        wd.start()
        print(f"[NAMED] watchdog active, idle timeout {NAMED_IDLE_TIMEOUT}s")

    print(f"[WEB] listening on 0.0.0.0:{WEB_PORT}")
    from gunicorn.app.base import BaseApplication
    class WSGIApp(BaseApplication):
        def load_config(self):
            self.cfg.set("bind", f"0.0.0.0:{WEB_PORT}")
            self.cfg.set("workers", 1)
            self.cfg.set("threads", 4)
            self.cfg.set("accesslog", "-")
        def load(self):
            return app
    WSGIApp().run()


if __name__ == "__main__":
    main()
