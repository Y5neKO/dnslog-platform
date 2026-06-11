#!/usr/bin/env python3
"""DNSlog Web Platform - Named log tail + Web UI + REST API + WebSocket"""

import asyncio
import configparser
import json
import os
import random
import re
import sqlite3
import string
import subprocess
import threading
import time
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

app = Flask(__name__)

db_lock = threading.Lock()

LOG_PATTERN = re.compile(
    r'(\d{2}-\w{3}-\d{4}\s+\d+:\d+:\d+\.\d+)\s+\w+:\s+client @0x[0-9a-f]+\s+([\d.]+)#\d+\s+\(([^)]+)\):\s+query:\s+(\S+)\s+IN\s+(\w+)'
)

ws_clients = []
ws_lock = threading.Lock()
ws_loop = None
last_token_time = 0
named_lock = threading.Lock()


def require_access_code(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        code = request.args.get("code", "").strip() or request.headers.get("X-Access-Code", "").strip()
        if code != ACCESS_CODE:
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
        time.sleep(30)
        with named_lock:
            if last_token_time > 0 and time.time() - last_token_time > NAMED_IDLE_TIMEOUT:
                named_stop()


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
    conn.execute("UPDATE records SET domain=LOWER(domain)")
    conn.commit()
    conn.close()


def trim_records():
    if MAX_RECORDS <= 0:
        return
    with db_lock:
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        if count > MAX_RECORDS:
            conn.execute(
                "DELETE FROM records WHERE id NOT IN (SELECT id FROM records ORDER BY id DESC LIMIT ?)",
                (MAX_RECORDS,)
            )
            deleted = count - conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            conn.commit()
            if deleted:
                print(f"[DB] trimmed {deleted} records (limit {MAX_RECORDS})")
        conn.close()


def notify_ws_clients():
    with ws_lock:
        dead = []
        for ws in ws_clients:
            try:
                asyncio.run_coroutine_threadsafe(ws.send("update"), ws_loop)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in ws_clients:
                ws_clients.remove(ws)


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
            time.sleep(2)


async def websocket_handler(websocket, path=None):
    try:
        msg = await asyncio.wait_for(websocket.recv(), timeout=5)
        data = json.loads(msg)
        if data.get("code") != ACCESS_CODE:
            await websocket.close(1008, "unauthorized")
            return
    except Exception:
        await websocket.close(1008, "unauthorized")
        return
    with ws_lock:
        ws_clients.append(websocket)
    try:
        await websocket.wait_closed()
    finally:
        with ws_lock:
            if websocket in ws_clients:
                ws_clients.remove(websocket)


def start_websocket():
    global ws_loop
    loop = asyncio.new_event_loop()
    ws_loop = loop
    asyncio.set_event_loop(loop)

    async def serve():
        async with websockets.serve(websocket_handler, "0.0.0.0", WS_PORT):
            print(f"[WS] listening on 0.0.0.0:{WS_PORT}")
            await asyncio.Future()

    loop.run_until_complete(serve())


@app.route("/")
def index():
    resp = render_template("index.html", domain=DOMAIN)
    return resp.replace("<head>", "<head><meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>")


@app.route("/api/docs")
def api_docs():
    return render_template("docs.html", domain=DOMAIN, web_port=WEB_PORT, ws_port=WS_PORT)


@app.route("/api/auth", methods=["POST"])
def api_auth():
    data = request.get_json(silent=True) or {}
    if data.get("code", "").strip() == ACCESS_CODE:
        return jsonify({"ok": True})
    return jsonify({"error": "wrong code"}), 403


@app.route("/api/status")
@require_access_code
def api_status():
    named_active = False
    remaining = 0
    if NAMED_IDLE_TIMEOUT > 0:
        try:
            r = subprocess.run(["sudo", "systemctl", "is-active", "named"],
                               capture_output=True, text=True)
            named_active = r.stdout.strip() == "active"
        except Exception:
            pass
        if named_active and last_token_time > 0:
            remaining = max(0, int(NAMED_IDLE_TIMEOUT - (time.time() - last_token_time)))
    else:
        try:
            r = subprocess.run(["sudo", "systemctl", "is-active", "named"],
                               capture_output=True, text=True)
            named_active = r.stdout.strip() == "active"
        except Exception:
            pass
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
        return jsonify([])
    limit = request.args.get("limit", 200, type=int)
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM records WHERE domain LIKE ? ORDER BY id DESC LIMIT ?",
        (f"%.{token}.%", limit),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/records", methods=["DELETE"])
@require_access_code
def api_clear():
    token = request.args.get("token", "").strip()
    conn = get_db()
    if token:
        conn.execute("DELETE FROM records WHERE domain LIKE ?", (f"%.{token}.%",))
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
    s = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return jsonify({"domain": f"{s}.{DOMAIN}"})


def main():
    init_db()
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
