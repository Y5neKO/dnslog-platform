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

app = Flask(__name__)

db_lock = threading.Lock()

LOG_PATTERN = re.compile(
    r'(\d{2}-\w{3}-\d{4}\s+\d+:\d+:\d+\.\d+)\s+\w+:\s+client @0x[0-9a-f]+\s+([\d.]+)#\d+\s+\(([^)]+)\):\s+query:\s+(\S+)\s+IN\s+(\w+)'
)

ws_clients = []
ws_lock = threading.Lock()
ws_loop = None


def require_access_code(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        code = request.headers.get("X-Access-Code", "").strip()
        if code != ACCESS_CODE:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


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
    resp = render_template("index.html")
    return resp.replace("<head>", "<head><meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>")


@app.route("/api/auth", methods=["POST"])
def api_auth():
    data = request.get_json(silent=True) or {}
    if data.get("code", "").strip() == ACCESS_CODE:
        return jsonify({"ok": True})
    return jsonify({"error": "wrong code"}), 403


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
    s = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return jsonify({"domain": f"{s}.{DOMAIN}"})


def main():
    init_db()
    print(f"[CONF] domain={DOMAIN} max_records={MAX_RECORDS}")

    ws_thread = threading.Thread(target=start_websocket, daemon=True)
    ws_thread.start()

    tailer = threading.Thread(target=tail_named_log, daemon=True)
    tailer.start()

    print(f"[WEB] listening on 0.0.0.0:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, threaded=True)


if __name__ == "__main__":
    main()
