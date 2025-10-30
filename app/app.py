#!/usr/bin/env python3
"""
app.py - Full Flask + Socket.IO dashboard backend (enhanced)
- Preserves all existing functionality
- Adds new routes for stats, system, process, and network info
"""

import argparse
import json
import logging
import os
import shutil
import threading
import time
import subprocess
import requests
import psutil
from collections import deque
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template
from flask_socketio import SocketIO, emit

# ---------------------------
# Directory Setup
# ---------------------------
DEFAULT_OPT = "/opt/honeypot_tools"
FALLBACK_HOME = os.path.expanduser("~/Ransomware_Project/honeypot_data")
BASE_DIR = DEFAULT_OPT if os.access(DEFAULT_OPT, os.W_OK) else FALLBACK_HOME

LOG_DIR = os.path.join(BASE_DIR, "logs")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")
LOG_FILE_DEFAULT = os.path.join(LOG_DIR, "events.log")
BLOCKED_FILE = os.path.join(BASE_DIR, "blocked.json")

for d in [LOG_DIR, QUARANTINE_DIR, BACKUP_DIR, os.path.dirname(BLOCKED_FILE)]:
    os.makedirs(d, exist_ok=True)

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dashboard")

# ---------------------------
# Flask + SocketIO
# ---------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "secret!")
socketio = SocketIO(app, cors_allowed_origins="*", logger=False, engineio_logger=False)

# ---------------------------
# Globals
# ---------------------------
MAX_RECENT = 2000
TAIL_POLL = 1.0
recent_events = deque(maxlen=MAX_RECENT)
recent_lock = threading.Lock()
tailer_thread = None
IPTABLES_CMD = "/usr/sbin/iptables"

# ---------------------------
# Helper Functions
# ---------------------------
def load_blocked():
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    return {x["ip"]: x for x in data if isinstance(x, dict) and "ip" in x}
    except Exception as e:
        logger.warning("load_blocked failed: %s", e)
    return {}

def save_blocked(data: dict):
    try:
        with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.warning("save_blocked failed: %s", e)
        return False

def safe_json_response(data, status=200):
    try:
        return app.response_class(
            response=json.dumps(data, indent=2, default=str),
            status=status,
            mimetype="application/json"
        )
    except Exception:
        return jsonify({"error": "internal serialization error"}), 500

def safe_parse_json_line(line: str):
    try:
        return json.loads(line)
    except Exception:
        return {"raw": line.strip(),
                "ts": datetime.now(timezone.utc).isoformat()}

# ---------------------------
# Tailer Thread
# ---------------------------
class JSONTailer(threading.Thread):
    def __init__(self, path, poll=1.0):
        super().__init__(daemon=True)
        self.path = path
        self.poll = poll
        self._stop = threading.Event()
        self.pos = 0

    def run(self):
        logger.info(f"Tailer started for {self.path}")
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", errors="replace") as fh:
                    fh.seek(0, os.SEEK_END)
                    self.pos = fh.tell()
        except Exception as e:
            logger.warning("Tailer init error: %s", e)

        while not self._stop.is_set():
            try:
                if not os.path.exists(self.path):
                    time.sleep(self.poll)
                    continue
                with open(self.path, "r", errors="replace") as fh:
                    fh.seek(self.pos)
                    for line in fh:
                        self.pos = fh.tell()
                        ev = safe_parse_json_line(line)
                        with recent_lock:
                            recent_events.append(ev)
                        socketio.emit("new_event", ev, namespace="/")
            except Exception as e:
                logger.debug("Tailer error: %s", e)
            time.sleep(self.poll)

    def stop(self):
        self._stop.set()

def start_tailer(log_path):
    global tailer_thread
    if tailer_thread and tailer_thread.is_alive():
        return
    tailer_thread = JSONTailer(log_path, poll=TAIL_POLL)
    tailer_thread.start()

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/events")
def api_events():
    with recent_lock:
        data = list(reversed(list(recent_events)))[:500]
    return safe_json_response(data)

@app.route("/api/list_quarantine")
def api_list_quarantine():
    files = [os.path.join(root, f)
             for root, _, fnames in os.walk(QUARANTINE_DIR)
             for f in fnames]
    return safe_json_response(sorted(files))

@app.route("/api/list_backup")
def api_list_backup():
    files = [os.path.join(root, f)
             for root, _, fnames in os.walk(BACKUP_DIR)
             for f in fnames]
    return safe_json_response(sorted(files))

@app.route("/api/blocked_ips")
def api_blocked_ips():
    blocked = load_blocked()
    entries = list(blocked.values())
    entries.sort(key=lambda x: x.get("last_blocked", ""), reverse=True)
    return safe_json_response(entries)

# ---------------------------
# 🧠 New System & Dashboard APIs
# ---------------------------
@app.route("/api/system_health")
def api_system_health():
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        uptime = time.time() - psutil.boot_time()
        return safe_json_response({
            "cpu": cpu,
            "memory": mem,
            "uptime": round(uptime, 1)
        })
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/process_list")
def api_process_list():
    try:
        procs = []
        for p in psutil.process_iter(attrs=["pid", "name", "username", "cpu_percent", "memory_percent"]):
            procs.append(p.info)
        procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
        return safe_json_response(procs[:20])
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/network_stats")
def api_network_stats():
    try:
        stats = psutil.net_io_counters()
        return safe_json_response({
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv
        })
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/stats_summary")
def api_stats_summary():
    blocked = load_blocked()
    q_files = len(os.listdir(QUARANTINE_DIR))
    b_files = len(os.listdir(BACKUP_DIR))
    total_events = len(recent_events)
    return safe_json_response({
        "total_events": total_events,
        "blocked_ips": len(blocked),
        "quarantine_count": q_files,
        "backup_count": b_files
    })

@app.route("/api/live_status")
def api_live_status():
    """Aggregated data for dashboard main cards"""
    blocked = load_blocked()
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory().percent
    uptime = time.time() - psutil.boot_time()
    return safe_json_response({
        "cpu": cpu,
        "memory": mem,
        "blocked_ips": len(blocked),
        "recent_events": len(recent_events),
        "uptime": round(uptime, 1)
    })

# ---------------------------
# Socket.IO
# ---------------------------
@socketio.on("connect")
def on_connect():
    logger.info("Client connected")
    with recent_lock:
        for e in list(recent_events)[-100:]:
            emit("new_event", e)

@socketio.on("new_event")
def on_new_event(data):
    with recent_lock:
        recent_events.append(data)
    emit("new_event", data, broadcast=True)

# ---------------------------
# Runner
# ---------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=5000, type=int)
    parser.add_argument("--log", default=LOG_FILE_DEFAULT)
    args = parser.parse_args()

    log_path = args.log

    if os.path.exists(log_path):
        try:
            with open(log_path, "r", errors="replace") as fh:
                lines = fh.read().splitlines()[-500:]
            for ln in lines:
                ev = safe_parse_json_line(ln)
                with recent_lock:
                    recent_events.append(ev)
        except Exception as e:
            logger.warning("Failed to preload events: %s", e)

    start_tailer(log_path)
    logger.info(f"Dashboard running on {args.host}:{args.port} (log={log_path})")
    socketio.run(app, host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
