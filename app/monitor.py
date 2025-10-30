#!/usr/bin/env python3
"""
monitor.py - Unified OS + Website monitor (final)
- Hybrid-safe base path: prefers /opt/honeypot_tools if writable, otherwise uses ~/Ransomware_Project/honeypot_data
- Watches website folder and OS folders concurrently
- Emits every action via Socket.IO (overview tab)
- Sandbox heuristics (YARA if present, entropy, filename patterns)
- Auto-quarantine: backup, copy to analysis, remove original, place decoy
- IP correlation from access logs -> block via iptables (optional)
- GeoIP lookup (ipinfo.io)
- Email alerts (SMTP) on suspicious/quarantine events
"""

from __future__ import annotations
import os
import sys
import time
import json
import shutil
import signal
import hashlib
import logging
import threading
import datetime
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from collections import deque, defaultdict, Counter
from typing import Optional, List, Dict

import requests
import socketio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# monitor.py (near other imports)

# prevention subsystems
try:
    from prevention import FileGuard, ProcessGuard, NetGuard, SandboxAnalyzer
except Exception as _e:
    FileGuard = ProcessGuard = NetGuard = SandboxAnalyzer = None



from datetime import datetime, timezone
datetime.now(timezone.utc)


# Optional libraries
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    yara = None
    YARA_AVAILABLE = False

# ---------------------------
# Hybrid base path selection
# ---------------------------
DEFAULT_OPT = "/opt/honeypot_tools"
FALLBACK_HOME = os.path.expanduser("~/Ransomware_Project/honeypot_data")
BASE_DIR = DEFAULT_OPT if os.access(DEFAULT_OPT, os.W_OK) else FALLBACK_HOME
os.makedirs(BASE_DIR, exist_ok=True)

# Paths derived from BASE_DIR
LOG_PATH = os.getenv("LOG_PATH", os.path.join(BASE_DIR, "logs", "events.log"))
BACKUP_DIR = os.getenv("BACKUP_DIR", os.path.join(BASE_DIR, "backup"))
QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", os.path.join(BASE_DIR, "quarantine"))
HONEYPOT_ANALYSIS_DIR = os.getenv("HONEYPOT_ANALYSIS_DIR", os.path.join(BASE_DIR, "honeypot_analysis"))
DECOY_DIR = os.getenv("DECOY_DIR", os.path.join(BASE_DIR, "decoys"))

# Ensure directories
for d in [os.path.dirname(LOG_PATH), BACKUP_DIR, QUARANTINE_DIR, HONEYPOT_ANALYSIS_DIR, DECOY_DIR]:
    os.makedirs(d, exist_ok=True)

# ---------------------------
# Config (tune via env)
# ---------------------------
WATCH_DIR = Path(os.getenv("HP_WATCH_DIR", "/var/www/html/college_clone_honeypot"))
USER_HOME = os.getenv("USER_HOME", os.path.expanduser("~"))
MONITORED_FOLDERS = [
    os.path.join(USER_HOME, d) for d in ["Desktop", "Downloads", "Documents", "Pictures"]
]
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "6"))
MOD_THRESHOLD = int(os.getenv("MOD_THRESHOLD", "30"))
CREATE_THRESHOLD = int(os.getenv("CREATE_THRESHOLD", "20"))
HIGH_ENTROPY_THRESHOLD = float(os.getenv("HIGH_ENTROPY_THRESHOLD", "7.5"))
YARA_RULE_PATH = os.getenv("YARA_RULE_PATH", str(Path(__file__).resolve().parent / "yara" / "yara_ransom.yar"))

# Email & IP blocking config
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
EMAIL_TO = os.getenv("EMAIL_TO", EMAIL_USER or "")
BLOCK_IPS = os.getenv("BLOCK_IPS", "true").lower() in ("1", "true", "yes")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

# Access logs to parse for IP correlation
ACCESS_LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
]

# Heuristics
SUSPICIOUS_EXTS = {'.locked', '.encrypted', '.crypt', '.enc', '.encrypt', '.lock'}
RANSOM_PATTERNS = ['README_DECRYPT', 'HOW_TO_DECRYPT', 'README_DECRYPTION', 'HOW_TO_RECOVER', 'README-FILES']
SMALL_FILE_MIN = 16

# ---------------------------
# Logging setup
# ---------------------------
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logger = logging.getLogger("monitor")
logger.setLevel(logging.INFO)
try:
    fh = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
except PermissionError:
    # fallback to stdout logging if file cannot be created
    logger.addHandler(logging.StreamHandler(sys.stdout))
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.info("Monitor starting (base dir=%s).", BASE_DIR)

# ---------------------------
# YARA rules load
# ---------------------------
yara_rules = None
if YARA_AVAILABLE and os.path.exists(YARA_RULE_PATH):
    try:
        yara_rules = yara.compile(YARA_RULE_PATH)
        logger.info("YARA loaded from %s", YARA_RULE_PATH)
    except Exception as e:
        logger.warning("YARA compile failed: %s", e)
else:
    logger.info("YARA not available or rule file missing; continuing without YARA.")

# ---------------------------
# SocketIO client to send events to dashboard
# ---------------------------
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://127.0.0.1:5000")
sio = socketio.Client(logger=False, engineio_logger=False, reconnection=False)
sio_lock = threading.Lock()
stop_event = threading.Event()

def safe_emit(event: str, payload: dict):
    with sio_lock:
        try:
            if sio.connected:
                sio.emit(event, payload, namespace="/")
            else:
                logger.debug("Socket not connected, skipping emit: %s", event)
        except Exception as e:
            logger.debug("Emit failed: %s", e)

def dashboard_reconnect_loop():
    while not stop_event.is_set():
        with sio_lock:
            if not sio.connected:
                try:
                    sio.connect(DASHBOARD_URL, namespaces=["/"], wait_timeout=5)
                    logger.info("Connected to dashboard at %s", DASHBOARD_URL)
                except Exception as e:
                    logger.debug("Dashboard connect failed: %s", e)
        stop_event.wait(5)

# ---------------------------
# Utilities
# ---------------------------
def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def write_event_struct(obj: dict):
    try:
        obj.setdefault("timestamp", now_iso())
        with open(LOG_PATH, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(obj, default=str) + "\n")
    except Exception as e:
        logger.debug("Failed to write structured event: %s", e)

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    ln = len(data)
    for count in freq.values():
        p = count / ln
        ent -= p * math.log2(p)
    return ent

def compute_hashes(path: str):
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception:
        return "", ""

def yara_scan_file(path: str):
    if yara_rules is None:
        return []
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 64)
        matches = yara_rules.match(data=data)
        return [m.rule for m in matches] if matches else []
    except Exception as e:
        logger.debug("YARA scan error %s: %s", path, e)
        return []

# ---------------------------
# Sliding counters & dedupe
# ---------------------------
class SlidingWindowCounter:
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.timestamps = deque()
        self.lock = threading.Lock()
    def add(self):
        now = time.time()
        with self.lock:
            self.timestamps.append(now)
            self._cleanup(now)
    def _cleanup(self, now):
        cutoff = now - self.window
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
    def count(self):
        now = time.time()
        with self.lock:
            self._cleanup(now)
            return len(self.timestamps)

create_counter = SlidingWindowCounter(WINDOW_SECONDS)
modify_counter = SlidingWindowCounter(WINDOW_SECONDS)
last_event_for_path = defaultdict(lambda: 0.0)
last_event_lock = threading.Lock()
DEDUPE_COOLDOWN = 0.5

def is_dedup(path: str) -> bool:
    now = time.time()
    with last_event_lock:
        last = last_event_for_path.get(path, 0.0)
        if now - last < DEDUPE_COOLDOWN:
            return True
        last_event_for_path[path] = now
        return False

# ---------------------------
# Quarantine / decoy / backup
# ---------------------------
def safe_copy(src: str, dest_dir: str) -> str:
    try:
        os.makedirs(dest_dir, exist_ok=True)
        basename = os.path.basename(src)
        dest = os.path.join(dest_dir, f"{int(time.time())}_{basename}")
        shutil.copy2(src, dest)
        return dest
    except Exception as e:
        logger.debug("safe_copy failed: %s", e)
        return ""


def create_decoy(target_path: str, reason: str = "quarantine_decoy"):
    """Create a decoy or replace a quarantined file safely."""
    try:
        _, ext = os.path.splitext(target_path)
        ext_low = ext.lower()
        content = b""
        if ext_low in {'.html', '.htm', '.php', '.txt', '.js', '.css'}:
            content = (
                "<html><head><title>Maintenance</title></head>"
                "<body><h2>Temporary Maintenance</h2>"
                "<p>Resource isolated for security analysis.</p></body></html>"
            ).encode("utf-8")
        try:
            with open(target_path, "wb") as f:
                f.write(content)
            os.chmod(target_path, 0o444)
            write_event_struct({
                "severity": "info",
                "reason": "decoy_created",
                "path": target_path,
                "decoy_reason": reason
            })
        except Exception as e:
            logger.debug("create_decoy write fail: %s", e)
    except Exception as e:
        logger.debug("create_decoy exception: %s", e)


def create_decoy_at_path(base_dir: str = "/opt/honeypot_tools/decoys",
                         name: str = "decoy_trigger.txt") -> str:
    """Standalone helper to create decoys for ransomware bait detection."""
    try:
        os.makedirs(base_dir, exist_ok=True)
        path = os.path.join(base_dir, name)
        with open(path, "w") as f:
            f.write("Ransomware decoy file. Do not modify.\n")
        os.chmod(path, 0o444)
        logger.info("Decoy created at %s", path)
        return path
    except Exception as e:
        logger.debug("create_decoy_at_path failed: %s", e)
        return ""


def backup_and_quarantine(src_path: str, reason: str) -> dict:
    """Backup, quarantine, and decoy replacement workflow."""
    meta = {"src": src_path, "reason": reason}
    try:
        if not os.path.exists(src_path):
            meta["note"] = "not_found"
            write_event_struct(meta)
            return meta

        md5, sha256 = compute_hashes(src_path)
        meta.update({"md5": md5, "sha256": sha256})

        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup_path = os.path.join(
            BACKUP_DIR, f"{int(time.time())}_{os.path.basename(src_path)}"
        )
        shutil.copy2(src_path, backup_path)
        meta["backup_path"] = backup_path

        honeypot_copy = safe_copy(src_path, HONEYPOT_ANALYSIS_DIR)
        meta["honeypot_copy"] = honeypot_copy

        try:
            os.remove(src_path)
        except Exception:
            try:
                tmp = src_path + f".quarantined.{int(time.time())}"
                shutil.move(src_path, tmp)
                meta["moved_to"] = tmp
            except Exception as e:
                meta["move_err"] = str(e)

        create_decoy(src_path, reason)
        meta["status"] = "quarantined"

        write_event_struct({"severity": "critical", "reason": reason, **meta})
    except Exception as e:
        meta["error"] = str(e)
        write_event_struct({"severity": "error", "reason": "quarantine_failed", **meta})
    return meta


# ---------------------------
# Prevention helpers mapping
# ---------------------------
def _emit_event_safe(ev: dict):
    """Emit to dashboard if possible, else write to log file."""
    try:
        if 'emit_alert' in globals() and callable(emit_alert):
            try:
                emit_alert(ev)
                return
            except Exception:
                pass
        if 'write_event' in globals() and callable(write_event):
            write_event(ev)
            return
        logger.info("PREVENTION_EVENT: %s", ev)
    except Exception:
        try:
            logger.exception("Emit fallback failed")
        except Exception:
            pass


helpers = {
    "backup_and_quarantine": backup_and_quarantine,
    "create_decoy_at_path": create_decoy_at_path,
    "emit_event": _emit_event_safe,
}



# ---------------------------
# IP correlation, block, geo
# ---------------------------
def tail_lines(path: str, max_lines: int = 2000) -> List[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b""
            while size > 0 and data.count(b"\n") <= max_lines:
                read_size = min(block, size)
                f.seek(size - read_size)
                data = f.read(read_size) + data
                size -= read_size
                if size <= 0:
                    break
            return data.decode(errors="ignore").splitlines()[-max_lines:]
    except Exception:
        return []

def correlate_ips(target_name: str, paths: List[str] = None) -> List[str]:
    if paths is None:
        paths = ACCESS_LOG_PATHS
    counter = Counter()
    for p in paths:
        if not os.path.exists(p):
            continue
        for ln in tail_lines(p, max_lines=1500):
            if target_name in ln:
                parts = ln.split()
                if parts:
                    ip = parts[0]
                    counter[ip] += 1
    if not counter:
        return []
    return [ip for ip, _ in counter.most_common(5)]

def block_ip_iptables(ip: str) -> dict:
    meta = {"ip": ip, "blocked": False}
    try:
        # try -C to check if present, otherwise append
        check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode == 0:
            meta["note"] = "already_blocked"
            meta["blocked"] = True
            return meta
        r = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
        if r.returncode == 0:
            meta["blocked"] = True
        else:
            meta["error"] = r.stderr.strip()
    except Exception as e:
        meta["error"] = str(e)
    return meta

def geoip(ip: str) -> Optional[dict]:
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if IPINFO_TOKEN:
            headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"
        r = requests.get(url, headers=headers, timeout=6)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

# ---------------------------
# Blocked IP persistence (monitor.py)
# ---------------------------
BLOCKED_PATH = os.path.join(BASE_DIR, "blocked.json")

def load_blocked():
    try:
        if os.path.exists(BLOCKED_PATH):
            with open(BLOCKED_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        logger.debug("Failed to load blocked.json")
    return {}

def save_blocked(data: dict):
    try:
        with open(BLOCKED_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        logger.warning("Failed to write blocked.json: %s", e)

# update handle_suspicious to persist blocked IPs
def handle_suspicious(path: str, reason: str, analysis: dict):
    event = {"timestamp": now_iso(), "reason": reason, "path": path, "analysis": analysis}
    meta = backup_and_quarantine(path, reason)
    event["quarantine"] = meta

    # correlate IPs and block
    ips = correlate_ips(os.path.basename(path))
    event["correlated_ips"] = ips
    blocked = []
    geo = {}
    blocked_store = load_blocked()

    for ip in ips:
        if BLOCK_IPS:
            bmeta = block_ip_iptables(ip)
            bmeta['when'] = now_iso()
            blocked.append(bmeta)
            # persist only if blocked True
            if bmeta.get("blocked"):
                ip_entry = blocked_store.get(ip, {})
                ip_entry.update({
                    "ip": ip,
                    "blocked": True,
                    "blocked_meta": bmeta,
                    "first_seen": ip_entry.get("first_seen") or now_iso(),
                    "last_blocked": now_iso()
                })
                g = geoip(ip)
                if g:
                    ip_entry['geo'] = g
                blocked_store[ip] = ip_entry
        else:
            g = geoip(ip)
            if g:
                geo[ip] = g

    event["blocked"] = blocked
    if geo:
        event["geo"] = geo

    # save blocked list to disk
    save_blocked(blocked_store)

    write_event_struct(event)
    safe_emit("new_event", {"type": "suspicious", **event})
    email_payload = build_alert_payload(event)
    send_email(email_payload["subject"], email_payload["html"], email_payload["text"])

# ---------------------------
# Email alerting
# ---------------------------

# ============================
# Email Configuration
# ============================
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587

# 🔹 Sender Gmail account (the one generating the App Password)
EMAIL_USER = "deepakseenur12@gmail.com"

# 🔹 Gmail App Password (NOT your login password)
EMAIL_PASS = "rwfq hvnw pusc jfvl"

# 🔹 Receiver email (where alerts will be sent)
EMAIL_TO = "deepakr3012@gmail.com"

def send_email(subject: str, html: str, text: str = "") -> dict:
    meta = {"sent": False}
    if not EMAIL_USER or not EMAIL_PASS or not EMAIL_TO:
        meta["error"] = "email_not_configured"
        logger.debug("Email not configured; skipping.")
        return meta
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_TO
        msg.attach(MIMEText(text or html, "plain"))
        msg.attach(MIMEText(html, "html"))
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
        server.ehlo()
        if EMAIL_PORT in (587, 25):
            server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, [EMAIL_TO], msg.as_string())
        server.quit()
        meta["sent"] = True
    except Exception as e:
        meta["error"] = str(e)
    return meta

def build_alert_payload(event: dict) -> dict:
    subj = f"[Honeypot] {event.get('reason','suspicious')} - {os.path.basename(event.get('path',''))}"
    html = f"<h3>Honeypot Alert</h3><pre>{json.dumps(event, indent=2, default=str)}</pre>"
    text = f"Honeypot Alert\n\n{json.dumps(event, indent=2, default=str)}"
    return {"subject": subj, "html": html, "text": text}

def handle_suspicious(path: str, reason: str, analysis: dict):
    event = {"timestamp": now_iso(), "reason": reason, "path": path, "analysis": analysis}
    meta = backup_and_quarantine(path, reason)
    event["quarantine"] = meta
    # correlate IPs
    ips = correlate_ips(os.path.basename(path))
    event["correlated_ips"] = ips
    blocked = []
    geo = {}
    for ip in ips:
        if BLOCK_IPS:
            bmeta = block_ip_iptables(ip)
            blocked.append(bmeta)
        g = geoip(ip)
        if g:
            geo[ip] = g
    event["blocked"] = blocked
    event["geo"] = geo
    write_event_struct(event)
    safe_emit("new_event", {"type": "suspicious", **event})
    email_payload = build_alert_payload(event)
    send_email(email_payload["subject"], email_payload["html"], email_payload["text"])

# ---------------------------
# Sandbox heuristics
# ---------------------------
def sandbox_analysis(path: str) -> dict:
    r = {"suspicious": False, "reasons": [], "score": 0.0}
    try:
        if not os.path.exists(path):
            r["reasons"].append("not_found"); return r
        base = os.path.basename(path).upper()
        for p in RANSOM_PATTERNS:
            if p in base:
                r["reasons"].append("ransom_name"); r["score"] += 5.0
        _, ext = os.path.splitext(path)
        if ext.lower() in SUSPICIOUS_EXTS:
            r["reasons"].append("suspicious_ext"); r["score"] += 5.0
        if yara_rules:
            try:
                matches = yara_scan_file(path)
                if matches:
                    r["reasons"].append(f"yara:{','.join(matches)}"); r["score"] += 6.0
            except Exception:
                pass
        try:
            size = os.path.getsize(path)
            if size >= SMALL_FILE_MIN:
                with open(path, "rb") as f:
                    chunk = f.read(4096)
                ent = shannon_entropy(chunk)
                r["reasons"].append(f"entropy={ent:.2f}")
                if ent > HIGH_ENTROPY_THRESHOLD:
                    r["score"] += 4.0
            else:
                r["reasons"].append("tiny_file")
        except Exception:
            r["reasons"].append("entropy_err")
        if r["score"] >= 6.0:
            r["suspicious"] = True
    except Exception:
        r["reasons"].append("analysis_failed")
    return r

# ---------------------------
# Watchdog handlers (emit every action)
# ---------------------------
class BaseHandler(FileSystemEventHandler):
    def emit_action(self, action: str, path: str, extra: dict = None):
        obj = {"type": "action", "action": action, "path": path, "timestamp": now_iso()}
        if extra:
            obj.update(extra)
        write_event_struct(obj)
        safe_emit("new_event", obj)

class WebHandler(BaseHandler):
    def on_created(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_dedup(path): return
        create_counter.add()
        self.emit_action("web_created", path)
        analysis = sandbox_analysis(path)
        self.emit_action("web_created_analysis", path, {"analysis": analysis})
        if analysis.get("suspicious"):
            handle_suspicious(path, "web_suspicious", analysis)
        else:
            copy = safe_copy(path, HONEYPOT_ANALYSIS_DIR)
            if copy: self.emit_action("web_copied_for_analysis", path, {"copy": copy})

    def on_modified(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_dedup(path): return
        modify_counter.add()
        self.emit_action("web_modified", path)
        if modify_counter.count() >= MOD_THRESHOLD:
            self.emit_action("mass_modification_detected", path, {"count": modify_counter.count()})
        analysis = sandbox_analysis(path)
        self.emit_action("web_modified_analysis", path, {"analysis": analysis})
        if analysis.get("suspicious"):
            handle_suspicious(path, "web_mod_suspicious", analysis)

class OSHandler(BaseHandler):
    def on_created(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_dedup(path): return
        create_counter.add()
        self.emit_action("os_created", path)
        analysis = sandbox_analysis(path)
        self.emit_action("os_created_analysis", path, {"analysis": analysis})
        if analysis.get("suspicious"):
            handle_suspicious(path, "os_created_suspicious", analysis)

    def on_modified(self, event):
        if event.is_directory: return
        path = os.path.abspath(event.src_path)
        if is_dedup(path): return
        self.emit_action("os_modified", path)
        _, ext = os.path.splitext(path)
        if ext.lower() in [".jpg", ".png", ".pdf", ".docx", ".doc"]:
            b = safe_copy(path, BACKUP_DIR)
            if b: self.emit_action("os_proactive_backup", path, {"backup": b})
        analysis = sandbox_analysis(path)
        self.emit_action("os_modified_analysis", path, {"analysis": analysis})
        if analysis.get("suspicious"):
            handle_suspicious(path, "os_mod_suspicious", analysis)

# ---------------------------
# Runner & lifecycle
# ---------------------------
create_counter = SlidingWindowCounter(WINDOW_SECONDS)
modify_counter = SlidingWindowCounter(WINDOW_SECONDS)
observers = []
threads: List[threading.Thread] = []

def start_watchers():
    web_obs = Observer()
    web_obs.schedule(WebHandler(), str(WATCH_DIR), recursive=True)
    web_obs.start()
    observers.append(web_obs)
    logger.info("Watching web dir: %s", WATCH_DIR)
    os_obs = Observer()
    os_handler = OSHandler()
    for folder in MONITORED_FOLDERS:
        try:
            if os.path.exists(folder):
                os_obs.schedule(os_handler, folder, recursive=True)
                logger.info("Watching OS folder: %s", folder)
            else:
                logger.debug("OS folder not present: %s", folder)
        except Exception as e:
            logger.debug("Failed to schedule %s: %s", folder, e)
    os_obs.start()
    observers.append(os_obs)

def stop_all():
    logger.info("Stopping monitors...")
    stop_event.set()
    for obs in observers:
        try: obs.stop()
        except: pass
    for obs in observers:
        try: obs.join(timeout=2)
        except: pass
    with sio_lock:
        try:
            if sio.connected: sio.disconnect()
        except: pass
    logger.info("Stopped.")

def handle_sig(sig, frame):
    logger.info("Signal %s received.", sig)
    stop_all()

signal.signal(signal.SIGINT, handle_sig)
signal.signal(signal.SIGTERM, handle_sig)

def main():
    t = threading.Thread(target=dashboard_reconnect_loop, daemon=True)
    t.start()
    threads.append(t)

    start_watchers()
    logger.info("Monitor running. Press Ctrl-C to stop.")

    # ---------------------------
    # Start prevention subsystems (conservative defaults)
    # ---------------------------
    file_guard = None
    proc_guard = None
    net_guard = None
    sandbox_analyzer = None

    try:
        if FileGuard:
            watch_dirs = [str(WATCH_DIR)] + MONITORED_FOLDERS
            file_guard = FileGuard(watch_dirs=watch_dirs, helpers=helpers)
            file_guard.start()
            logger.info("FileGuard started.")

        if ProcessGuard:
            proc_guard = ProcessGuard(
                helpers=helpers,
                terminate_on_detect=False,
                whitelist_basenames=["sshd", "systemd", "nginx", "apache2", "python", "bash"]
            )
            proc_guard.start()
            logger.info("ProcessGuard started.")

        if NetGuard:
            net_guard = NetGuard(helpers=helpers)
            net_guard.start()
            logger.info("NetGuard started.")

        if SandboxAnalyzer:
            sandbox_analyzer = SandboxAnalyzer(
                yara_scan_callable=(yara_scan if 'yara_scan' in globals() else None)
            )
            logger.info("SandboxAnalyzer ready.")

        # expose to globals so other parts can reference them if needed
        globals().update({
            "file_guard": file_guard,
            "proc_guard": proc_guard,
            "net_guard": net_guard,
            "sandbox_analyzer": sandbox_analyzer
        })

    except Exception as e:
        logger.exception("Failed to start prevention subsystems: %s", e)

    # ---------------------------
    # Main loop
    # ---------------------------
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Shutting down...")
    finally:
        stop_all()

        # Graceful shutdown for prevention subsystems
        try:
            if 'file_guard' in globals() and file_guard:
                file_guard.stop()
        except Exception:
            pass

        try:
            if 'proc_guard' in globals() and proc_guard:
                proc_guard.stop()
        except Exception:
            pass

        try:
            if 'net_guard' in globals() and net_guard:
                net_guard.stop()
        except Exception:
            pass


if __name__ == "__main__":
    main()
