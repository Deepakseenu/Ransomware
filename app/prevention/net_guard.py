# prevention/net_guard.py
"""
NetGuard: network protections - auto-block repeated offenders, manage blocked list,
call dashboard API or local iptables as needed.
"""

import os
import json
import time
import logging
import threading
import subprocess
from datetime import datetime, timezone
from typing import Dict, Callable, Optional

import requests

logger = logging.getLogger("prevention.net_guard")

BLOCKED_FILE = os.environ.get("HP_BLOCKED_FILE", "/opt/honeypot_tools/blocked.json")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://127.0.0.1:5000")
BLOCK_COOLDOWN = int(os.environ.get("HP_BLOCK_COOLDOWN", "300"))  # seconds before re-blocking
AUTOBLOCK_ENABLED = os.environ.get("HP_AUTOBLOCK", "false").lower() in ("1","true","yes")

IPTABLES_CMD = os.environ.get("IPTABLES_CMD", "/usr/sbin/iptables")

def load_blocked_local():
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_blocked_local(data):
    try:
        with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False

class NetGuard:
    def __init__(self, helpers: Optional[Dict[str, Callable]] = None):
        self.helpers = helpers or {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self):
        # nothing heavy to start; kept for symmetry
        logger.info("NetGuard ready (autoblock=%s)", AUTOBLOCK_ENABLED)

    def stop(self):
        self._stop.set()

    def _local_block(self, ip: str):
        try:
            # check existing
            check = subprocess.run(["sudo", IPTABLES_CMD, "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
            if check.returncode == 0:
                return {"ip": ip, "blocked": True, "note": "already"}
            add = subprocess.run(["sudo", IPTABLES_CMD, "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
            if add.returncode == 0:
                return {"ip": ip, "blocked": True, "method": "iptables"}
            return {"ip": ip, "blocked": False, "stderr": add.stderr}
        except Exception as e:
            return {"error": str(e)}

    def _dashboard_block(self, ip: str, timeout=5):
        try:
            url = f"{DASHBOARD_URL.rstrip('/')}/api/block_ip"
            resp = requests.post(url, json={"ip": ip}, timeout=timeout)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def ensure_block(self, ip: str):
        """Main entry - attempt dashboard then fallback to local iptables."""
        res = None
        try:
            if AUTOBLOCK_ENABLED and "ensure_block" in self.helpers:
                # prefer calling monitor/dashboard helper if provided
                try:
                    res = self.helpers["ensure_block"](ip)
                except Exception:
                    res = None

            if not res:
                # try dashboard HTTP API
                res = self._dashboard_block(ip)
            if not res or ("error" in res and res.get("error")):
                # fallback to local iptables
                res2 = self._local_block(ip)
                # save to local blocked file
                data = load_blocked_local()
                data[ip] = {"ip": ip, "blocked": res2.get("blocked", False), "meta": res2, "last_blocked": datetime.now(timezone.utc).isoformat()}
                save_blocked_local(data)
                return {"fallback_local": res2}
            return {"dashboard": res}
        except Exception as e:
            return {"error": str(e)}
