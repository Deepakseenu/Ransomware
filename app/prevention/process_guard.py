# prevention/process_guard.py
"""
ProcessGuard: monitors processes, detects suspicious names/behavior,
terminates and isolates malicious processes, emits prevention events.
"""

import psutil
import time
import logging
import threading
import os
import signal
from datetime import datetime
from typing import List, Dict, Callable, Optional

logger = logging.getLogger("prevention.process_guard")

# Tunables
SCAN_INTERVAL = int(os.environ.get("HP_PROC_SCAN_INTERVAL", "5"))
CPU_SPIKE_THRESHOLD = float(os.environ.get("HP_CPU_SPIKE", "80.0"))  # percent
MEM_SPIKE_THRESHOLD = float(os.environ.get("HP_MEM_SPIKE", "80.0"))  # percent
SUSPICIOUS_NAMES = {"nmap", "metasploit", "msfconsole", "sqlmap", "hydra", "john", "msf", "nc", "netcat"}

class ProcessGuard:
    def __init__(self, helpers: Optional[Dict[str, Callable]] = None,
                 terminate_on_detect: bool = True,
                 whitelist_basenames: Optional[List[str]] = None):
        self.helpers = helpers or {}
        self.terminate_on_detect = terminate_on_detect
        self.whitelist = set(whitelist_basenames or [])
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("ProcessGuard started")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _emit(self, event):
        try:
            if "emit_event" in self.helpers:
                try:
                    self.helpers["emit_event"](event)
                except Exception:
                    pass
            logger.info("PG_EVENT: %s", event)
        except Exception:
            pass

    def _is_suspicious_proc(self, p: psutil.Process):
        try:
            name = p.name().lower()
            if name in self.whitelist:
                return False
            # simple name match
            for s in SUSPICIOUS_NAMES:
                if s in name:
                    return True
            # resource spike
            cpu = p.cpu_percent(interval=0.1)
            mem = p.memory_percent()
            if cpu > CPU_SPIKE_THRESHOLD or mem > MEM_SPIKE_THRESHOLD:
                return True
        except Exception:
            return False
        return False

    def _take_action(self, p: psutil.Process):
        info = {}
        try:
            info["pid"] = p.pid
            info["name"] = p.name()
            info["cmdline"] = p.cmdline()
            info["create_time"] = datetime.utcfromtimestamp(p.create_time()).isoformat()
        except Exception:
            pass

        # attempt graceful terminate then kill
        try:
            if self.terminate_on_detect:
                try:
                    p.terminate()
                    gone, alive = psutil.wait_procs([p], timeout=3)
                    if alive:
                        p.kill()
                except Exception:
                    try:
                        os.kill(p.pid, signal.SIGKILL)
                    except Exception:
                        pass
                info["action"] = "killed"
            else:
                # suspend instead
                try:
                    p.suspend()
                    info["action"] = "suspended"
                except Exception:
                    info["action"] = "suspend_failed"
        except Exception as e:
            info["action_error"] = str(e)

        # Optionally: dump memory, stacktrace (requires elevated privileges)
        event = {"type": "prevention", "subtype": "process_action", "detail": info, "timestamp": datetime.utcnow().isoformat()}
        self._emit(event)
        return info

    def _loop(self):
        while not self._stop.is_set():
            try:
                for p in psutil.process_iter(attrs=["pid", "name"]):
                    try:
                        if self._is_suspicious_proc(p):
                            self._take_action(p)
                    except psutil.NoSuchProcess:
                        continue
                    except Exception:
                        continue
            except Exception as e:
                logger.debug("processguard loop error: %s", e)
            time.sleep(SCAN_INTERVAL)
