# prevention/file_guard.py
"""
FileGuard: monitors specified directories (website + user folders)
- Maintains baseline checksums
- On suspicious change: backup + quarantine + restore from last good snapshot
- Emits events via emit_event helper
- Uses existing monitor helpers if provided (backup_and_quarantine, create_decoy_at_path)
"""

import os
import json
import time
import shutil
import hashlib
import logging
import threading
from datetime import datetime
from typing import List, Dict, Callable, Optional

logger = logging.getLogger("prevention.file_guard")

DEFAULT_BASELINE = os.environ.get("HP_BASELINE", "/opt/honeypot_tools/baseline_checksums.json")
DEFAULT_QUARANTINE_DIR = os.environ.get("HP_QUARANTINE", "/opt/honeypot_tools/quarantine")
DEFAULT_BACKUP_DIR = os.environ.get("HP_BACKUP", "/opt/honeypot_tools/backup")

# Tunables
INTEGRITY_INTERVAL = int(os.environ.get("HP_INTEGRITY_INTERVAL", "30"))  # seconds
MASS_CHANGE_THRESHOLD = int(os.environ.get("HP_MASS_CHANGE_THRESHOLD", "8"))

def sha256(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

class FileGuard:
    def __init__(self,
                 watch_dirs: List[str],
                 baseline_path: Optional[str] = None,
                 quarantine_dir: Optional[str] = None,
                 backup_dir: Optional[str] = None,
                 helpers: Optional[Dict[str, Callable]] = None):
        self.watch_dirs = watch_dirs
        self.baseline_path = baseline_path or DEFAULT_BASELINE
        self.quarantine_dir = quarantine_dir or DEFAULT_QUARANTINE_DIR
        self.backup_dir = backup_dir or DEFAULT_BACKUP_DIR
        self.helpers = helpers or {}
        self._stop = threading.Event()
        self._thread = None
        self._baseline = {}  # path -> hash
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        self._load_or_build_baseline()

    def _load_or_build_baseline(self):
        try:
            if os.path.exists(self.baseline_path):
                with open(self.baseline_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._baseline = data.get("files", {}) if isinstance(data, dict) else {}
            if not self._baseline:
                # build baseline
                self._baseline = {}
                for root in self.watch_dirs:
                    for dirpath, _, files in os.walk(root):
                        for fn in files:
                            fp = os.path.join(dirpath, fn)
                            try:
                                if os.path.isfile(fp):
                                    self._baseline[fp] = sha256(fp)
                            except Exception:
                                pass
                self._persist_baseline()
                logger.info("FileGuard baseline built with %d entries", len(self._baseline))
        except Exception as e:
            logger.exception("baseline load/build failed: %s", e)

    def _persist_baseline(self):
        try:
            with open(self.baseline_path, "w", encoding="utf-8") as f:
                json.dump({"updated": datetime.utcnow().isoformat(), "files": self._baseline}, f, indent=2)
        except Exception:
            logger.exception("persist baseline failed")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("FileGuard started watching %s", self.watch_dirs)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _emit(self, event: dict):
        """Emit via helpers if provided, else log"""
        try:
            if "emit_event" in self.helpers and callable(self.helpers["emit_event"]):
                try:
                    self.helpers["emit_event"](event)
                except Exception:
                    logger.debug("helpers.emit_event failed, fallback to log")
            logger.info("FG_EVENT: %s", json.dumps(event, default=str))
        except Exception:
            pass

    def _quarantine_file(self, path: str, reason: str) -> str:
        """Use backup_and_quarantine helper if present; else move to quarantine_dir."""
        try:
            if "backup_and_quarantine" in self.helpers:
                meta = self.helpers["backup_and_quarantine"](path, reason)
                return meta.get("backup_path") or meta.get("honeypot_copy") or ""
            # fallback: copy to quarantine dir with timestamped name
            dst = os.path.join(self.quarantine_dir, f"{int(time.time())}_{os.path.basename(path)}")
            shutil.copy2(path, dst)
            return dst
        except Exception as e:
            logger.exception("quarantine fallback failed: %s", e)
            return ""

    def _restore_from_backup(self, path: str) -> bool:
        """Try to restore file from backup directory if matching file exists."""
        # simple heuristic: find most recent backup file that endswith basename
        try:
            basename = os.path.basename(path)
            candidates = []
            for root, _, files in os.walk(self.backup_dir):
                for f in files:
                    if f.endswith("_" + basename) or f.endswith(basename):
                        candidates.append(os.path.join(root, f))
            if not candidates:
                return False
            # choose most recent
            candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            best = candidates[0]
            shutil.copy2(best, path)
            return True
        except Exception:
            return False

    def _handle_changed(self, path: str, old_hash: str, new_hash: str):
        event = {"type": "prevention", "subtype": "file_changed", "path": path,
                 "old_hash": old_hash, "new_hash": new_hash, "timestamp": datetime.utcnow().isoformat()}
        # Quarantine original (copy)
        qpath = self._quarantine_file(path, "file_changed")
        event["quarantine_copy"] = qpath
        # Attempt restoration
        restored = self._restore_from_backup(path)
        event["restored_from_backup"] = restored
        # If helpers provide create_decoy_at_path create decoy
        try:
            if "create_decoy_at_path" in self.helpers:
                self.helpers["create_decoy_at_path"](path, reason="file_guard_decoy")
                event["decoy"] = True
        except Exception:
            event["decoy_error"] = "create_decoy_failed"
        self._emit(event)
        # update baseline
        self._baseline[path] = sha256(path)
        self._persist_baseline()

    def _loop(self):
        while not self._stop.is_set():
            changed = []
            try:
                # check existing baseline entries
                for path, old in list(self._baseline.items()):
                    if not os.path.exists(path):
                        changed.append((path, old, None))  # missing
                        self._baseline.pop(path, None)
                        continue
                    new = sha256(path)
                    if new and new != old:
                        changed.append((path, old, new))
                        self._baseline[path] = new
                # discover new files
                for root in self.watch_dirs:
                    for dirpath, _, files in os.walk(root):
                        for fn in files:
                            fp = os.path.join(dirpath, fn)
                            if fp not in self._baseline and os.path.isfile(fp):
                                self._baseline[fp] = sha256(fp)
                                changed.append((fp, None, self._baseline[fp]))
                # persist baseline
                self._persist_baseline()
            except Exception as e:
                logger.debug("FileGuard loop error: %s", e)

            if len(changed) >= MASS_CHANGE_THRESHOLD:
                # escalate mass change
                evt = {"type": "prevention", "subtype": "mass_file_change", "count": len(changed),
                       "details": [{"path": p, "old": o, "new": n} for (p,o,n) in changed],
                       "timestamp": datetime.utcnow().isoformat()}
                self._emit(evt)
                # call handler for each changed
                for (p,o,n) in changed:
                    try:
                        self._handle_changed(p, o, n)
                    except Exception as e:
                        logger.debug("handle_changed failed for %s: %s", p, e)
            else:
                # for smaller changes, handle individually (but less noisy)
                for (p,o,n) in changed:
                    try:
                        self._handle_changed(p, o, n)
                    except Exception as e:
                        logger.debug("handle_changed failed small: %s", e)

            time.sleep(INTEGRITY_INTERVAL)
