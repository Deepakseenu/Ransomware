# prevention.py
"""
Prevention helpers for monitor.py

Usage:
  - from prevention import run_prevention, start_integrity_monitor, load_whitelist
  - call run_prevention(path, analysis, helpers= {...}) when a file is deemed suspicious
  - start_integrity_monitor(watch_dirs, baseline_path, interval_seconds, helpers=...)
Notes:
  - Some actions (lsof, chattr, iptables) may require root/privileges.
  - By default actions are conservative: pause (SIGSTOP) processes, not kill.
"""

import os
import json
import time
import hashlib
import logging
import subprocess
import threading
import signal
from datetime import datetime
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("prevention")

# Configuration (tune these)
WHITELIST_PATH = os.environ.get("HP_WHITELIST", "/opt/honeypot_tools/whitelist.json")
BASELINE_PATH = os.environ.get("HP_BASELINE", "/opt/honeypot_tools/baseline_checksums.json")
INTEGRITY_INTERVAL = int(os.environ.get("HP_INTEGRITY_INTERVAL", "60"))  # seconds
MASS_CHANGE_THRESHOLD = int(os.environ.get("HP_MASS_CHANGE_THRESHOLD", "10"))  # files changed -> escalate

# Safety flags
PAUSE_PROCESSES = True     # use SIGSTOP on offending pids (safer than kill)
SET_IMMUTABLE = True      # try chattr +i on decoy or protected files (requires root)
AUTOBLOCK = False         # monitor will only request blocking if explicitly enabled (default off)

# Helper type hints
Helpers = Dict[str, Callable]

# ------------- whitelist helpers -------------
def load_whitelist(path: Optional[str] = None) -> Dict[str, dict]:
    p = path or WHITELIST_PATH
    try:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                # allow list form
                if isinstance(data, list):
                    return {entry.get("path") or entry.get("name"): entry for entry in data if isinstance(entry, dict)}
    except Exception as e:
        logger.warning("load_whitelist failed: %s", e)
    return {}

def is_whitelisted_exe(exe_path: str, whitelist: Dict[str, dict]) -> bool:
    if not exe_path:
        return False
    exe_norm = os.path.realpath(exe_path)
    for k, info in whitelist.items():
        # whitelist entry can be exact path or basename match
        wpath = info.get("path") or info.get("exe") or k
        if not wpath:
            continue
        if os.path.isabs(wpath):
            try:
                if os.path.realpath(wpath) == exe_norm:
                    return True
            except Exception:
                pass
        else:
            # basename match
            if os.path.basename(exe_norm) == os.path.basename(wpath):
                return True
    return False

# ------------- checksum baseline helpers -------------
def compute_sha256(path: str, blocksize: int = 65536) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(blocksize), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def build_baseline(paths: List[str], baseline_path: Optional[str] = None) -> Dict[str, str]:
    baseline = {}
    for root in paths:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    if os.path.isfile(fp):
                        baseline[fp] = compute_sha256(fp)
                except Exception:
                    pass
    bp = baseline_path or BASELINE_PATH
    try:
        os.makedirs(os.path.dirname(bp), exist_ok=True)
        with open(bp, "w", encoding="utf-8") as f:
            json.dump({"created": datetime.utcnow().isoformat(), "files": baseline}, f, indent=2)
    except Exception as e:
        logger.warning("Failed to write baseline: %s", e)
    return baseline

def load_baseline(baseline_path: Optional[str] = None) -> Dict[str, str]:
    bp = baseline_path or BASELINE_PATH
    try:
        if os.path.exists(bp):
            with open(bp, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("files", {}) if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("load_baseline failed: %s", e)
    return {}

# ------------- process lookup helpers -------------
def pids_using_file(path: str) -> List[int]:
    """Return list of PIDs that hold open handles to the file (uses lsof)."""
    try:
        # lsof -t <file> returns pids only
        proc = subprocess.run(["lsof", "-t", path], capture_output=True, text=True)
        if proc.returncode != 0:
            return []
        out = proc.stdout.strip().splitlines()
        return [int(x) for x in out if x.strip().isdigit()]
    except Exception:
        return []

def exe_of_pid(pid: int) -> str:
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        return exe
    except Exception:
        return ""

# ------------- safe action helpers -------------
def try_pause_pids(pids: List[int], whitelist: Dict[str, dict]):
    """SIGSTOP processes that are not whitelisted (safer than SIGKILL)."""
    results = {"paused": [], "skipped_whitelist": [], "errors": []}
    for pid in pids:
        try:
            exe = exe_of_pid(pid)
            if is_whitelisted_exe(exe, whitelist):
                results["skipped_whitelist"].append({"pid": pid, "exe": exe})
                continue
            if PAUSE_PROCESSES:
                os.kill(pid, signal.SIGSTOP)
                results["paused"].append({"pid": pid, "exe": exe})
            else:
                # fallback: send SIGTERM (less safe)
                os.kill(pid, signal.SIGTERM)
                results["paused"].append({"pid": pid, "exe": exe, "term_sent": True})
        except Exception as e:
            results["errors"].append({"pid": pid, "error": str(e)})
    return results

def try_set_immutable(path: str):
    """Try to set chattr +i (immutable) if available."""
    if not SET_IMMUTABLE:
        return {"set": False, "reason": "immutable_disabled"}
    try:
        proc = subprocess.run(["chattr", "+i", path], capture_output=True, text=True)
        if proc.returncode == 0:
            return {"set": True}
        return {"set": False, "stderr": proc.stderr}
    except Exception as e:
        return {"set": False, "error": str(e)}

# ------------- high-level prevention action -------------
def run_prevention(path: str,
                   analysis: dict,
                   helpers: Optional[Helpers] = None,
                   whitelist_path: Optional[str] = None,
                   do_autoblock: Optional[bool] = None) -> dict:
    """
    Top-level prevention action to execute when a suspicious file is detected.

    helpers: dict of helper callables expected:
      - backup_and_quarantine(path, reason) -> dict
      - create_decoy_at_path(path, reason) -> None
      - emit_event(dict) -> None  (optional)
      - ensure_block(ip) -> dict  (optional)
    """
    res = {"path": path, "analysis": analysis, "actions": [], "timestamp": datetime.utcnow().isoformat()}
    helpers = helpers or {}
    do_autoblock_final = AUTOBLOCK if do_autoblock is None else bool(do_autoblock)

    # Load whitelist
    whitelist = load_whitelist(whitelist_path)

    # 1) Backup & Quarantine
    try:
        if "backup_and_quarantine" in helpers:
            meta = helpers["backup_and_quarantine"](path, reason="prevention_quarantine")
            res["actions"].append({"backup_and_quarantine": meta})
        else:
            # fallback: move to quarantined folder locally
            qdir = os.path.join("/opt/honeypot_tools", "quarantine")
            os.makedirs(qdir, exist_ok=True)
            dest = os.path.join(qdir, f"{int(time.time())}_{os.path.basename(path)}")
            try:
                shutil.copy2(path, dest)
                res["actions"].append({"copied_to_quarantine": dest})
            except Exception as e:
                res["actions"].append({"quarantine_copy_failed": str(e)})
    except Exception as e:
        res["actions"].append({"backup_error": str(e)})

    # 2) Place decoy at original path
    try:
        if "create_decoy_at_path" in helpers:
            helpers["create_decoy_at_path"](path, reason="prevention_decoy")
            res["actions"].append({"decoy_created": True})
        else:
            # minimal decoy: create empty read-only file
            try:
                with open(path, "wb") as f:
                    f.write(b"Quarantined for analysis.")
                os.chmod(path, 0o444)
                res["actions"].append({"decoy_created": "basic"})
            except Exception as e:
                res["actions"].append({"decoy_failed": str(e)})
    except Exception as e:
        res["actions"].append({"decoy_error": str(e)})

    # 3) Try set immutable (safer) and make read-only
    try:
        os.chmod(path, 0o444)
        imm = try_set_immutable(path)
        res["actions"].append({"chmod_readonly": True, "immutable": imm})
    except Exception as e:
        res["actions"].append({"chmod_error": str(e)})

    # 4) Try to find processes using the path and pause them if not whitelisted
    try:
        pids = pids_using_file(path)
        res["detected_pids"] = pids
        if pids:
            pause_res = try_pause_pids(pids, whitelist)
            res["pause_result"] = pause_res
    except Exception as e:
        res["actions"].append({"pids_error": str(e)})

    # 5) Optionally ask dashboard to block correlated IPs (if helpers provided)
    if do_autoblock_final:
        try:
            # if analysis contains correlated_ips or src_ip keys
            ips = analysis.get("correlated_ips") or analysis.get("src_ips") or []
            if isinstance(ips, str):
                ips = [ips]
            blocked_results = {}
            for ip in ips:
                try:
                    if "ensure_block" in helpers:
                        blocked_results[ip] = helpers["ensure_block"](ip)
                    else:
                        # attempt local iptables add as fallback
                        proc = subprocess.run(["sudo", "/usr/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                                              capture_output=True, text=True)
                        blocked_results[ip] = {"cmd_returncode": proc.returncode, "stderr": proc.stderr}
                except Exception as e:
                    blocked_results[ip] = {"error": str(e)}
            res["blocked_ips"] = blocked_results
        except Exception as e:
            res["blocked_ips_error"] = str(e)

    # 6) Emit / log final prevention event (if helper present)
    try:
        if "emit_event" in helpers:
            evt = {"type": "prevention_action", "path": path, "analysis": analysis, "result": res, "timestamp": datetime.utcnow().isoformat()}
            try:
                helpers["emit_event"](evt)
            except Exception:
                logger.debug("emit_event failed in prevention helpers")
    except Exception:
        pass

    return res

# ------------- integrity monitor thread -------------
def start_integrity_monitor(watch_dirs: List[str], baseline_path: Optional[str] = None, interval_seconds: int = INTEGRITY_INTERVAL, helpers: Optional[Helpers] = None):
    """
    Spawns a thread that periodically computes checksums and compares them to baseline.
    If mass changes exceed threshold it returns a dict with changed paths.
    helpers: same as run_prevention helpers (so monitor can call backup/quarantine)
    """
    baseline = load_baseline(baseline_path)
    if not baseline:
        logger.info("Baseline missing or empty, building baseline now.")
        baseline = build_baseline(watch_dirs, baseline_path)

    stop_event = threading.Event()

    def loop():
        while not stop_event.is_set():
            changed = []
            for path, old_h in list(baseline.items()):
                if not os.path.exists(path):
                    changed.append({"path": path, "reason": "missing"})
                    baseline.pop(path, None)
                    continue
                new_h = compute_sha256(path)
                if new_h and new_h != old_h:
                    changed.append({"path": path, "old": old_h, "new": new_h})
                    baseline[path] = new_h
            # detect new files
            for root in watch_dirs:
                for dirpath, _, filenames in os.walk(root):
                    for fn in filenames:
                        fp = os.path.join(dirpath, fn)
                        if fp not in baseline:
                            baseline[fp] = compute_sha256(fp)
                            changed.append({"path": fp, "reason": "new"})
            # persist baseline
            try:
                with open(baseline_path or BASELINE_PATH, "w", encoding="utf-8") as f:
                    json.dump({"updated": datetime.utcnow().isoformat(), "files": baseline}, f, indent=2)
            except Exception:
                pass

            if len(changed) >= MASS_CHANGE_THRESHOLD:
                # escalate: call prevention for changed files
                logger.warning("Mass changes detected: %d files", len(changed))
                if helpers and "emit_event" in helpers:
                    helpers["emit_event"]({"type": "integrity_mass_change", "count": len(changed), "details": changed, "timestamp": datetime.utcnow().isoformat()})
                # optionally call run_prevention on each changed path
                if helpers and "backup_and_quarantine" in helpers and "create_decoy_at_path" in helpers:
                    for c in changed:
                        path = c.get("path")
                        try:
                            run_prevention(path, {"score": 10.0, "reasons": ["mass_change_detected"]}, helpers=helpers)
                        except Exception as e:
                            logger.debug("prevention call failed for %s: %s", path, e)

            time.sleep(interval_seconds)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return stop_event, t
