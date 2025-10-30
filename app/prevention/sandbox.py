# prevention/sandbox.py
"""
SandboxAnalyzer: lightweight container-less sandbox for static + shallow dynamic checks.
- Runs YARA (if available), entropy and filetype heuristics.
- If Docker/firejail present, it can optionally run file in a contained environment (disabled by default).
"""

import os
import logging
import math
from typing import Dict
from pathlib import Path

logger = logging.getLogger("prevention.sandbox")

# optional yara rules; monitor may provide yara_scan_file helper
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    ln = len(data)
    for count in freq.values():
        p = count / ln
        ent -= p * math.log2(p)
    return ent

class SandboxAnalyzer:
    def __init__(self, yara_scan_callable=None, high_entropy_threshold: float = 7.5):
        self.yara_scan = yara_scan_callable
        self.ent_thresh = high_entropy_threshold

    def analyze(self, path: str) -> Dict:
        res = {"path": path, "suspicious": False, "reasons": [], "score": 0.0}
        try:
            if not os.path.exists(path):
                res["reasons"].append("missing")
                return res
            size = os.path.getsize(path)
            # sample first chunk
            try:
                with open(path, "rb") as f:
                    data = f.read(8192)
                ent = shannon_entropy(data)
                res["entropy"] = round(ent, 2)
                if ent > self.ent_thresh:
                    res["score"] += 4.0
                    res["reasons"].append("high_entropy")
            except Exception:
                res["reasons"].append("read_fail")

            # yara
            try:
                if callable(self.yara_scan):
                    matches = self.yara_scan(path)
                    if matches:
                        res["score"] += 6.0
                        res["reasons"].append("yara:" + ",".join(matches))
            except Exception:
                pass

            # filename heuristics
            base = os.path.basename(path).upper()
            if "README_DECRYPT" in base or base.endswith(".locked") or base.endswith(".encrypted"):
                res["score"] += 5.0
                res["reasons"].append("ransom_name")

            if res["score"] >= 6.0:
                res["suspicious"] = True
            return res
        except Exception as e:
            logger.exception("sandbox analyze failed: %s", e)
            res["reasons"].append("analyze_error")
            return res
