#!/usr/bin/env python3
"""
Safe ransomware *simulator* — NON-DESTRUCTIVE.
Only operates inside SIM_TEST_DIR. It copies files and writes a small marker.
Do NOT run on real data.
"""

import os
import shutil
import time
import datetime

# >>> Configure this to a folder created just for testing (inside your VM)
SIM_TEST_DIR = "/home/yashu/Documents/RansomwareProject/SimTestFiles"
SIM_OUTPUT_DIR = os.path.join(SIM_TEST_DIR, "sim_output")
LOG = os.path.join(SIM_TEST_DIR, "simulator_log.txt")

os.makedirs(SIM_TEST_DIR, exist_ok=True)
os.makedirs(SIM_OUTPUT_DIR, exist_ok=True)

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | {msg}\n"
    print(line, end="")
    with open(LOG, "a") as f:
        f.write(line)

def simulate_run():
    """
    Walk SIM_TEST_DIR (non-recursive, ignore sim_output and log),
    copy each file to sim_output and create a small marker file that
    indicates the file was 'simulated encrypted'.
    """
    for name in os.listdir(SIM_TEST_DIR):
        src = os.path.join(SIM_TEST_DIR, name)

        # skip directories and simulator outputs/logs
        if os.path.isdir(src):
            if os.path.basename(src) == "sim_output":
                continue
            else:
                continue
        if name == os.path.basename(LOG):
            continue

        try:
            dest = os.path.join(SIM_OUTPUT_DIR, f"{name}.SIMULATED")
            # copy original file contents (non-destructive)
            shutil.copy2(src, dest)

            # create a tiny marker file describing the simulation
            marker = dest + ".marker.txt"
            with open(marker, "w") as m:
                m.write("SIMULATOR: this file was copied as part of a safe simulation.\n")
                m.write(f"Original: {src}\n")
                m.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")

            log(f"SIMULATED_COPY: {src} -> {dest}")
        except Exception as e:
            log(f"ERROR processing {src}: {e}")

if __name__ == "__main__":
    log("SIMULATOR_STARTED")
    simulate_run()
    log("SIMULATOR_FINISHED")
