#!/usr/bin/env python3
import os
import base64
import random
import string
import time

# ------------------------------
# Configuration
# ------------------------------
PROJECT_FOLDER = "/home/yashu/Documents/RansomwareProject"
TEST_FOLDER = os.path.join(PROJECT_FOLDER, "SandboxTest")
NUM_FILES = 5
DELAY = 1  # seconds between file operations

os.makedirs(TEST_FOLDER, exist_ok=True)

# ------------------------------
# Create dummy files
# ------------------------------
print("[*] Creating dummy files...")
for i in range(1, NUM_FILES + 1):
    fname = f"dummy_file_{i}.txt"
    fpath = os.path.join(TEST_FOLDER, fname)
    with open(fpath, "w") as f:
        f.write("This is a safe test file.\n" * 5)
    print(f"  Created {fname}")
time.sleep(1)

# ------------------------------
# Simulate encryption
# ------------------------------
print("[*] Simulating ransomware encryption...")
for file_name in os.listdir(TEST_FOLDER):
    file_path = os.path.join(TEST_FOLDER, file_name)
    # Read content
    with open(file_path, "rb") as f:
        data = f.read()
    # Encode as base64 (safe "encryption")
    encoded = base64.b64encode(data)
    # Overwrite file
    with open(file_path, "wb") as f:
        f.write(encoded)
    print(f"  Encrypted {file_name}")
    time.sleep(DELAY)

# ------------------------------
# Simulate ransom note
# ------------------------------
ransom_note = os.path.join(TEST_FOLDER, "README_RANSOM.txt")
with open(ransom_note, "w") as f:
    f.write("⚠️ Your files have been encrypted! This is a simulation. ⚠️\n")
print(f"[*] Ransom note created: {ransom_note}")

print("[*] Simulation complete. No real files were harmed.")
