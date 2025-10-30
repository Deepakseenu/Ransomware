#!/usr/bin/env python3
"""
safe_ransom_simulator.py

Harmless ransomware *simulator* for testing detection and response.
- DOES NOT DELETE or MODIFY original files.
- Creates base64-encoded copies in a separate folder named simulated_encrypted.
- Safety guard: target directory must contain 'sandbox' or 'test' (case-insensitive).
- Usage: python3 safe_ransom_simulator.py /path/to/my_sandbox_folder
"""

import sys
import os
import base64
import pathlib
import datetime
import logging

# ---------- Configuration ----------
LOGFILE_NAME = "simulator.log"
ENC_DIRNAME = "simulated_encrypted"
RANSOM_NOTE_NAME = "RANSOM_NOTE.txt"
ALLOWED_KEYWORDS = ("sandbox", "test")  # path must contain one of these
# -----------------------------------

def safe_path_check(target):
    lowered = str(target).lower()
    return any(k in lowered for k in ALLOWED_KEYWORDS)

def setup_logging(base_dir):
    logpath = os.path.join(base_dir, LOGFILE_NAME)
    logging.basicConfig(
        filename=logpath,
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
    logging.info("Simulator log started.")

def simulate_on_directory(target):
    target = pathlib.Path(target).resolve()
    if not target.exists() or not target.is_dir():
        logging.error("Target path does not exist or is not a directory: %s", target)
        sys.exit(1)

    if not safe_path_check(target):
        logging.error("Safety check failed. Directory path must contain 'sandbox' or 'test' (case-insensitive).")
        sys.exit(1)

    enc_dir = target / ENC_DIRNAME
    enc_dir.mkdir(exist_ok=True)

    files_processed = 0
    for root, dirs, files in os.walk(target):
        # Skip the encoded output directory and the log file
        if ENC_DIRNAME in root.split(os.sep):
            continue
        for fname in files:
            if fname in (LOGFILE_NAME, RANSOM_NOTE_NAME):
                continue
            src_path = pathlib.Path(root) / fname
            # Only process regular files (no symlinks, devices)
            if not src_path.is_file() or src_path.is_symlink():
                continue

            rel_path = src_path.relative_to(target)
            dest_subdir = enc_dir / rel_path.parent
            dest_subdir.mkdir(parents=True, exist_ok=True)

            try:
                with src_path.open("rb") as f:
                    data = f.read()
                encoded = base64.b64encode(data)
                dest_name = src_path.name + ".locked"
                dest_path = dest_subdir / dest_name
                with dest_path.open("wb") as out:
                    out.write(encoded)
                files_processed += 1
                logging.info("Processed: %s -> %s", src_path, dest_path)
            except Exception as e:
                logging.error("Failed to process %s : %s", src_path, e)

    # Write a ransom note into the enc_dir root
    now = datetime.datetime.utcnow().isoformat() + "Z"
    note_text = (
        "YOUR FILES HAVE BEEN SIMULATED-LOCKED\n\n"
        f"This is a harmless simulation created at {now} for testing purposes only.\n"
        "Original files were NOT modified. Encoded copies were placed in:\n"
        f"{enc_dir}\n\n"
        "To restore in this simulation, decode base64 from the .locked files.\n"
        "THIS IS NOT REAL MALWARE.\n"
    )
    with (enc_dir / RANSOM_NOTE_NAME).open("w") as note:
        note.write(note_text)
    logging.info("Simulation complete. Files processed: %d", files_processed)
    print("\nSimulation complete.")
    print(f"Encoded copies (base64) are in: {enc_dir}")
    print("Original files were left unchanged.")
    logging.info("Simulation finished successfully.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 safe_ransom_simulator.py /path/to/your_sandbox_folder")
        sys.exit(1)

    target = sys.argv[1]
    # Basic absolute path resolution
    target = os.path.abspath(target)
    # Prevent running on root-like directories
    if target in ("/", os.path.expanduser("~"), os.path.expanduser("~/")):
        print("Refusing to run on dangerous/root/home directories. Provide a sandbox/test folder.")
        sys.exit(1)

    setup_logging(target)
    logging.info("Starting simulator on: %s", target)
    simulate_on_directory(target)

if __name__ == "__main__":
    main()
