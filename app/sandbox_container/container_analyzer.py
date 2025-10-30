import os
import subprocess
import datetime
import json

# === Configuration ===
FILES_DIR = "/analysis/files"
LOG_DIR = "/opt/honeypot_tools/logs"
LOG_FILE = os.path.join(LOG_DIR, "sandbox_analysis.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)


def log_event(file_name, status, details):
    """Write structured log entries for sandbox analysis."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "file": file_name,
        "status": status,
        "details": details
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def scan_with_clamav(file_path):
    """Run ClamAV scan on a file."""
    try:
        result = subprocess.run(["clamscan", file_path], capture_output=True, text=True)
        infected = "Infected files: 0" not in result.stdout
        return not infected, result.stdout
    except Exception as e:
        return False, str(e)


def analyze_files():
    """Main analyzer function to scan files in the sandbox."""
    if not os.path.exists(FILES_DIR):
        print(f"[❌] Files directory not found: {FILES_DIR}")
        return

    print("[🔍] Starting sandbox file analysis...")

    for file in os.listdir(FILES_DIR):
        file_path = os.path.join(FILES_DIR, file)

        if not os.path.isfile(file_path):
            continue

        print(f"[+] Scanning {file} ...")
        clean, output = scan_with_clamav(file_path)

        if clean:
            print(f"✅ {file} is clean")
            log_event(file, "clean", "No infection detected")
        else:
            print(f"🚨 Malware detected in {file}")
            log_event(file, "infected", output)

    print("[✔️] Sandbox analysis completed.")
    print(f"[📄] Log saved to {LOG_FILE}")


if __name__ == "__main__":
    analyze_files()
