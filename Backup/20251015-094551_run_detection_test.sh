#!/usr/bin/env bash
# run_detection_test.sh
# Creates test files in ~/Downloads/monitor_test, simulates modifications,
# then shows Backup folder and activity log.
# Usage:
#   1) (Optional) Start monitor in test mode:
#        FORCE_DETECT=1 python monitor.py
#      or without test forcing:
#        python monitor.py
#   2) In another terminal run:
#        chmod +x ~/Downloads/run_detection_test.sh
#        ~/Downloads/run_detection_test.sh

set -euo pipefail

USER_HOME="$HOME"
TEST_DIR="$USER_HOME/Downloads/monitor_test"
PROJECT="$HOME/Documents/RansomwareProject"
BACKUP_DIR="$PROJECT/Backup"
LOG_FILE="$PROJECT/activity_log.txt"

mkdir -p "$TEST_DIR"
mkdir -p "$BACKUP_DIR"

echo
echo "==> Test dir: $TEST_DIR"
echo "Creating test files..."

# Clean old test files
rm -f "$TEST_DIR"/* || true

# Normal file (should NOT trigger backup/honeypot unless FORCE_DETECT enabled)
printf "normal file\n" > "$TEST_DIR/normal_file.txt"

# Simulated malware file (we'll rely on FORCE_DETECT or your model)
printf "simulated ransom sample\n" > "$TEST_DIR/test_ransomware_sim.exe"

# Image file (should be replaced by honeypot when detected)
printf "fake image bytes\n" > "$TEST_DIR/test_image.jpg"

# PDF file
printf "fake pdf\n" > "$TEST_DIR/test_doc.pdf"

# Hidden file (should be ignored)
touch "$TEST_DIR/.temp_swap.swp"

# Make sure files exist
ls -la "$TEST_DIR"

echo
echo "Triggering modifications to cause watchdog events..."
for i in 1 2 3; do
  # append timestamp to modify files
  date >> "$TEST_DIR/normal_file.txt"
  date >> "$TEST_DIR/test_ransomware_sim.exe"
  date >> "$TEST_DIR/test_image.jpg"
  date >> "$TEST_DIR/test_doc.pdf"
  sleep 1
done

echo
echo "Waiting 3 seconds for monitor to process events..."
sleep 3

echo
echo "===== Contents of test folder ($TEST_DIR) ====="
ls -la "$TEST_DIR" || true

echo
echo "===== Recent files in Backup ($BACKUP_DIR) ====="
ls -la "$BACKUP_DIR" | tail -n 30 || true

echo
echo "===== Last 50 lines of activity log ($LOG_FILE) ====="
tail -n 50 "$LOG_FILE" || true

echo
echo "If monitor was started with FORCE_DETECT=1, you should see backups and .honeypot_ files for test_ransomware_sim.exe, test_image.jpg, and test_doc.pdf."
echo "If monitor was started normally (no FORCE_DETECT), only files flagged by ML/sandbox will be backed up and replaced."
