#!/bin/bash
# auto_restore.sh - Restore from last snapshot after fake payment
set -e

SNAP_DIR=$(ls -dt /opt/honeypot_tools/snapshots/* | head -n 1)
WEBROOT="/var/www/html/college_clone_honeypot"

if [ -z "$SNAP_DIR" ]; then
  echo "[!] No snapshot found!"
  exit 1
fi

echo "[*] Restoring webroot from $SNAP_DIR ..."
rsync -a --delete "$SNAP_DIR/" "$WEBROOT/"

systemctl start apache2 || service apache2 start
echo "[*] Website restored successfully from snapshot!"
