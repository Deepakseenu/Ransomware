#!/bin/bash
# run_env_setup.sh - Honeypot environment bootstrap

set -e
DEST="/opt/honeypot_tools"
mkdir -p "$DEST" "$DEST/snapshots" "$DEST/forensics"

# --- Python venv ---
python3 -m venv "$DEST/venv"
source "$DEST/venv/bin/activate"
pip install --upgrade pip
pip install watchdog requests python-telegram-bot==13.15 yara-python

# --- Install system tools ---
apt-get update -y
apt-get install -y yara suricata falco

# --- Setup systemd skeletons ---
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/honeypot_monitor.service <<EOF
[Unit]
Description=Honeypot Monitoring Script
After=network.target

[Service]
ExecStart=$DEST/venv/bin/python3 $DEST/monitor_inotify.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Environment ready."
echo "Virtualenv: $DEST/venv"
echo "Activate: source $DEST/venv/bin/activate"
echo "Systemd unit created: honeypot_monitor.service"
