#!/bin/bash
# quarantine_and_snapshot.sh
# Monitors & quarantines suspicious files triggered by monitor_master.py

# -------------------------
# Configuration
# -------------------------
PROJECT_ROOT="${PROJECT_ROOT:-$(dirname $(dirname $(realpath $0)))}"
BACKUP_DIR="$PROJECT_ROOT/Backup"
WEB_HONEYPOT="$PROJECT_ROOT/website/college_clone_honeypot"
LOG_FILE="$PROJECT_ROOT/logs/quarantine.log"

# Dashboard endpoint
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:5000/update_quarantine}"

# Debounce file
DEBOUNCE_FILE="$PROJECT_ROOT/logs/.quarantine_last"

mkdir -p "$BACKUP_DIR" "$PROJECT_ROOT/logs"

# -------------------------
# Functions
# -------------------------
timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

log() {
    echo "[$(timestamp)] $*" | tee -a "$LOG_FILE"
}

notify_dashboard() {
    local event="$1"
    local file="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"event\":\"$event\",\"file\":\"$file\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$DASHBOARD_URL" >/dev/null 2>&1
    fi
}

backup_file() {
    local src="$1"
    if [ ! -f "$src" ]; then return; fi
    local ts=$(date "+%Y%m%d-%H%M%S")
    local dest="$BACKUP_DIR/${ts}_$(basename "$src")"
    mv "$src" "$dest" 2>/dev/null
    log "BACKUP: $src -> $dest"
    notify_dashboard "BACKUP" "$dest"
}

simulate_ransom() {
    # optional: overwrite honeypot content to simulate ransomware
    local file="$1"
    if [ -f "$file" ]; then
        echo "=== HONEYPOT LOCKED ===" > "$file"
        log "Simulated ransom on $file"
        notify_dashboard "RANSOM_SIMULATION" "$file"
    fi
}

debounce_check() {
    local now=$(date +%s)
    local last=0
    [ -f "$DEBOUNCE_FILE" ] && last=$(cat "$DEBOUNCE_FILE")
    if [ $((now - last)) -lt 30 ]; then
        return 1
    fi
    echo "$now" > "$DEBOUNCE_FILE"
    return 0
}

# -------------------------
# Main
# -------------------------
event="$1"

log "QUARANTINE TRIGGERED: $event"

# Debounce to prevent repeated triggers
debounce_check || {
    log "Debounce active. Skipping repeated quarantine."
    exit 0
}

# Quarantine logic
if [ "$event" = "yara_match" ] || [ "$event" = "mass_mod_detected" ]; then
    # Backup all files in web honeypot
    find "$WEB_HONEYPOT" -type f | while read f; do
        backup_file "$f"
        simulate_ransom "$f"
    done
fi

log "QUARANTINE COMPLETED for event: $event"
