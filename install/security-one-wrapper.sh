#!/bin/bash
# Security One IDS - Continuous scanning wrapper
# Runs desktop:scan every 60 seconds in a loop

INSTALL_DIR="/opt/security-one-ids"
LOG_DIR="/var/log/security-one-ids"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

cd "$INSTALL_DIR" || exit 1

echo "$(date): Security One IDS wrapper started" >> "$LOG_DIR/wrapper.log"

while true; do
    echo "$(date): Running security scan..." >> "$LOG_DIR/wrapper.log"
    
    # Run the scan with timeout to prevent hanging
    /usr/bin/php "$INSTALL_DIR/artisan" desktop:scan --full 2>&1 | head -50 >> "$LOG_DIR/output.log"
    
    exit_code=$?
    echo "$(date): Scan completed with exit code $exit_code" >> "$LOG_DIR/wrapper.log"
    
    # Wait 60 seconds before next scan
    sleep 60
done
