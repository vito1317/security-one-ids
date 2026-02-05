#!/bin/bash
# Security One IDS - Continuous scanning wrapper
# Runs desktop:scan every 60 seconds in a loop

INSTALL_DIR="/opt/security-one-ids"
LOG_DIR="/var/log/security-one-ids"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Find PHP binary (check common locations)
PHP_BIN=""
for path in /opt/homebrew/bin/php /usr/local/bin/php /usr/bin/php; do
    if [ -x "$path" ]; then
        PHP_BIN="$path"
        break
    fi
done

if [ -z "$PHP_BIN" ]; then
    echo "$(date): ERROR - PHP not found!" >> "$LOG_DIR/wrapper.log"
    exit 1
fi

cd "$INSTALL_DIR" || exit 1

echo "$(date): Security One IDS wrapper started (PHP: $PHP_BIN)" >> "$LOG_DIR/wrapper.log"

while true; do
    echo "$(date): Running WAF sync (heartbeat)..." >> "$LOG_DIR/wrapper.log"
    
    # Send heartbeat to WAF Hub with system stats including network
    "$PHP_BIN" "$INSTALL_DIR/artisan" waf:sync >> "$LOG_DIR/output.log" 2>&1
    
    echo "$(date): Running security scan..." >> "$LOG_DIR/wrapper.log"
    
    # Run the scan with -v for verbose output, capture ALL output
    "$PHP_BIN" "$INSTALL_DIR/artisan" desktop:scan --full -v >> "$LOG_DIR/output.log" 2>&1
    
    exit_code=$?
    echo "$(date): Scan completed with exit code $exit_code" >> "$LOG_DIR/wrapper.log"
    
    # Wait 60 seconds before next scan
    sleep 60
done
