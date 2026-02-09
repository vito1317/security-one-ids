#!/bin/bash
# Security One IDS - Auto-Recovery Watchdog Wrapper
# This script manages the IDS scan process with automatic crash recovery
# Version 2.0 - Enhanced with crash recovery, health monitoring, and logging

INSTALL_DIR="/opt/security-one-ids"
LOG_DIR="/var/log/security-one-ids"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
PID_FILE="$INSTALL_DIR/storage/ids.pid"
CRASH_COUNT_FILE="$INSTALL_DIR/storage/crash_count"
MAX_CRASHES_BEFORE_RESET=5
SCAN_INTERVAL=300  # Security scan interval (5 min)
DEFAULT_HEARTBEAT_INTERVAL=60
CONFIG_FILE="$INSTALL_DIR/storage/app/waf_config.json"
HEALTH_CHECK_INTERVAL=30

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Find PHP binary (check common locations)
find_php() {
    for path in /opt/homebrew/bin/php /usr/local/bin/php /usr/bin/php /usr/local/php/bin/php; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

PHP_BIN=$(find_php)
if [ -z "$PHP_BIN" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [FATAL] PHP not found!" >> "$WATCHDOG_LOG"
    exit 1
fi

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [$level] $message" >> "$WATCHDOG_LOG"
    
    # Keep log size manageable (rotate at 10MB)
    if [ -f "$WATCHDOG_LOG" ] && [ $(stat -f%z "$WATCHDOG_LOG" 2>/dev/null || stat -c%s "$WATCHDOG_LOG" 2>/dev/null) -gt 10485760 ]; then
        mv "$WATCHDOG_LOG" "$WATCHDOG_LOG.old"
        log_message "INFO" "Log rotated"
    fi
}

# Get crash count
get_crash_count() {
    if [ -f "$CRASH_COUNT_FILE" ]; then
        cat "$CRASH_COUNT_FILE"
    else
        echo "0"
    fi
}

# Increment crash count
increment_crash_count() {
    local count=$(get_crash_count)
    echo $((count + 1)) > "$CRASH_COUNT_FILE"
}

# Reset crash count
reset_crash_count() {
    echo "0" > "$CRASH_COUNT_FILE"
}

# Check if crash limit reached
check_crash_limit() {
    local count=$(get_crash_count)
    if [ "$count" -ge "$MAX_CRASHES_BEFORE_RESET" ]; then
        log_message "CRITICAL" "Max crashes ($MAX_CRASHES_BEFORE_RESET) reached. Resetting and waiting 5 minutes..."
        reset_crash_count
        
        # Clear any stale locks/caches that might cause issues
        rm -f "$INSTALL_DIR/storage/framework/cache/data/*" 2>/dev/null
        rm -f "$INSTALL_DIR/storage/framework/sessions/*" 2>/dev/null
        
        sleep 300
        return 1
    fi
    return 0
}

# Run artisan command with timeout and error handling
run_artisan() {
    local command="$1"
    local timeout_seconds="${2:-120}"
    local exit_code=0
    
    cd "$INSTALL_DIR" || return 1
    
    # Run with timeout (if available)
    if command -v timeout &> /dev/null; then
        timeout "$timeout_seconds" "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    elif command -v gtimeout &> /dev/null; then
        # macOS with coreutils installed
        gtimeout "$timeout_seconds" "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    else
        # No timeout available, run directly
        "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    fi
    
    return $exit_code
}

# Health check - verify PHP and database are working
health_check() {
    cd "$INSTALL_DIR" || return 1
    
    # Quick health check using a simple artisan command
    if "$PHP_BIN" "$INSTALL_DIR/artisan" --version > /dev/null 2>&1; then
        return 0
    else
        log_message "WARNING" "Health check failed - artisan not responding"
        return 1
    fi
}

# Cleanup on exit
cleanup() {
    log_message "INFO" "Watchdog shutting down..."
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGTERM SIGINT

# Write PID file
echo $$ > "$PID_FILE"

log_message "INFO" "=== Security One IDS Watchdog Started ==="
log_message "INFO" "PHP: $PHP_BIN"
log_message "INFO" "Install Dir: $INSTALL_DIR"
log_message "INFO" "Scan Interval: ${SCAN_INTERVAL}s"
log_message "INFO" "Default Heartbeat Interval: ${DEFAULT_HEARTBEAT_INTERVAL}s (overridden by Hub config)"

# Reset crash count on fresh start
reset_crash_count

# Main watchdog loop
consecutive_failures=0
last_health_check=0

while true; do
    current_time=$(date +%s)
    
    # Periodic health check
    if [ $((current_time - last_health_check)) -ge $HEALTH_CHECK_INTERVAL ]; then
        if ! health_check; then
            log_message "WARNING" "Health check failed, waiting before retry..."
            sleep 10
            last_health_check=$current_time
            continue
        fi
        last_health_check=$current_time
    fi
    
    # Check crash limit before continuing
    if ! check_crash_limit; then
        continue
    fi
    
    # === WAF Sync (Heartbeat) ===
    log_message "INFO" "Running WAF sync (heartbeat)..."
    if run_artisan "waf:sync" 300; then
        log_message "INFO" "WAF sync completed successfully"
        consecutive_failures=0
    else
        exit_code=$?
        log_message "WARNING" "WAF sync failed with exit code $exit_code"
        consecutive_failures=$((consecutive_failures + 1))
        
        if [ $consecutive_failures -ge 3 ]; then
            log_message "ERROR" "Multiple consecutive failures, incrementing crash count"
            increment_crash_count
            consecutive_failures=0
            sleep 30
            continue
        fi
    fi
    
    # === Security Scan ===
    log_message "INFO" "Running security scan..."
    if run_artisan "desktop:scan --full" 300; then
        log_message "INFO" "Security scan completed successfully"
        consecutive_failures=0
        reset_crash_count  # Reset on successful run
    else
        exit_code=$?
        log_message "ERROR" "Security scan failed with exit code $exit_code"
        increment_crash_count
        consecutive_failures=$((consecutive_failures + 1))
        
        # Check for specific error conditions
        if [ $exit_code -eq 137 ] || [ $exit_code -eq 139 ]; then
            log_message "CRITICAL" "Process killed (OOM or SEGFAULT). Waiting 60s before retry..."
            sleep 60
        elif [ $exit_code -eq 255 ]; then
            log_message "ERROR" "PHP fatal error. Waiting 30s before retry..."
            sleep 30
        else
            log_message "WARNING" "Unknown error. Waiting 10s before retry..."
            sleep 10
        fi
        
        continue
    fi
    
    # Read dynamic heartbeat interval from Hub config
    heartbeat_interval=$DEFAULT_HEARTBEAT_INTERVAL
    if [ -f "$CONFIG_FILE" ]; then
        # Parse heartbeat_interval from JSON (using grep+sed for portability)
        hi=$(grep -o '"heartbeat_interval"[[:space:]]*:[[:space:]]*[0-9]*' "$CONFIG_FILE" 2>/dev/null | grep -o '[0-9]*$')
        if [ -n "$hi" ] && [ "$hi" -ge 5 ] && [ "$hi" -le 300 ]; then
            heartbeat_interval=$hi
        fi
    fi

    # Wait for heartbeat interval before next sync cycle
    log_message "INFO" "Waiting ${heartbeat_interval}s before next heartbeat (scan every ${SCAN_INTERVAL}s)..."
    
    # Use heartbeat interval for sync, but run desktop:scan less frequently
    elapsed_since_scan=0
    while [ $elapsed_since_scan -lt $SCAN_INTERVAL ]; do
        sleep $heartbeat_interval
        elapsed_since_scan=$((elapsed_since_scan + heartbeat_interval))
        
        # Run heartbeat sync
        if run_artisan "waf:sync" 300; then
            log_message "INFO" "Heartbeat sync OK"
        else
            log_message "WARNING" "Heartbeat sync failed"
        fi
        
        # Re-read interval in case Hub updated it
        if [ -f "$CONFIG_FILE" ]; then
            hi=$(grep -o '"heartbeat_interval"[[:space:]]*:[[:space:]]*[0-9]*' "$CONFIG_FILE" 2>/dev/null | grep -o '[0-9]*$')
            if [ -n "$hi" ] && [ "$hi" -ge 5 ] && [ "$hi" -le 300 ]; then
                heartbeat_interval=$hi
            fi
        fi
    done
done
