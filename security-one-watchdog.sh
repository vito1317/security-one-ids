#!/bin/bash
# Security One IDS - Multi-Threaded Watchdog Wrapper
# Runs 3 independent background loops: heartbeat, sync, scan
# Version 3.0 - True multi-threaded with independent process loops

INSTALL_DIR="/opt/security-one-ids"
LOG_DIR="/var/log/security-one-ids"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
PID_FILE="$INSTALL_DIR/storage/ids.pid"
CRASH_COUNT_FILE="$INSTALL_DIR/storage/crash_count"
MAX_CRASHES_BEFORE_RESET=5
SCAN_INTERVAL=300  # Security scan interval (5 min)
DEFAULT_HEARTBEAT_INTERVAL=60
CONFIG_FILE="$INSTALL_DIR/storage/app/waf_config.json"

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
        gtimeout "$timeout_seconds" "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    else
        "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    fi
    
    return $exit_code
}

# Read heartbeat interval from Hub config
get_heartbeat_interval() {
    local interval=$DEFAULT_HEARTBEAT_INTERVAL
    if [ -f "$CONFIG_FILE" ]; then
        local hi=$(grep -o '"heartbeat_interval"[[:space:]]*:[[:space:]]*[0-9]*' "$CONFIG_FILE" 2>/dev/null | grep -o '[0-9]*$')
        if [ -n "$hi" ] && [ "$hi" -ge 5 ] && [ "$hi" -le 300 ]; then
            interval=$hi
        fi
    fi
    echo "$interval"
}

# Auto-install Snort 3 on Linux if not found
 # ensure_snort_installed () {
    # Only run on Linux
    if [[ "$OSTYPE" == "darwin"* ]]; then
        return 0
    fi

    # Check if Snort is already installed
    if command -v snort &>/dev/null || command -v snort3 &>/dev/null; then
        local ver=$(snort -V 2>&1 | grep -oP 'Version\s+\K[\d.]+' || snort3 -V 2>&1 | grep -oP 'Version\s+\K[\d.]+' || echo "unknown")
        log_message "INFO" "Snort already installed: $ver"
        return 0
    fi

    # Check common paths
    for p in /usr/local/bin/snort /usr/sbin/snort /usr/bin/snort /usr/local/bin/snort3; do
        if [ -x "$p" ]; then
            log_message "INFO" "Snort found at $p"
            return 0
        fi
    done

    log_message "INFO" "Snort not found, auto-installing Snort 3..."
    local MARKER="$INSTALL_DIR/storage/snort3_install_attempted"

    # Prevent repeated install attempts
    if [ -f "$MARKER" ]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$MARKER" 2>/dev/null || echo 0) ))
        if [ "$age" -lt 86400 ]; then
            log_message "WARNING" "Snort 3 install was attempted less than 24h ago, skipping"
            return 1
        fi
    fi
    touch "$MARKER"

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        log_message "INFO" "Installing build dependencies (apt)..."
        apt-get update -qq 2>/dev/null
        apt-get install -y build-essential libpcap-dev libpcre2-dev \
            libdnet-dev zlib1g-dev cmake libhwloc-dev pkg-config \
            libluajit-5.1-dev libssl-dev libsafec-dev \
            flex bison curl git autoconf automake libtool \
            libgoogle-perftools-dev 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        log_message "INFO" "Installing build dependencies (yum)..."
        yum install -y gcc gcc-c++ make libpcap-devel pcre2-devel \
            libdnet-devel zlib-devel cmake hwloc-devel \
            luajit-devel openssl-devel \
            flex bison curl git autoconf automake libtool \
            gperftools-devel 2>/dev/null || true
    else
        log_message "ERROR" "No supported package manager found (apt/yum)"
        return 1
    fi

    # Build libdaq from source
    log_message "INFO" "Building libdaq..."
    cd /tmp
    rm -rf libdaq
    if git clone --depth 1 https://github.com/snort3/libdaq.git 2>/dev/null; then
        cd libdaq
        ./bootstrap 2>/dev/null && ./configure --prefix=/usr/local 2>/dev/null && \
        make -j$(nproc) 2>/dev/null && make install 2>/dev/null && ldconfig
        cd /tmp && rm -rf libdaq
        log_message "INFO" "libdaq installed"
    else
        log_message "ERROR" "Failed to clone libdaq"
        return 1
    fi

    # Fetch latest Snort 3 version
    local SNORT_VER=$(curl -fsSL https://api.github.com/repos/snort3/snort3/releases/latest 2>/dev/null \
        | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o '[0-9][0-9.]*' || echo "")
    if [ -z "$SNORT_VER" ]; then
        SNORT_VER="3.6.2.0"
        log_message "INFO" "Using fallback Snort version: $SNORT_VER"
    else
        log_message "INFO" "Latest Snort 3 version: $SNORT_VER"
    fi

    # Download and build Snort 3
    log_message "INFO" "Building Snort 3 v${SNORT_VER} (this may take 5-10 minutes)..."
    cd /tmp
    curl -fsSL -o "snort3-${SNORT_VER}.tar.gz" \
        "https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VER}.tar.gz" 2>/dev/null

    if [ ! -f "snort3-${SNORT_VER}.tar.gz" ]; then
        log_message "ERROR" "Failed to download Snort 3 source"
        return 1
    fi

    tar xzf "snort3-${SNORT_VER}.tar.gz"
    cd "snort3-${SNORT_VER}"
    mkdir -p build && cd build
    if cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DENABLE_TCMALLOC=ON 2>/dev/null && \
       make -j$(nproc) 2>/dev/null && \
       make install 2>/dev/null; then
        ldconfig
        cd /tmp && rm -rf "snort3-${SNORT_VER}"*

        # Ensure snort is in PATH
        if [ -f /usr/local/bin/snort ] && ! command -v snort &>/dev/null; then
            ln -sf /usr/local/bin/snort /usr/bin/snort
        fi

        # Create default directories and config
        mkdir -p /var/log/snort /etc/snort/rules 2>/dev/null
        chmod 755 /var/log/snort /etc/snort /etc/snort/rules

        if [ ! -f /etc/snort/snort.lua ]; then
            cat > /etc/snort/snort.lua << 'SNORTLUA'
-- Security One IDS - Auto-generated Snort 3 config
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    variables = default_variables,
}

alert_json = {
    file = true,
    limit = 100,
    fields = 'timestamp sig_id sig_rev msg src_addr src_port dst_addr dst_port proto action class priority',
}
SNORTLUA
        fi

        local installed_ver=$(snort -V 2>&1 | grep -oP 'Version\s+\K[\d.]+' || echo "unknown")
        log_message "INFO" "Snort 3 installed successfully: v${installed_ver}"
        return 0
    else
        log_message "ERROR" "Failed to build Snort 3"
        cd /tmp && rm -rf "snort3-${SNORT_VER}"*
        return 1
    fi
}

# Cleanup all child processes on exit
CHILD_PIDS=()
cleanup() {
    log_message "INFO" "Watchdog shutting down, stopping all child processes..."
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    rm -f "$PID_FILE"
    log_message "INFO" "Watchdog stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGHUP

# Write PID file
echo $$ > "$PID_FILE"

log_message "INFO" "=== Security One IDS Multi-Threaded Watchdog v3.0 ==="
log_message "INFO" "PHP: $PHP_BIN"
log_message "INFO" "Install Dir: $INSTALL_DIR"

# Auto-install Snort if not present
 # ensure_snort_installed 

# ============================================================
# Thread 1: HEARTBEAT (independent, high-frequency)
# Never blocked by sync or scan operations
# ============================================================
heartbeat_loop() {
    log_message "INFO" "[Thread:Heartbeat] Started"
    local failures=0
    
    while true; do
        if run_artisan "waf:heartbeat" 60; then
            log_message "INFO" "[Thread:Heartbeat] OK"
            failures=0
        else
            failures=$((failures + 1))
            log_message "WARNING" "[Thread:Heartbeat] Failed (consecutive: $failures)"
            
            if [ $failures -ge 5 ]; then
                log_message "ERROR" "[Thread:Heartbeat] Too many failures, waiting 60s"
                sleep 60
                failures=0
                continue
            fi
        fi
        
        local interval=$(get_heartbeat_interval)
        sleep "$interval"
    done
}

# ============================================================
# Thread 2: SYNC (rule sync, Snort management, maintenance)
# Uses Process::pool internally for sub-parallelism
# ============================================================
sync_loop() {
    log_message "INFO" "[Thread:Sync] Started"
    local crash_count=0
    
    while true; do
        if run_artisan "waf:sync" 600; then
            log_message "INFO" "[Thread:Sync] Completed"
            crash_count=0
        else
            exit_code=$?
            crash_count=$((crash_count + 1))
            log_message "ERROR" "[Thread:Sync] Failed (exit: $exit_code, crashes: $crash_count)"
            
            if [ $crash_count -ge $MAX_CRASHES_BEFORE_RESET ]; then
                log_message "CRITICAL" "[Thread:Sync] Max crashes reached, cooling down 5min"
                crash_count=0
                rm -f "$INSTALL_DIR/storage/framework/cache/data/*" 2>/dev/null
                sleep 300
                continue
            fi
            
            # Backoff on specific errors
            if [ $exit_code -eq 137 ] || [ $exit_code -eq 139 ]; then
                sleep 60
            else
                sleep 10
            fi
        fi
        
        # Sync runs less frequently than heartbeat
        local interval=$(get_heartbeat_interval)
        local sync_wait=$((interval * 3))
        [ $sync_wait -lt 60 ] && sync_wait=60
        [ $sync_wait -gt 600 ] && sync_wait=600
        sleep "$sync_wait"
    done
}

# ============================================================
# Thread 3: SCAN (desktop security scan + AI analysis)
# Runs every SCAN_INTERVAL, completely independent
# ============================================================
scan_loop() {
    log_message "INFO" "[Thread:Scan] Started (interval: ${SCAN_INTERVAL}s)"
    
    while true; do
        log_message "INFO" "[Thread:Scan] Starting security scan..."
        if run_artisan "desktop:scan --full" 600; then
            log_message "INFO" "[Thread:Scan] Completed"
        else
            log_message "WARNING" "[Thread:Scan] Failed"
        fi
        
        sleep $SCAN_INTERVAL
    done
}

# ============================================================
# Launch all 3 threads as background processes
# ============================================================
log_message "INFO" "Launching 3 independent threads..."

heartbeat_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → Heartbeat thread: PID $!"

sync_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → Sync thread: PID $!"

scan_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → Scan thread: PID $!"

log_message "INFO" "All threads launched. Monitoring..."

# Main watchdog: monitor child processes, restart if they die
while true; do
    for i in "${!CHILD_PIDS[@]}"; do
        pid=${CHILD_PIDS[$i]}
        labels=("Heartbeat" "Sync" "Scan")
        label=${labels[$i]:-"Unknown"}
        
        if ! kill -0 "$pid" 2>/dev/null; then
            log_message "CRITICAL" "[Thread:$label] Process $pid died! Restarting..."
            
            case $i in
                0) heartbeat_loop & ;;
                1) sync_loop & ;;
                2) scan_loop & ;;
            esac
            CHILD_PIDS[$i]=$!
            log_message "INFO" "[Thread:$label] Restarted as PID ${CHILD_PIDS[$i]}"
        fi
    done
    
    sleep 30
done
