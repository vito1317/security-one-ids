#!/bin/bash
# Emergency IPS rollback — run this if connectivity breaks.
# Idempotent. Safe to re-run.

set +e
LOG=/var/log/security-one-ids/ips-panic.log
mkdir -p "$(dirname "$LOG")"
echo "$(date '+%F %T') PANIC rollback invoked by $USER" >> "$LOG"

# 1. Force mode back to ids so watchdog won't re-start IPS.
sed -i 's/"suricata_mode": "ips"/"suricata_mode": "ids"/' \
  /opt/security-one-ids/storage/app/waf_config.json 2>/dev/null

# 2. Kill Suricata.
systemctl stop suricata 2>/dev/null
pkill -9 -f '/usr/bin/suricata' 2>/dev/null
sleep 1

# 3. Remove every rule we installed (tagged with 'security-one-ids').
#    Admin-added rules (not tagged) are left alone.
for chain in INPUT FORWARD; do
  while iptables -L "$chain" -n --line-numbers 2>/dev/null | grep -q 'security-one-ids'; do
    N=$(iptables -L "$chain" -n --line-numbers | grep 'security-one-ids' | head -1 | awk '{print $1}')
    [ -z "$N" ] && break
    iptables -D "$chain" "$N" || break
  done
done

# 4. Report.
echo "=== INPUT after rollback ===" | tee -a "$LOG"
iptables -L INPUT -n --line-numbers | tee -a "$LOG"
echo "=== Suricata ps ===" | tee -a "$LOG"
ps -ef | grep suricata | grep -v grep | tee -a "$LOG" || echo "stopped" | tee -a "$LOG"
echo "$(date '+%F %T') PANIC rollback complete" >> "$LOG"
