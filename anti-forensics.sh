#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-wipe — Anti-forensics: clean traces after engagement
# ═══════════════════════════════════════════════════════════════════════════════
# Run AFTER every engagement to clean all traces
# Usage: sudo bash ~/.opsec/anti-forensics.sh [quick|full|nuclear]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MODE="${1:-quick}"
CLEANED=0

wipe() {
    local target="$1"
    local desc="$2"
    
    if [[ -e "$target" ]]; then
        if [[ -d "$target" ]]; then
            rm -rf "$target" 2>/dev/null || true
        else
            # Overwrite before delete for sensitive files
            shred -u "$target" 2>/dev/null || rm -f "$target" 2>/dev/null || true
        fi
        echo -e "  ${GREEN}wiped${NC} $desc"
        CLEANED=$((CLEANED + 1))
    fi
}

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC ANTI-FORENSICS — MODE: $MODE"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ── 1. Shell History ──────────────────────────────────────────────────────────
echo -e "${CYAN}[1/6] Wiping shell history...${NC}"

wipe ~/.bash_history "bash history"
wipe ~/.zsh_history "zsh history"
wipe ~/.python_history "python history"
wipe ~/.mysql_history "mysql history"
wipe ~/.psql_history "psql history"

# Clear current session history
history -c 2>/dev/null || true
unset HISTFILE 2>/dev/null || true

# Wipe in-memory history
cat /dev/null > ~/.bash_history 2>/dev/null || true

echo -e "  ${GREEN}done${NC}"

# ── 2. System Logs ────────────────────────────────────────────────────────────
echo -e "${CYAN}[2/6] Cleaning system logs...${NC}"

# Auth logs
wipe /var/log/auth.log "auth log"
wipe /var/log/syslog "syslog"
wipe /var/log/kern.log "kernel log"
wipe /var/log/dmesg "dmesg"
wipe /var/log/dmesg.0 "dmesg old"

# Journal logs
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true

# Clear wtmp/btmp (login records)
> /var/log/wtmp 2>/dev/null || true
> /var/log/btmp 2>/dev/null || true
> /var/log/lastlog 2>/dev/null || true

# Clear utmp (current logins)
> /var/run/utmp 2>/dev/null || true

echo -e "  ${GREEN}done${NC}"

# ── 3. Application Logs ──────────────────────────────────────────────────────
echo -e "${CYAN}[3/6] Cleaning application logs...${NC}"

# Docker logs
docker system prune -f 2>/dev/null || true
find /var/lib/docker/containers -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true

# Tor logs
wipe /var/log/tor/ "tor logs"
mkdir -p /var/log/tor && chmod 700 /var/log/tor

# VPN logs
wipe /var/log/opsec-vpn.log "VPN logs"
wipe /var/log/openvpn/ "openvpn logs"

# Audit logs
wipe /var/log/audit/ "audit logs"

# Nginx/Apache
wipe /var/log/nginx/ "nginx logs"
wipe /var/log/apache2/ "apache logs"

echo -e "  ${GREEN}done${NC}"

# ── 4. Temporary Files ────────────────────────────────────────────────────────
echo -e "${CYAN}[4/6] Wiping temporary files...${NC}"

# System tmp
find /tmp -type f -delete 2>/dev/null || true
find /var/tmp -type f -delete 2>/dev/null || true

# Shared memory
find /dev/shm -type f -delete 2>/dev/null || true

# Browser caches
wipe ~/.cache/google-chrome/ "Chrome cache"
wipe ~/.cache/mozilla/ "Firefox cache"
wipe ~/.cache/thunderbird/ "Thunderbird cache"

# Package manager caches
wipe ~/.cache/pip/ "pip cache"
wipe ~/.npm/_cacache/ "npm cache"
wipe ~/.cache/yarn/ "yarn cache"

# Thumbnail cache
wipe ~/.cache/thumbnails/ "thumbnail cache"

echo -e "  ${GREEN}done${NC}"

# ── 5. OPSEC-Specific Cleanup ────────────────────────────────────────────────
echo -e "${CYAN}[5/6] Cleaning OPSEC artifacts...${NC}"

# Reports from honeypot scans
wipe "${HOME}/.opsec/reports/" "scan reports"

# Docker container data (inside containers)
for container in $(docker ps -a --filter "name=opsec-" --format "{{.Names}}" 2>/dev/null); do
    docker exec "$container" bash -c "
        history -c 2>/dev/null
        find /tmp -type f -delete 2>/dev/null
        find /home/redteam/.cache -type f -delete 2>/dev/null
        cat /dev/null > /home/redteam/.bash_history 2>/dev/null
    " 2>/dev/null || true
    echo "  Cleaned container: $container"
done

# Clear DNS cache
systemd-resolve --flush-caches 2>/dev/null || true

# Clear ARP cache
ip neigh flush all 2>/dev/null || true

echo -e "  ${GREEN}done${NC}"

# ── 6. Network Traces ────────────────────────────────────────────────────────
echo -e "${CYAN}[6/6] Cleaning network traces...${NC}"

# Clear iptables counters
iptables -Z 2>/dev/null || true

# Clear connection tracking
conntrack -F 2>/dev/null || true

# Clear route cache
ip route flush cache 2>/dev/null || true

# Rotate MAC if configured
if [[ -f "${HOME}/.opsec/mac-randomize.sh" ]]; then
    bash "${HOME}/.opsec/mac-randomize.sh" 2>/dev/null || true
fi

echo -e "  ${GREEN}done${NC}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ANTI-FORENSICS COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo "  Items cleaned: $CLEANED"
echo "  Mode: $MODE"
echo ""

if [[ "$MODE" == "full" || "$MODE" == "nuclear" ]]; then
    echo -e "  ${YELLOW}Additional recommendations:${NC}"
    echo "    - Reboot to clear kernel memory"
    echo "    - Run: sudo journalctl --rotate && sudo journalctl --vacuum-time=1s"
    echo "    - Check: sudo lsof | grep deleted (find lingering file handles)"
fi

if [[ "$MODE" == "nuclear" ]]; then
    echo ""
    echo -e "  ${RED}NUCLEAR MODE — Additional steps:${NC}"
    echo "    - sudo docker system prune -a --volumes"
    echo "    - sudo find / -name '*.log' -exec truncate -s 0 {} \;"
    echo "    - sudo swapoff -a && sudo mkswap /dev/sda2 && sudo swapon -a"
    echo "    - Consider: sudo systemctl stop tor && sudo rm -rf /var/lib/tor/*"
fi

echo "════════════════════════════════════════════════════════════════"
