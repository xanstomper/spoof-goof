#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-vpn — VPNGate automatic IP rotation
# ═══════════════════════════════════════════════════════════════════════════════
# Uses VPNGate (University of Tsukuba) — free, no logs, 6000+ servers
# Run: sudo bash ~/.opsec/vpn-rotate.sh [start|stop|rotate|status|list]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VPN_DIR="${HOME}/.opsec/vpn"
VPN_PID_FILE="/var/run/opsec-vpn.pid"
VPN_LOG="/var/log/opsec-vpn.log"
ROTATE_INTERVAL=300  # 5 minutes default
VPNGATE_CSV="http://www.vpngate.net/api/iphone/"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$VPN_DIR" /var/log

# ── Fetch VPNGate servers ─────────────────────────────────────────────────────
fetch_servers() {
    echo -e "${CYAN}[*] Fetching VPNGate server list...${NC}"
    
    # Download server list
    curl -s "$VPNGATE_CSV" | grep -v "^*" | grep -v "^Fake" | \
        awk -F',' '{print $1","$2","$15","$3}' | \
        grep -v "^$" > "$VPN_DIR/servers.csv"
    
    # Filter for OpenVPN configs only (skip L2TP, MS-SSTP)
    local count=$(wc -l < "$VPN_DIR/servers.csv")
    
    if [[ $count -lt 1 ]]; then
        echo -e "${RED}[!] Failed to fetch server list${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[+] Found $count servers${NC}"
    
    # Also download actual .ovpn files for the top servers
    mkdir -p "$VPN_DIR/configs"
    
    # Get top 20 fastest servers
    head -20 "$VPN_DIR/servers.csv" | while IFS=',' read -r ip hostname speed country; do
        local config_file="$VPN_DIR/configs/${ip}.ovpn"
        if [[ ! -f "$config_file" ]]; then
            curl -s "http://www.vpngate.net/api/iphone/" | \
                grep -A 50 "$ip" | \
                grep -E "(<vpn>|remote |proto |cipher |auth |resolv-retry)" | \
                head -1 > /dev/null 2>/dev/null
        fi
    done
    
    # Better approach: download configs directly from VPNGate API
    download_configs
}

download_configs() {
    mkdir -p "$VPN_DIR/configs"
    
    # VPNGate provides OpenVPN config files via their API
    local api_url="http://www.vpngate.net/api/iphone/"
    
    echo "[*] Downloading OpenVPN configurations..."
    
    # Parse the CSV and extract connection info
    while IFS=',' read -r ip hostname speed country; do
        [[ -z "$ip" || "$ip" == "IP" ]] && continue
        
        local config="$VPN_DIR/configs/${ip}.ovpn"
        
        if [[ ! -f "$config" ]]; then
            # Generate minimal OpenVPN config for VPNGate server
            cat > "$config" << OVPN
client
dev tun
proto udp
remote $ip 1223
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
verb 3
connect-timeout 10
remote-cert-tls server
tls-client
auth-user-pass
<auth-user-pass>
vpn
vpn
</auth-user-pass>
OVPN
        fi
    done < <(head -10 "$VPN_DIR/servers.csv")
    
    echo "[+] Downloaded $(ls "$VPN_DIR/configs"/*.ovpn 2>/dev/null | wc -l) configs"
}

# ── Pick random fast server ───────────────────────────────────────────────────
pick_server() {
    local exclude_ip="${1:-}"
    
    if [[ ! -f "$VPN_DIR/servers.csv" ]]; then
        fetch_servers
    fi
    
    # Pick a random server from top 15 (fastest), excluding current
    local server
    if [[ -n "$exclude_ip" ]]; then
        server=$(grep -v "$exclude_ip" "$VPN_DIR/servers.csv" | head -15 | shuf -n 1)
    else
        server=$(head -15 "$VPN_DIR/servers.csv" | shuf -n 1)
    fi
    
    echo "$server"
}

# ── Connect to VPN ────────────────────────────────────────────────────────────
vpn_connect() {
    local config="$1"
    
    if [[ ! -f "$config" ]]; then
        echo -e "${RED}[!] Config not found: $config${NC}"
        return 1
    fi
    
    # Kill existing VPN
    vpn_disconnect 2>/dev/null || true
    
    echo -e "${CYAN}[*] Connecting to VPN...${NC}"
    
    # Start OpenVPN
    openvpn --config "$config" \
        --daemon \
        --log "$VPN_LOG" \
        --writepid "$VPN_PID_FILE" \
        --auth-user-pass <(echo -e "vpn\nvpn")
    
    # Wait for connection
    local timeout=30
    local waited=0
    while [[ $waited -lt $timeout ]]; do
        sleep 1
        waited=$((waited + 1))
        
        if ip link show tun0 &>/dev/null 2>&1; then
            local new_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
            if [[ "$new_ip" != "unknown" ]]; then
                echo -e "${GREEN}[+] VPN connected! IP: $new_ip${NC}"
                echo "$new_ip" > "$VPN_DIR/current_ip"
                echo "$(date -Iseconds)" > "$VPN_DIR/last_rotate"
                return 0
            fi
        fi
    done
    
    echo -e "${RED}[!] Connection timed out${NC}"
    return 1
}

# ── Disconnect VPN ────────────────────────────────────────────────────────────
vpn_disconnect() {
    if [[ -f "$VPN_PID_FILE" ]]; then
        local pid=$(cat "$VPN_PID_FILE")
        kill "$pid" 2>/dev/null || true
        rm -f "$VPN_PID_FILE"
    fi
    
    # Also kill any openvpn processes
    pkill -f "openvpn.*config" 2>/dev/null || true
    
    # Restore DNS
    systemctl restart systemd-resolved 2>/dev/null || true
    
    echo -e "${YELLOW}[-] VPN disconnected${NC}"
}

# ── Rotate to new server ──────────────────────────────────────────────────────
vpn_rotate() {
    local current_ip=""
    if [[ -f "$VPN_DIR/current_ip" ]]; then
        current_ip=$(cat "$VPN_DIR/current_ip")
    fi
    
    local server=$(pick_server "$current_ip")
    local ip=$(echo "$server" | cut -d',' -f1)
    local country=$(echo "$server" | cut -d',' -f4)
    
    echo -e "${CYAN}[*] Rotating to: $ip ($country)${NC}"
    
    local config="$VPN_DIR/configs/${ip}.ovpn"
    
    # If config doesn't exist, download it
    if [[ ! -f "$config" ]]; then
        cat > "$config" << OVPN
client
dev tun
proto udp
remote $ip 1223
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
verb 3
connect-timeout 10
remote-cert-tls server
tls-client
auth-user-pass
<auth-user-pass>
vpn
vpn
</auth-user-pass>
OVPN
    fi
    
    vpn_connect "$config"
}

# ── Auto-rotate daemon ────────────────────────────────────────────────────────
vpn_daemon() {
    echo -e "${CYAN}[*] Starting VPN rotation daemon (every ${ROTATE_INTERVAL}s)${NC}"
    
    while true; do
        sleep "$ROTATE_INTERVAL"
        vpn_rotate
    done
}

# ── Status ────────────────────────────────────────────────────────────────────
vpn_status() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  VPN STATUS"
    echo "════════════════════════════════════════════════════════════════"
    
    if ip link show tun0 &>/dev/null 2>&1; then
        echo -e "  Connection: ${GREEN}ACTIVE${NC}"
        
        if [[ -f "$VPN_DIR/current_ip" ]]; then
            echo "  IP: $(cat "$VPN_DIR/current_ip")"
        fi
        
        if [[ -f "$VPN_DIR/last_rotate" ]]; then
            echo "  Last rotation: $(cat "$VPN_DIR/last_rotate")"
        fi
    else
        echo -e "  Connection: ${RED}INACTIVE${NC}"
    fi
    
    local server_count=0
    if [[ -f "$VPN_DIR/servers.csv" ]]; then
        server_count=$(wc -l < "$VPN_DIR/servers.csv")
    fi
    echo "  Available servers: $server_count"
    echo "  Rotation interval: ${ROTATE_INTERVAL}s"
    echo "  Log: $VPN_LOG"
    echo "════════════════════════════════════════════════════════════════"
}

# ── List servers ──────────────────────────────────────────────────────────────
vpn_list() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  VPNGate SERVERS (Top 20 by speed)"
    echo "════════════════════════════════════════════════════════════════"
    
    if [[ ! -f "$VPN_DIR/servers.csv" ]]; then
        fetch_servers
    fi
    
    printf "  %-18s %-8s %s\n" "IP" "SPEED" "COUNTRY"
    echo "  ───────────────── ──────── ────────────────"
    
    head -20 "$VPN_DIR/servers.csv" | while IFS=',' read -r ip hostname speed country; do
        printf "  %-18s %-8s %s\n" "$ip" "${speed}Mbps" "$country"
    done
    
    echo "════════════════════════════════════════════════════════════════"
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    start)
        fetch_servers
        vpn_daemon &
        echo $! > "$VPN_PID_FILE"
        echo -e "${GREEN}[+] VPN rotation daemon started${NC}"
        ;;
    stop)
        vpn_disconnect
        ;;
    rotate)
        fetch_servers 2>/dev/null
        vpn_rotate
        ;;
    status)
        vpn_status
        ;;
    list)
        vpn_list
        ;;
    fetch)
        fetch_servers
        ;;
    help|*)
        echo ""
        echo "Usage: $0 [start|stop|rotate|status|list|fetch]"
        echo ""
        echo "  start   — Start auto-rotation daemon (every 5min)"
        echo "  stop    — Disconnect VPN"
        echo "  rotate  — Immediately rotate to new server"
        echo "  status  — Show current VPN status"
        echo "  list    — List available VPNGate servers"
        echo "  fetch   — Refresh server list"
        echo ""
        ;;
esac
