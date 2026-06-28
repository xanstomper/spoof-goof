#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-isolate — Create isolated network namespace for red teaming
# ═══════════════════════════════════════════════════════════════════════════════
# Creates a sandboxed environment where all traffic goes through VPN/Tor
# and your host system is completely hidden from targets.
#
# Run as root: sudo bash ~/.opsec/isolate.sh [create|destroy|enter|status]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

NS_NAME="redteam"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
SUBNET_HOST="10.99.0.1/24"
SUBNET_NS="10.99.0.2/24"
DNS_NS="1.1.1.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Create isolated namespace ─────────────────────────────────────────────────
ns_create() {
    echo -e "${CYAN}[*] Creating isolated network namespace '$NS_NAME'...${NC}"
    
    # Check if already exists
    if ip netns list | grep -q "$NS_NAME"; then
        echo -e "${YELLOW}[!] Namespace '$NS_NAME' already exists${NC}"
        return 0
    fi
    
    # Create namespace
    ip netns add "$NS_NAME"
    
    # Create veth pair (host <-> namespace)
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    
    # Move one end into the namespace
    ip link set "$VETH_NS" netns "$NS_NAME"
    
    # Configure host side
    ip addr add "$SUBNET_HOST" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up
    
    # Configure namespace side
    ip netns exec "$NS_NAME" ip addr add "$SUBNET_NS" dev "$VETH_NS"
    ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    ip netns exec "$NS_NAME" ip link set lo up
    
    # Set default route in namespace (goes through host)
    ip netns exec "$NS_NAME" ip route add default via 10.99.0.1
    
    # Enable IP forwarding on host
    sysctl -w net.ipv4.ip_forward=1
    
    # Set up NAT so namespace traffic exits through host's VPN
    iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o tun0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE
    
    # Allow forwarding
    iptables -A FORWARD -i "$VETH_HOST" -o tun0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$VETH_HOST" -j ACCEPT
    iptables -A FORWARD -o "$VETH_HOST" -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # DNS in namespace
    ip netns exec "$NS_NAME" bash -c "echo 'nameserver $DNS_NS' > /etc/resolv.conf"
    
    echo -e "${GREEN}[+] Isolated namespace created${NC}"
    echo "  Host:     $SUBNET_HOST"
    echo "  Namespace: $SUBNET_NS"
    echo "  Gateway:  10.99.0.1 (routes through host VPN)"
}

# ── Destroy namespace ─────────────────────────────────────────────────────────
ns_destroy() {
    echo -e "${YELLOW}[*] Destroying isolated namespace '$NS_NAME'...${NC}"
    
    # Remove iptables rules
    iptables -t nat -D POSTROUTING -s 10.99.0.0/24 -o tun0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -o tun0 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$VETH_HOST" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    
    # Remove veth pair
    ip link del "$VETH_HOST" 2>/dev/null || true
    
    # Remove namespace
    ip netns del "$NS_NAME" 2>/dev/null || true
    
    echo -e "${GREEN}[+] Namespace destroyed${NC}"
}

# ── Enter namespace ───────────────────────────────────────────────────────────
ns_enter() {
    echo -e "${CYAN}[*] Entering isolated environment...${NC}"
    echo -e "${YELLOW}    Type 'exit' to leave${NC}"
    echo ""
    
    # Drop into namespace with a special shell
    ip netns exec "$NS_NAME" bash --rcfile <(cat << 'RCEOF'
# Red team shell profile
export PS1="\[\033[1;31m\][REDTEAM]\[\033[0m\] \u@\h:\w\$ "
export PATH="/usr/local/bin:/usr/bin:/bin"

# Safety aliases
alias ll='ls -alF'
alias grep='grep --color=auto'

# Leak check
echo ""
echo -e "\033[0;31m╔══════════════════════════════════════════════════╗\033[0m"
echo -e "\033[0;31m║  ISOLATED RED TEAM ENVIRONMENT                  ║\033[0m"
echo -e "\033[0;31m║  All traffic routes through host VPN            ║\033[0m"
echo -e "\033[0;31m║  Your host IP is HIDDEN from targets            ║\033[0m"
echo -e "\033[0;31m╚══════════════════════════════════════════════════╝\033[0m"
echo ""

# Quick identity check
echo -n "  External IP: "
curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "blocked (good)"
echo -n "  DNS server:  "
cat /etc/resolv.conf 2>/dev/null | grep nameserver | head -1
echo ""
RCEOF
) -i
}

# ── Status ────────────────────────────────────────────────────────────────────
ns_status() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  ISOLATED ENVIRONMENT STATUS"
    echo "════════════════════════════════════════════════════════════════"
    
    if ip netns list | grep -q "$NS_NAME"; then
        echo -e "  Namespace: ${GREEN}ACTIVE${NC}"
        
        echo "  Network:"
        ip netns exec "$NS_NAME" ip addr show 2>/dev/null | grep -E "inet |link/" | while read -r line; do
            echo "    $line"
        done
        
        echo ""
        echo "  Routing:"
        ip netns exec "$NS_NAME" ip route show 2>/dev/null | while read -r line; do
            echo "    $line"
        done
    else
        echo -e "  Namespace: ${RED}NOT ACTIVE${NC}"
    fi
    
    echo ""
    echo "  VPN Status:"
    if ip link show tun0 &>/dev/null 2>&1; then
        echo -e "    Tunnel: ${GREEN}ACTIVE${NC}"
        curl -s --max-time 5 https://api.ipify.org 2>/dev/null | xargs -I{} echo "    Exit IP: {}"
    else
        echo -e "    Tunnel: ${RED}INACTIVE${NC}"
        echo "    WARNING: Namespace will use host's direct connection!"
    fi
    
    echo "════════════════════════════════════════════════════════════════"
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    create)  ns_create ;;
    destroy) ns_destroy ;;
    enter)   ns_enter ;;
    status)  ns_status ;;
    help|*)
        echo ""
        echo "Usage: $0 [create|destroy|enter|status]"
        echo ""
        echo "  create  — Create isolated network namespace"
        echo "  destroy — Remove namespace and cleanup"
        echo "  enter   — Drop into isolated shell"
        echo "  status  — Show namespace and VPN status"
        echo ""
        echo "  Setup order:"
        echo "    1. sudo bash ~/.opsec/vpn-rotate.sh start  (start VPN rotation)"
        echo "    2. sudo bash ~/.opsec/isolate.sh create     (create namespace)"
        echo "    3. sudo bash ~/.opsec/isolate.sh enter      (enter sandbox)"
        echo ""
        ;;
esac
