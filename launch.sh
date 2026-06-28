#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-launch — Full red team environment launcher
# ═══════════════════════════════════════════════════════════════════════════════
# Chains: VPN rotation → Tor → Isolated Docker container → Honeypot detection
# Usage: sudo bash ~/.opsec/launch.sh [up|down|status|scan <target>]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="${HOME}/.opsec"
VM_DIR="${SCRIPT_DIR}/vm"
LOG_DIR="${SCRIPT_DIR}/logs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$LOG_DIR" "${VM_DIR}/workspace" "${SCRIPT_DIR}/reports"

log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
preflight() {
    log "${CYAN}Running pre-flight checks...${NC}"
    
    local ok=1
    
    # Check Docker
    if ! docker info &>/dev/null; then
        echo -e "${RED}[FAIL] Docker is not running${NC}"
        ok=0
    else
        echo -e "${GREEN}  [OK] Docker running${NC}"
    fi
    
    # Check firewall
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "${GREEN}  [OK] Firewall active${NC}"
    else
        echo -e "${YELLOW}  [WARN] Firewall not active${NC}"
    fi
    
    # Check Tor
    if systemctl is-active tor &>/dev/null; then
        echo -e "${GREEN}  [OK] Tor running${NC}"
    else
        echo -e "${YELLOW}  [WARN] Tor not running — starting...${NC}"
        systemctl start tor 2>/dev/null || true
    fi
    
    # Check kernel hardening
    local redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "1")
    if [[ "$redirects" == "0" ]]; then
        echo -e "${GREEN}  [OK] Kernel hardened${NC}"
    else
        echo -e "${YELLOW}  [WARN] Kernel not hardened — run: sudo bash ~/.opsec/harden.sh${NC}"
    fi
    
    # Check disk space
    local free_gb=$(df -BG / | tail -1 | awk '{print $4}' | tr -d 'G')
    if [[ $free_gb -lt 5 ]]; then
        echo -e "${RED}  [FAIL] Low disk space: ${free_gb}GB free${NC}"
        ok=0
    else
        echo -e "${GREEN}  [OK] Disk space: ${free_gb}GB free${NC}"
    fi
    
    return $ok
}

# ── Start VPN rotation ───────────────────────────────────────────────────────
start_vpn() {
    log "Starting VPN rotation..."
    
    # Fetch VPNGate servers
    bash "$SCRIPT_DIR/vpn-rotate.sh" fetch 2>/dev/null || true
    
    # Start rotation daemon
    bash "$SCRIPT_DIR/vpn-rotate.sh" start 2>/dev/null &
    
    sleep 3
    
    if ip link show tun0 &>/dev/null 2>&1; then
        local ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
        echo -e "${GREEN}  [OK] VPN connected: $ip${NC}"
    else
        echo -e "${YELLOW}  [WARN] VPN not connected yet — may take a moment${NC}"
    fi
}

# ── Build Docker environment ──────────────────────────────────────────────────
build_env() {
    log "Building isolated Docker environment..."
    
    cd "$VM_DIR"
    
    # Build the red team container
    docker compose build --quiet 2>&1 | tail -5
    
    echo -e "${GREEN}  [OK] Container built${NC}"
}

# ── Launch full stack ─────────────────────────────────────────────────────────
launch_up() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  OPSEC RED TEAM ENVIRONMENT — LAUNCHING"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    
    preflight || {
        echo -e "${RED}Pre-flight checks failed. Fix issues above.${NC}"
        return 1
    }
    
    echo ""
    start_vpn
    echo ""
    build_env
    echo ""
    
    log "Starting container stack..."
    cd "$VM_DIR"
    docker compose up -d 2>&1 | tail -5
    
    sleep 5
    
    # Verify containers
    local running=$(docker ps --filter "name=opsec-" --format "{{.Names}}" | wc -l)
    echo -e "${GREEN}  [OK] $running containers running${NC}"
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  ENVIRONMENT READY"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Enter the isolated shell:"
    echo "    docker exec -it opsec-redteam bash"
    echo ""
    echo "  Or use the shortcut:"
    echo "    opsec-enter"
    echo ""
    echo "  Scan a target (honeypot check first):"
    echo "    opsec-scan <target-ip>"
    echo ""
    echo "  Tear down:"
    echo "    opsec-down"
    echo "════════════════════════════════════════════════════════════════"
}

# ── Tear down ─────────────────────────────────────────────────────────────────
launch_down() {
    log "Tearing down environment..."
    
    cd "$VM_DIR"
    docker compose down 2>/dev/null || true
    
    # Stop VPN
    bash "$SCRIPT_DIR/vpn-rotate.sh" stop 2>/dev/null || true
    
    # Wipe logs
    rm -f "$LOG_DIR"/*.log 2>/dev/null || true
    
    echo -e "${GREEN}  [OK] Environment torn down${NC}"
}

# ── Status ────────────────────────────────────────────────────────────────────
launch_status() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  OPSEC ENVIRONMENT STATUS"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    
    # Containers
    echo "  Containers:"
    docker ps --filter "name=opsec-" --format "    {{.Names}}: {{.Status}}" 2>/dev/null || echo "    None running"
    echo ""
    
    # VPN
    if ip link show tun0 &>/dev/null 2>&1; then
        local ip=$(cat "$SCRIPT_DIR/vpn/current_ip" 2>/dev/null || echo "unknown")
        echo "  VPN: CONNECTED ($ip)"
    else
        echo "  VPN: DISCONNECTED"
    fi
    
    # Tor
    if systemctl is-active tor &>/dev/null; then
        echo "  Tor: ACTIVE"
    else
        echo "  Tor: INACTIVE"
    fi
    
    # Firewall
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "  Firewall: ACTIVE"
    else
        echo "  Firewall: INACTIVE"
    fi
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
}

# ── Quick scan wrapper ────────────────────────────────────────────────────────
launch_scan() {
    local target="${1:-}"
    
    if [[ -z "$target" ]]; then
        echo "Usage: opsec-scan <target-ip>"
        return 1
    fi
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  PRE-ENGAGEMENT SCAN: $target"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    
    # 1. Honeypot detection first
    log "Running honeypot detection..."
    bash "$SCRIPT_DIR/honeypot-detect.sh" "$target"
    
    echo ""
    
    # 2. Scope verification
    if [[ -f "${SCRIPT_DIR}/scope.txt" ]]; then
        if grep -q "$target" "${SCRIPT_DIR}/scope.txt"; then
            echo -e "${GREEN}  Target is in scope${NC}"
        else
            echo -e "${RED}  WARNING: Target NOT found in scope.txt${NC}"
            echo "  Add it to ${SCRIPT_DIR}/scope.txt before proceeding"
            read -rp "  Continue anyway? [y/N] " confirm
            [[ "$confirm" != "y" ]] && return 1
        fi
    fi
    
    echo ""
    echo "  Safe to engage? Check the honeypot report above."
    echo "════════════════════════════════════════════════════════════════"
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    up)     launch_up ;;
    down)   launch_down ;;
    status) launch_status ;;
    scan)   launch_scan "${2:-}" ;;
    help|*)
        echo ""
        echo "Usage: $0 [up|down|status|scan <target>]"
        echo ""
        echo "  up              — Launch full protected environment"
        echo "  down            — Tear down everything"
        echo "  status          — Show current status"
        echo "  scan <target>   — Honeypot check + scope verify"
        echo ""
        ;;
esac
