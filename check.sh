#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-check — Pre-engagement security posture validator
# ═══════════════════════════════════════════════════════════════════════════════
# Run BEFORE every red team engagement
# Usage: opsec-check [target-scope]
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
CHECKS=()

check() {
    local name="$1"
    local result="$2"  # pass/fail/warn
    local detail="$3"
    
    case "$result" in
        pass)
            echo -e "  ${GREEN}[PASS]${NC} $name"
            PASS=$((PASS + 1))
            ;;
        fail)
            echo -e "  ${RED}[FAIL]${NC} $name — $detail"
            FAIL=$((FAIL + 1))
            ;;
        warn)
            echo -e "  ${YELLOW}[WARN]${NC} $name — $detail"
            WARN=$((WARN + 1))
            ;;
    esac
}

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC POSTURE CHECK"
echo "════════════════════════════════════════════════════════════════"
echo "  $(date)"
echo "════════════════════════════════════════════════════════════════"

# --- 1. Firewall ---
echo ""
echo -e "${CYAN}[1/8] FIREWALL${NC}"

if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    RULES=$(ufw status | grep -c "[0-9]")
    check "UFW enabled" "pass" ""
    check "UFW has rules" "pass" "$RULES rules active"
else
    check "UFW enabled" "fail" "Firewall is OFF — run: sudo ufw enable"
fi

# Check iptables INPUT policy
if iptables -L INPUT -n 2>/dev/null | head -1 | grep -q "policy DROP"; then
    check "iptables INPUT policy: DROP" "pass" ""
else
    check "iptables INPUT policy: DROP" "warn" "Policy is not DROP (UFW may handle this)"
fi

# --- 2. Network ---
echo ""
echo -e "${CYAN}[2/8] NETWORK${NC}"

# Check for IP leaks
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
if [[ "$PUBLIC_IP" != "unknown" ]]; then
    check "Public IP visible" "warn" "$PUBLIC_IP — are you behind VPN/Tor?"
else
    check "Public IP check" "pass" "Could not reach ipify (good if behind Tor)"
fi

# Check Tor
if systemctl is-active tor &>/dev/null; then
    check "Tor service running" "pass" ""
    
    # Verify Tor exit
    TOR_IP=$(curl -s --max-time 10 --socks5-hostname 127.0.0.1:9050 https://api.ipify.org 2>/dev/null || echo "unknown")
    if [[ "$TOR_IP" != "unknown" && "$TOR_IP" != "$PUBLIC_IP" ]]; then
        check "Tor exit IP different" "pass" "Exit: $TOR_IP"
    else
        check "Tor exit IP different" "fail" "Tor IP matches public IP — Tor may not be working"
    fi
else
    check "Tor service running" "fail" "Tor is NOT running — run: sudo systemctl start tor"
fi

# Check DNS
echo ""
echo -e "${CYAN}[3/8] DNS${NC}"

DNS_SERVER=$(resolvectl status 2>/dev/null | grep "DNS Servers" | head -1 | awk '{print $NF}' || echo "unknown")
if [[ "$DNS_SERVER" == "127.0.0.1" || "$DNS_SERVER" == *"dnscrypt"* ]]; then
    check "DNS resolver: dnscrypt-proxy" "pass" ""
else
    check "DNS resolver: dnscrypt-proxy" "warn" "Using $DNS_SERVER — may leak DNS queries"
fi

# --- 3. Kernel Parameters ---
echo ""
echo -e "${CYAN}[4/8] KERNEL SECURITY${NC}"

check_sysctl() {
    local param="$1"
    local expected="$2"
    local desc="$3"
    
    actual=$(sysctl -n "$param" 2>/dev/null || echo "unknown")
    if [[ "$actual" == "$expected" ]]; then
        check "$desc" "pass" ""
    else
        check "$desc" "fail" "$param=$actual (expected $expected)"
    fi
}

check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "ICMP redirects disabled"
check_sysctl "net.ipv4.conf.all.send_redirects" "0" "ICMP send_redirects disabled"
check_sysctl "net.ipv4.conf.all.rp_filter" "1" "Reverse path filtering strict"
check_sysctl "net.ipv6.conf.all.accept_redirects" "0" "IPv6 redirects disabled"
check_sysctl "net.ipv4.tcp_syncookies" "1" "SYN cookies enabled"
check_sysctl "net.ipv4.conf.all.log_martians" "1" "Martian packet logging"

# --- 4. MAC Address ---
echo ""
echo -e "${CYAN}[5/8] MAC ADDRESS${NC}"

OPSEC_DIR="/home/jewboy420/.opsec"

if [[ -f "$OPSEC_DIR/original-macs.txt" ]]; then
    check "MAC randomization setup" "pass" ""
    
    # Check if current MAC differs from original
    while IFS='=' read -r iface orig_mac; do
        current_mac=$(ip link show "$iface" 2>/dev/null | awk '/link\/ether/ {print $2}')
        if [[ "$current_mac" != "$orig_mac" ]]; then
            check "MAC randomized on $iface" "pass" "Current: $current_mac"
        else
            check "MAC randomized on $iface" "warn" "Same as original — run: mac-random"
        fi
    done < "$OPSEC_DIR/original-macs.txt"
else
    check "MAC randomization setup" "fail" "Not configured — run: sudo bash $OPSEC_DIR/mac.sh"
fi

# --- 5. Secrets ---
echo ""
echo -e "${CYAN}[6/8] SECRETS & KEYS${NC}"

# Check if API keys are in .bashrc
if grep -qE 'export.*API_KEY.*=' ~/.bashrc 2>/dev/null; then
    check "No plaintext keys in .bashrc" "fail" "API keys found in plaintext in .bashrc"
else
    check "No plaintext keys in .bashrc" "pass" ""
fi

if [[ -f "$OPSEC_DIR/secrets.env.gpg" ]]; then
    check "Encrypted vault exists" "pass" ""
else
    check "Encrypted vault exists" "fail" "Run: bash $OPSEC_DIR/setup.sh"
fi

# Check for exposed keys in common locations
EXPOSED=0
for loc in ~/.env ~/.config/.env /etc/environment; do
    if [[ -f "$loc" ]] && grep -qiE '(api.?key|secret|token|password)' "$loc" 2>/dev/null; then
        EXPOSED=$((EXPOSED + 1))
    fi
done
if [[ $EXPOSED -gt 0 ]]; then
    check "No keys in env files" "warn" "$EXPOSED file(s) may contain secrets"
else
    check "No keys in env files" "pass" ""
fi

# --- 6. System ---
echo ""
echo -e "${CYAN}[7/8] SYSTEM HARDENING${NC}"

# Check SSH config
if grep -q "PermitRootLogin no" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null; then
    check "SSH: Root login disabled" "pass" ""
else
    check "SSH: Root login disabled" "warn" "SSH may allow root login"
fi

if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null; then
    check "SSH: Password auth disabled" "pass" ""
else
    check "SSH: Password auth disabled" "warn" "SSH may allow password authentication"
fi

# Check for running services that leak info
for svc in avahi-daemon cups bluetooth ModemManager; do
    if systemctl is-active "$svc" &>/dev/null; then
        check "Service: $svc disabled" "fail" "Service is running — leaks info"
    else
        check "Service: $svc disabled" "pass" ""
    fi
done

# Check if USB storage is blocked
if lsmod 2>/dev/null | grep -q usb_storage; then
    check "USB storage module" "warn" "usb-storage module is loaded"
else
    check "USB storage module" "pass" "Not loaded"
fi

# --- 7. Browser ---
echo ""
echo -e "${CYAN}[8/8] BROWSER & WEB${NC}"

# Check if default browser is privacy-focused
DEFAULT_BROWSER=$(xdg-settings get default-web-browser 2>/dev/null || echo "unknown")
case "$DEFAULT_BROWSER" in
    *firefox*|*tor*|*brave*)
        check "Privacy browser default" "pass" "$DEFAULT_BROWSER"
        ;;
    *chrome*|*chromium*)
        check "Privacy browser default" "warn" "$DEFAULT_BROWSER — Chrome/Chromium tracks you"
        ;;
    *)
        check "Privacy browser default" "warn" "$DEFAULT_BROWSER"
        ;;
esac

# Check for WebRTC leak potential
if command -v firefox &>/dev/null; then
    check "Firefox available" "pass" "Can be used with Tor Browser"
else
    check "Firefox available" "warn" "Install Firefox for privacy browsing"
fi

# --- 8. VPN Check ---
echo ""
echo -e "${CYAN}[BONUS] VPN STATUS${NC}"

VPN_INTERFACES=$(ip link show | grep -cE 'tun|tap|wg|ppp' || true)
if [[ $VPN_INTERFACES -gt 0 ]]; then
    check "VPN interface detected" "pass" "$VPN_INTERFACES tunnel(s) found"
else
    check "VPN interface detected" "warn" "No VPN detected — recommend using VPN + Tor"
fi

# --- Summary ---
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  RESULTS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}PASS: $PASS${NC}"
echo -e "  ${YELLOW}WARN: $WARN${NC}"
echo -e "  ${RED}FAIL: $FAIL${NC}"
echo ""

TOTAL=$((PASS + WARN + FAIL))
if [[ $TOTAL -gt 0 ]]; then
    SCORE=$(( (PASS * 100) / TOTAL ))
    echo -e "  Score: ${CYAN}${SCORE}%${NC}"
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}║  POSTURE: READY FOR ENGAGEMENT             ║${NC}"
    echo -e "  ${GREEN}╚══════════════════════════════════════════════╝${NC}"
else
    echo -e "  ${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "  ${RED}║  POSTURE: NOT READY — Fix FAIL items first  ║${NC}"
    echo -e "  ${RED}╚══════════════════════════════════════════════╝${NC}"
fi

echo ""
echo "  Scope check: If a scope file exists, verify it:"
if [[ -f "$OPSEC_DIR/scope.txt" ]]; then
    echo -e "  ${CYAN}$(wc -l < "$OPSEC_DIR/scope.txt") target(s) in scope.txt${NC}"
elif [[ -f "$OPSEC_DIR/authorization.md" ]]; then
    echo -e "  ${CYAN}authorization.md found — review before proceeding${NC}"
else
    echo -e "  ${YELLOW}No scope.txt or authorization.md found${NC}"
    echo "  Create scope.txt with authorized targets (hostnames/CIDRs)"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
