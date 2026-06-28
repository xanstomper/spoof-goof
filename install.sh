#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-install — Master setup: run all OPSEC hardening scripts
# ═══════════════════════════════════════════════════════════════════════════════
# Run as root: sudo bash ~/.opsec/install.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC MASTER INSTALL — Full System Hardening"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  This will:"
echo "    1. Install required packages (tor, proxychains4, macchanger, etc.)"
echo "    2. Harden kernel parameters"
echo "    3. Configure UFW firewall"
echo "    4. Set up DNS-over-HTTPS"
echo "    5. Configure Tor + Proxychains"
echo "    6. Set up MAC randomization"
echo "    7. System-level lockdown"
echo ""
echo "  Requires: sudo access"
echo ""
read -rp "  Continue? [y/N] " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && exit 0

echo ""

# --- Install dependencies ---
echo "[*] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
    tor torsocks proxychains4 \
    macchanger \
    dnscrypt-proxy \
    auditd \
    gpg \
    curl wget \
    net-tools \
    2>/dev/null || true

echo "[+] Dependencies installed"
echo ""

# --- Run each hardening script ---
SCRIPTS=(
    "firewall.sh:Firewall Hardening"
    "dns.sh:DNS Leak Protection"
    "tor.sh:Tor + Proxychains"
    "mac.sh:MAC Randomization"
    "harden.sh:System Lockdown"
)

OPSEC_DIR="${HOME}/.opsec"

for entry in "${SCRIPTS[@]}"; do
    script="${entry%%:*}"
    name="${entry##*:}"
    
    echo "════════════════════════════════════════════════════════════════"
    echo "  Running: $name"
    echo "════════════════════════════════════════════════════════════════"
    
    if [[ -f "$OPSEC_DIR/$script" ]]; then
        bash "$OPSEC_DIR/$script"
    else
        echo "[!] Script not found: $OPSEC_DIR/$script"
    fi
    echo ""
done

# --- Setup secrets vault ---
echo "════════════════════════════════════════════════════════════════"
echo "  Encrypting Secrets Vault"
echo "════════════════════════════════════════════════════════════════"

if [[ -f "$OPSEC_DIR/secrets.env" && ! -f "$OPSEC_DIR/secrets.env.gpg" ]]; then
    echo "[*] Encrypting secrets.env..."
    gpg --symmetric --cipher-algo AES256 "$OPSEC_DIR/secrets.env"
    echo "[+] Vault encrypted"
elif [[ -f "$OPSEC_DIR/secrets.env.gpg" ]]; then
    echo "[*] Vault already encrypted"
else
    echo "[!] secrets.env not found — create it with your API keys"
fi

# --- Make scripts executable ---
chmod +x "$OPSEC_DIR"/*.sh
chmod 700 "$OPSEC_DIR"

# --- Install opsec-check as system command ---
cp "$OPSEC_DIR/check.sh" /usr/local/bin/opsec-check 2>/dev/null || true
chmod +x /usr/local/bin/opsec-check 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC INSTALL COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Available commands:"
echo "    opsec-check         — Validate security posture"
echo "    opsec-load          — Load secrets into session"
echo "    opsec-unload        — Clear secrets from session"
echo "    opsec-status        — Show current security state"
echo "    tor <cmd>           — Route command through Tor"
echo "    myip                — Show Tor exit IP"
echo "    mac-random          — Randomize MAC addresses"
echo "    mac-restore         — Restore original MACs"
echo ""
echo "  IMPORTANT: Log out and back in for all changes to take effect."
echo "════════════════════════════════════════════════════════════════"
