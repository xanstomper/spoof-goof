#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-mac — MAC address randomization
# ═══════════════════════════════════════════════════════════════════════════════
# Run as root: sudo bash ~/.opsec/mac.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC MAC ADDRESS RANDOMIZATION"
echo "════════════════════════════════════════════════════════════════"

# --- 1. Install macchanger ---
if ! command -v macchanger &>/dev/null; then
    echo "[*] Installing macchanger..."
    apt-get update -qq && apt-get install -y -qq macchanger
fi

# --- 2. Get list of network interfaces ---
echo "[*] Detecting network interfaces..."

# Find physical interfaces (exclude docker, lo, veth, etc.)
INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|docker|veth|br-|virbr|vmnet|tun|tap')

if [[ -z "$INTERFACES" ]]; then
    echo "[!] No physical network interfaces found"
    exit 1
fi

echo "  Found interfaces: $INTERFACES"

# --- 3. Save original MACs ---
echo "[*] Saving original MAC addresses..."
mkdir -p ~/.opsec

for iface in $INTERFACES; do
    ORIG_MAC=$(ip link show "$iface" | awk '/link\/ether/ {print $2}')
    echo "  $iface: $ORIG_MAC"
    echo "$iface=$ORIG_MAC" >> ~/.opsec/original-macs.txt
done

# --- 4. Create randomization script ---
cat > ~/.opsec/mac-randomize.sh << 'RANDOMIZE'
#!/usr/bin/env bash
# Randomize MAC addresses on all physical interfaces
# Usage: sudo ~/.opsec/mac-randomize.sh

set -euo pipefail

INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE 'lo|docker|veth|br-|virbr|vmnet|tun|tap')

for iface in $INTERFACES; do
    echo "[*] Randomizing MAC on $iface..."
    
    # Take interface down
    ip link set "$iface" down
    
    # Randomize MAC
    macchanger -r "$iface" 2>/dev/null
    
    # Bring interface back up
    ip link set "$iface" up
    
    NEW_MAC=$(ip link show "$iface" | awk '/link\/ether/ {print $2}')
    echo "[+] $iface: $NEW_MAC"
done

echo ""
echo "[+] All MAC addresses randomized"
echo "[*] New IP lease may be needed: sudo dhclient -r && sudo dhclient"
RANDOMIZE

chmod +x ~/.opsec/mac-randomize.sh

# --- 5. Create restore script ---
cat > ~/.opsec/mac-restore.sh << 'RESTORE'
#!/usr/bin/env bash
# Restore original MAC addresses
# Usage: sudo ~/.opsec/mac-restore.sh

set -euo pipefail

MAC_FILE="${HOME}/.opsec/original-macs.txt"

if [[ ! -f "$MAC_FILE" ]]; then
    echo "[!] Original MACs not found at $MAC_FILE"
    exit 1
fi

while IFS='=' read -r iface orig_mac; do
    echo "[*] Restoring $iface to $orig_mac..."
    ip link set "$iface" down
    macchanger -m "$orig_mac" "$iface" 2>/dev/null
    ip link set "$iface" up
    echo "[+] $iface: $orig_mac"
done < "$MAC_FILE"

echo ""
echo "[+] Original MAC addresses restored"
RESTORE

chmod +x ~/.opsec/mac-restore.sh

# --- 6. Create systemd service for auto-randomize on boot ---
cat > /etc/systemd/system/opsec-mac.service << 'SERVICE'
[Unit]
Description=OPSEC MAC Address Randomization
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/home/jewboy420/.opsec/mac-randomize.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

# --- 7. Create aliases ---
cat > ~/.opsec/mac-aliases.sh << 'ALIASES'
# MAC randomization
alias mac-random='sudo ~/.opsec/mac-randomize.sh'
alias mac-restore='sudo ~/.opsec/mac-restore.sh'
alias mac-show='ip link show | grep -E "link/ether"'
ALIASES

if ! grep -q "opsec/mac-aliases.sh" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# ─── OPSEC: MAC randomization aliases ────────────────────────────────" >> ~/.bashrc
    echo '[ -f ~/.opsec/mac-aliases.sh ] && source ~/.opsec/mac-aliases.sh' >> ~/.bashrc
    echo "# ──────────────────────────────────────────────────────────────────────────" >> ~/.bashrc
fi

# --- 8. Randomize now ---
echo "[*] Randomizing MAC addresses now..."
for iface in $INTERFACES; do
    ip link set "$iface" down 2>/dev/null || true
    macchanger -r "$iface" 2>/dev/null || true
    ip link set "$iface" up 2>/dev/null || true
    NEW_MAC=$(ip link show "$iface" | awk '/link\/ether/ {print $2}')
    echo "[+] $iface: $NEW_MAC"
done

# Enable auto-randomize on boot
systemctl daemon-reload
systemctl enable opsec-mac.service

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  MAC RANDOMIZATION COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Current MACs are randomized. Original MACs saved."
echo "  Auto-randomize enabled on boot."
echo ""
echo "  Commands:"
echo "    mac-random   — Randomize now"
echo "    mac-restore  — Restore original MACs"
echo "    mac-show     — Show current MACs"
echo "════════════════════════════════════════════════════════════════"
