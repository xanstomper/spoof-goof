#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-harden — System-level lockdown for red teaming
# ═══════════════════════════════════════════════════════════════════════════════
# Run as root: sudo bash ~/.opsec/harden.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC SYSTEM HARDENING"
echo "════════════════════════════════════════════════════════════════"

# --- 1. Kernel module blacklisting (prevent fingerprinting) ---
echo "[*] Blacklisting kernel modules for fingerprinting prevention..."
cat > /etc/modprobe.d/opsec-blacklist.conf << 'MODPROBE'
# Prevent kernel fingerprinting
blacklist usb-storage    # Prevent USB-based attacks against you
blacklist firewire-core  # FireWire DMA attacks
blacklist ieee1394       # FireWire
blacklist uvcvideo       # Webcam
blacklist snd            # Audio
blacklist btusb          # Bluetooth
blacklist btrtl          # Bluetooth
blacklist btbcm          # Bluetooth
blacklist btintel        # Bluetooth
MODPROBE

echo "[+] Kernel modules blacklisted"

# --- 2. Disable USB storage ---
echo "[*] Disabling USB storage..."
echo 'blacklist usb-storage' > /etc/modprobe.d/opsec-usb-storage.conf
modprobe -r usb-storage 2>/dev/null || true
echo "[+] USB storage disabled"

# --- 3. Set restrictive permissions ---
echo "[*] Setting restrictive file permissions..."

# SSH directory
chmod 700 ~/.ssh 2>/dev/null || true
chmod 600 ~/.ssh/id_* 2>/dev/null || true
chmod 600 ~/.ssh/authorized_keys 2>/dev/null || true

# GPG
chmod 700 ~/.gnupg 2>/dev/null || true

# History files
chmod 600 ~/.bash_history 2>/dev/null || true
chmod 600 ~/.zsh_history 2>/dev/null || true

# Opsec vault
chmod 700 ~/.opsec 2>/dev/null || true
chmod 600 ~/.opsec/*.env 2>/dev/null || true
chmod 600 ~/.opsec/*.sh 2>/dev/null || true

echo "[+] File permissions set"

# --- 4. Harden SSH ---
echo "[*] Hardening SSH..."
cat > /etc/ssh/sshd_config.d/opsec-hardening.conf << 'SSHCONF'
# OPSEC SSH Hardening
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
Banner /etc/issue.net
PermitUserEnvironment no
SSHCONF

echo "[+] SSH hardened"

# --- 5. Disable unnecessary services ---
echo "[*] Disabling unnecessary services..."
SERVICES=(
    "cups"           # Printing
    "avahi-daemon"   # mDNS/Bonjour (fingerprinting)
    "bluetooth"      # Bluetooth
    "ModemManager"   # Modem
    "wpa_supplicant" # WiFi (if using ethernet)
)

for svc in "${SERVICES[@]}"; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        echo "  Disabled: $svc"
    fi
done

echo "[+] Unnecessary services disabled"

# --- 6. File integrity monitoring ---
echo "[*] Setting up file integrity baseline..."
mkdir -p /var/opsec/fim

# Create baseline of critical files
cat > /var/opsec/fim/baseline.txt << 'FIM'
# OPSEC File Integrity Monitor Baseline
# Format: md5hash  filepath
# Run: opsec-fim-check to verify integrity
FIM

# Generate baseline
find /etc -type f -name "*.conf" -o -name "*.cfg" -o -name "*.key" -o -name "*.pem" 2>/dev/null | while read -r f; do
    md5sum "$f" 2>/dev/null >> /var/opsec/fim/baseline.txt
done

echo "[+] File integrity baseline created at /var/opsec/fim/baseline.txt"

# --- 7. Create FIM checker ---
cat > /usr/local/bin/opsec-fim-check << 'FIMCHECK'
#!/usr/bin/env bash
# Check file integrity against baseline
BASELINE="/var/opsec/fim/baseline.txt"
CHANGES=0

echo "════════════════════════════════════════════════════════════════"
echo "  FILE INTEGRITY CHECK"
echo "════════════════════════════════════════════════════════════════"

if [[ ! -f "$BASELINE" ]]; then
    echo "[!] Baseline not found at $BASELINE"
    echo "[*] Run: sudo bash ~/.opsec/harden.sh"
    exit 1
fi

while IFS='  ' read -r stored_hash filepath; do
    [[ "$stored_hash" == \#* || -z "$filepath" ]] && continue
    current_hash=$(md5sum "$filepath" 2>/dev/null | awk '{print $1}')
    if [[ "$current_hash" != "$stored_hash" ]]; then
        echo "[!] CHANGED: $filepath"
        echo "    Was: $stored_hash"
        echo "    Now: $current_hash"
        CHANGES=$((CHANGES + 1))
    fi
done < "$BASELINE"

if [[ $CHANGES -eq 0 ]]; then
    echo "[+] All files match baseline"
else
    echo ""
    echo "[!] $CHANGES file(s) modified since baseline"
fi
FIMCHECK

chmod +x /usr/local/bin/opsec-fim-check

# --- 8. Audit logging ---
echo "[*] Setting up audit logging..."
if ! command -v auditd &>/dev/null; then
    apt-get install -y -qq auditd 2>/dev/null || true
fi

if command -v auditctl &>/dev/null; then
    cat > /etc/audit/rules.d/opsec.rules << 'AUDITRULES'
# OPSEC Audit Rules — Monitor sensitive file access
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/jewboy420/.ssh/ -p wa -k ssh_keys
-w /home/jewboy420/.opsec/ -p wa -k opsec_vault
-w /etc/tor/torrc -p wa -k tor_config
AUDITRULES

    service auditd restart 2>/dev/null || true
    echo "[+] Audit logging configured"
else
    echo "[!] auditd not available, skipping audit rules"
fi

# --- 9. Disable core dumps ---
echo "[*] Disabling core dumps..."
cat > /etc/security/limits.d/opsec.conf << 'LIMITS'
* hard core 0
* soft core 0
LIMITS

cat >> /etc/sysctl.d/99-opsec-hardening.conf << 'COREDUMPS'
fs.suid_dumpable = 0
kernel.core_pattern=|/bin/false
COREDUMPS

sysctl -p /etc/sysctl.d/99-opsec-hardening.conf 2>/dev/null
echo "[+] Core dumps disabled"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  SYSTEM HARDENING COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  What was done:"
echo "    - Kernel modules blacklisted (USB, BT, camera, audio)"
echo "    - SSH hardened (no root, no password auth, no forwarding)"
echo "    - Unnecessary services disabled"
echo "    - File integrity baseline created"
echo "    - Audit logging enabled"
echo "    - Core dumps disabled"
echo ""
echo "  Run 'opsec-check' to validate your security posture."
echo "════════════════════════════════════════════════════════════════"
