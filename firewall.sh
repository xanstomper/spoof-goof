#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-firewall — Harden network perimeter
# ═══════════════════════════════════════════════════════════════════════════════
# Run as root: sudo bash ~/.opsec/firewall.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC FIREWALL HARDENING"
echo "════════════════════════════════════════════════════════════════"

# --- 1. System-level network hardening (sysctl) ---
echo "[*] Hardening kernel network parameters..."

cat > /etc/sysctl.d/99-opsec-hardening.conf << 'SYSCTL'
# ── ICMP ──────────────────────────────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_errors_use_inbound_ifaddr = 1

# ── Source Routing ────────────────────────────────────────────
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ── Redirects (prevent MITM) ─────────────────────────────────
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ── Reverse Path Filtering ───────────────────────────────────
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── SYN Flood Protection ─────────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# ── Logging ──────────────────────────────────────────────────
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── IPv6 Privacy Extensions (randomize IPv6 address) ─────────
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# ── Prevent IP Spoofing ──────────────────────────────────────
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.accept_local = 0

# ── BPF JIT hardening ────────────────────────────────────────
net.core.bpf_jit_harden = 2

# ── User namespaces (prevent container escapes) ──────────────
# Keep ip_forward=1 for Docker
SYSCTL

sysctl -p /etc/sysctl.d/99-opsec-hardening.conf 2>/dev/null
echo "[+] Kernel parameters hardened"

# --- 2. UFW Firewall ---
echo "[*] Configuring UFW firewall..."

# Reset to clean state
ufw --force reset

# Default policies: deny everything
ufw default deny incoming
ufw default deny outgoing
ufw default deny routed

# Allow loopback (required for local services)
ufw allow in on lo
ufw allow out on lo

# Allow established/related connections
ufw allow in proto tcp from any to any state established
ufw allow out proto tcp from any to any state established
ufw allow in proto udp from any to any state established
ufw allow out proto udp from any to any state established

# Allow DHCP (needed for network connectivity)
ufw allow out proto udp to any port 67,68
ufw allow in proto udp from any port 67,68

# Allow DNS outbound (essential for resolution)
ufw allow out proto udp to any port 53
ufw allow out proto tcp to any port 53

# Allow HTTPS outbound (for package updates, API calls)
ufw allow out proto tcp to any port 443

# Allow HTTP outbound (for package repos)
ufw allow out proto tcp to any port 80

# Allow SSH inbound (for remote access — adjust if needed)
ufw allow in proto tcp to any port 22

# Allow Docker bridge traffic (Docker manages its own chains)
ufw allow in on docker0
ufw allow out on docker0

# Allow ICMP (ping) — useful for diagnostics
ufw allow out proto icmp

# Rate limit SSH (brute force protection)
ufw limit 22/tcp comment "SSH rate limit"

# Enable logging
ufw logging on

# Enable the firewall
ufw --force enable

echo "[+] UFW firewall enabled"
echo ""
ufw status verbose

# --- 3. Additional iptables rules for red teaming ---
echo ""
echo "[*] Adding supplementary iptables rules..."

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

# Drop XMAS packets (common scan signature)
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A OUTPUT -p tcp --tcp-flags ALL ALL -j DROP

# Drop NULL packets (common scan signature)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A OUTPUT -p tcp --tcp-flags ALL NONE -j DROP

# Drop Christmas tree packets
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Block incoming to common attack vectors
iptables -A INPUT -p tcp --dport 23 -j DROP   # Telnet
iptables -A INPUT -p tcp --dport 111 -j DROP   # RPC portmapper
iptables -A INPUT -p udp --dport 111 -j DROP   # RPC portmapper
iptables -A INPUT -p tcp --dport 135 -j DROP   # MS RPC
iptables -A INPUT -p tcp --dport 139 -j DROP   # NetBIOS
iptables -A INPUT -p tcp --dport 445 -j DROP   # SMB
iptables -A INPUT -p tcp --dport 1433 -j DROP  # MSSQL
iptables -A INPUT -p tcp --dport 3389 -j DROP  # RDP
iptables -A INPUT -p tcp --dport 5900 -j DROP  # VNC

echo "[+] Supplementary iptables rules applied"

# --- 4. Disable IPv6 if not needed ---
echo "[*] Disabling IPv6 (reduces attack surface)..."
cat >> /etc/sysctl.d/99-opsec-hardening.conf << 'IPV6'

# Disable IPv6 (reduces attack surface for red teaming)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
IPV6

sysctl -p /etc/sysctl.d/99-opsec-hardening.conf 2>/dev/null
echo "[+] IPv6 disabled"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  FIREWALL HARDENING COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo "  Status: $(ufw status | head -1)"
echo "  Rules:  $(ufw status | grep -c '[0-9]') rules active"
echo ""
echo "  NOTE: Docker manages its own iptables chains."
echo "  Docker containers can still communicate via the bridge."
echo "════════════════════════════════════════════════════════════════"
