#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-tor — Set up Tor + Proxychains for traffic anonymization
# ═══════════════════════════════════════════════════════════════════════════════
# Run as root: sudo bash ~/.opsec/tor.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC TOR + PROXYCHAINS SETUP"
echo "════════════════════════════════════════════════════════════════"

# --- 1. Install packages ---
echo "[*] Installing tor + proxychains4..."
apt-get update -qq && apt-get install -y -qq tor torsocks proxychains4

# --- 2. Configure Tor ---
echo "[*] Configuring Tor..."

cat > /etc/tor/torrc << 'TORRC'
# ═══════════════════════════════════════════════════════════════
# OPSEC Tor Configuration
# ═══════════════════════════════════════════════════════════════

# SOCKS5 proxy on localhost
SocksPort 9050

# Control port for stem/automation (optional)
ControlPort 9051

# Cookie authentication for control port
CookieAuthentication 1

# Use bridges if you're in a censored environment
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# Bridge obfs4 ...

# Entry/Exit node configuration (for opsec)
# Prefer specific country exit nodes:
# ExitNodes {us},{ca},{gb}
# StrictNodes 1

# Block unencrypted traffic
FascistFirewall 1

# DNS requests through Tor
DNSPort 5353

# Don't connect to the Tor network when starting
# Uncomment to auto-start:
# RunAsDaemon 1

# Logging
Log notice file /var/log/tor/notices.log
TORRC

# --- 3. Configure Proxychains ---
echo "[*] Configuring proxychains..."

cat > /etc/proxychains4.conf << 'PROXYCHAINS'
# ═══════════════════════════════════════════════════════════════
# OPSEC Proxychains Configuration
# ═══════════════════════════════════════════════════════════════

# Proxy chain type (strict = must go through all proxies)
strict_chain

# Quiet mode (no output)
quiet_mode

# ProxyDNS through the chain
proxy_dns

# Timeout settings
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ── Proxy list ──────────────────────────────────────────────
# Format: type host port [user pass]
# 
# For red teaming, use chain with Tor + optional VPN:
[ProxyList]
socks5 127.0.0.1 9050
PROXYCHAINS

# Create user-level config too
mkdir -p ~/.config/proxychains
cp /etc/proxychains4.conf ~/.config/proxychains/proxychains.conf

echo "[+] Proxychains configured"

# --- 4. Enable Tor service ---
echo "[*] Enabling Tor service..."
systemctl enable tor
systemctl start tor 2>/dev/null || systemctl restart tor

echo "[+] Tor service started on port 9050"

# --- 5. Create convenience aliases ---
echo "[*] Adding opsec shell aliases..."

# These get sourced from .bashrc
cat > ~/.opsec/tor-aliases.sh << 'ALIASES'
# ═══════════════════════════════════════════════════════════════
# TOR OPSEC ALIASES
# ═══════════════════════════════════════════════════════════════

# Route any command through Tor
alias tor='proxychains4'

# Quick checks
alias myip='proxychains4 curl -s https://check.torproject.org/api/ip'
alias myrealip='curl -s https://check.torproject.org/api/ip'
alias torcheck='proxychains4 curl -s https://check.torproject.org/api/ip && echo "" && curl -s https://check.torproject.org/api/ip'
alias dnsleak='proxychains4 nslookup google.com'

# Restart Tor (get new circuit/identity)
alias tor-restart='sudo systemctl restart tor && echo "[+] Tor restarted — new circuit"'
alias tor-new='sudo systemctl restart tor && echo "[+] New Tor circuit established"'

# Force specific tool through Tor
alias nmap-tor='proxychains4 nmap'
alias curl-tor='proxychains4 curl'
alias wget-tor='proxychains4 wget'
ALIASES

# Source from .bashrc
if ! grep -q "opsec/tor-aliases.sh" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# ─── OPSEC: Tor proxy aliases ──────────────────────────────────────────" >> ~/.bashrc
    echo '[ -f ~/.opsec/tor-aliases.sh ] && source ~/.opsec/tor-aliases.sh' >> ~/.bashrc
    echo "# ──────────────────────────────────────────────────────────────────────────" >> ~/.bashrc
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  TOR + PROXYCHAINS SETUP COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  USAGE:"
echo "    proxychains4 <command>     — Route command through Tor"
echo "    myip                       — Show Tor exit IP"
echo "    tor-restart                — Get new Tor circuit"
echo "    tor <command>              — Shorthand for proxychains4"
echo ""
echo "  Verify Tor connection:"
echo "    proxychains4 curl -s https://check.torproject.org/api/ip"
echo ""
echo "  IMPORTANT: Tor protects network identity but not DNS leaks."
echo "  Use opsec-dns.sh + opsec-tor.sh together for full protection."
echo "════════════════════════════════════════════════════════════════"
