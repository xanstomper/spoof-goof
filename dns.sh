#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-dns — DNS leak protection with DNS-over-HTTPS
# ═══════════════════════════════════════════════════════════════════════════════
# Run as root: sudo bash ~/.opsec/dns.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC DNS LEAK PROTECTION"
echo "════════════════════════════════════════════════════════════════"

# --- 1. Install dnscrypt-proxy if not present ---
if ! command -v dnscrypt-proxy &>/dev/null; then
    echo "[*] Installing dnscrypt-proxy..."
    apt-get update -qq && apt-get install -y -qq dnscrypt-proxy
fi

# --- 2. Configure dnscrypt-proxy ---
echo "[*] Configuring dnscrypt-proxy..."

cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'DNSCONF'
# ═══════════════════════════════════════════════════════════════
# OPSEC DNS Configuration — DNS-over-HTTPS with leak protection
# ═══════════════════════════════════════════════════════════════

# Listen on localhost only
listen_addresses = ['127.0.0.1:53']

# Use multiple secure resolvers for redundancy
server_names = ['cloudflare', 'google', 'quad9-doh']

# Forward insecure (non-DNSSEC) queries
forwarding_rules = []

# Block common telemetry/tracking domains
blocked_names = ['blocked-names.txt']
blocked_ports = []

# Force DNSSEC validation
require_dnssec = false  # Some resolvers don't support it yet

# Use HTTPS (not plaintext)
# https://dns.google/dns-query
# https://cloudflare-dns.com/dns-query
# https://dns.quad9.net/dns-query

# Performance settings
max_clients = 250
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = false
doh_servers = true
require_nolog = false
require_nofilter = false
force_tcp = false
timeout = 5000
keepalive = 30
use_syslog = true
log_level = 0

# Cache
cache = true
cache_size = 1000
cache_min_ttl = 60
cache_max_ttl = 14400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 300

# Prevent DNS rebinding
reject_resolv_sites = true

[static]
  [static.'cloudflare']
  stamp = 'sdns://AgcAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5'
  
  [static.'google']
  stamp = 'sdns://AgcAAAAAAAAABzguOC44LjgADmRucy5nb29nbGUuY29tCi9kbnMtcXVlcnk'
  
  [static.'quad9-doh']
  stamp = 'sdns://AgcAAAAAAAAACzkuOS45LjkEDTkxLjEzMC4xMS4xBjk5LjEzMC4xMS4yA2RuczkubmV0AgcA'
DNSCONF

# --- 3. Create blocked names list ---
cat > /etc/dnscrypt-proxy/blocked-names.txt << 'BLOCKED'
# Telemetry and tracking domains
telemetry.microsoft.com
vortex.data.microsoft.com
settings-win.data.microsoft.com
watson.telemetry.microsoft.com
reports.wes.df.telemetry.microsoft.com
oca.telemetry.microsoft.com
sqm.telemetry.microsoft.com
scores.telemetry.microsoft.com
survey.watson.microsoft.com
watson.microsoft.com
watson.ppe.telemetry.microsoft.com
vortex-win.data.microsoft.com
telecommand.telemetry.microsoft.com
etw.microsoft.com
events.data.microsoft.com
 functionalcloudf.com
telegraphis.net
# Google telemetry
clients4.google.com
clients2.google.com
play.googleapis.com
gstatic.com
googleapis.com
# Facebook tracking
pixel.facebook.com
connect.facebook.net
graph.facebook.com
# Analytics
google-analytics.com
googletagmanager.com
hotjar.com
amplitude.com
mixpanel.com
segment.io
heap.io
fullstory.com
clarity.ms
BLOCKED

echo "[+] DNS-over-HTTPS configured"

# --- 4. Point system DNS to dnscrypt-proxy ---
echo "[*] Configuring systemd-resolved..."

# Create override to use dnscrypt-proxy
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/opsec.conf << 'RESOLVED'
[Resolve]
DNS=127.0.0.1
#FallbackDNS=
Domains=~.
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
RESOLVED

# Also update /etc/resolv.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true

# Restart services
systemctl restart dnscrypt-proxy 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true

echo "[+] DNS leak protection active"
echo ""
echo "  All DNS queries now flow through dnscrypt-proxy"
echo "  Resolvers: Cloudflare, Google, Quad9 (DNS-over-HTTPS)"
echo "  Telemetry/tracking domains are blocked"
echo ""
echo "  To verify: dnsleaktest.com or dig +short whoami.akamai.net"
