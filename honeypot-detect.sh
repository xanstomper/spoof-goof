#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-honeypot — Detect honeypots before engaging
# ═══════════════════════════════════════════════════════════════════════════════
# Run: bash ~/.opsec/honeypot-detect.sh <target-ip-or-hostname>
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

TARGET="${1:-}"
REPORT_DIR="${HOME}/.opsec/reports/honeypots"
REPORT_FILE="$REPORT_DIR/$(date +%Y%m%d_%H%M%S)_${TARGET//[^a-zA-Z0-9]/_}.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FINDINGS=0
RISK_SCORE=0

mkdir -p "$REPORT_DIR"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-ip-or-hostname>"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.1"
    echo "  $0 example.com"
    echo "  $0 -f targets.txt    (scan multiple targets)"
    exit 1
fi

# ── Logging ───────────────────────────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local msg="$*"
    echo "$msg" | tee -a "$REPORT_FILE"
}

finding() {
    local severity="$1"
    local desc="$2"
    FINDINGS=$((FINDINGS + 1))
    
    case "$severity" in
        CRITICAL) RISK_SCORE=$((RISK_SCORE + 10)); log "$RED" "  [!!!] $desc" ;;
        HIGH)     RISK_SCORE=$((RISK_SCORE + 7));  log "$RED" "  [!!]  $desc" ;;
        MEDIUM)   RISK_SCORE=$((RISK_SCORE + 4));  log "$YELLOW" "  [!]   $desc" ;;
        LOW)      RISK_SCORE=$((RISK_SCORE + 1));  log "$CYAN" "  [i]   $desc" ;;
    esac
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════" | tee "$REPORT_FILE"
echo "  HONEYPOT DETECTION SCAN" | tee -a "$REPORT_FILE"
echo "  Target: $TARGET" | tee -a "$REPORT_FILE"
echo "  $(date)" | tee -a "$REPORT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$REPORT_FILE"
echo ""

# ── 1. Port Scan (Quick) ─────────────────────────────────────────────────────
log "$CYAN" "[1/8] Port scanning..."
PORTS=$(timeout 30 nmap -sT -T5 --top-ports 20 --open -Pn "$TARGET" 2>/dev/null || echo "")
echo "$PORTS" >> "$REPORT_FILE"

# Detect port patterns that indicate honeypots
if echo "$PORTS" | grep -q "22.*open"; then
    # SSH honeypot indicators
    SSH_BANNER=$(echo "" | timeout 5 nc -w3 "$TARGET" 22 2>/dev/null || echo "")
    echo "$SSH_BANNER" >> "$REPORT_FILE"
    
    if echo "$SSH_BANNER" | grep -qiE "cowrie|kippo|dionaea|honeyd|sgnl|pot|trap|fake|honeypot"; then
        finding "CRITICAL" "SSH honeypot banner detected: $SSH_BANNER"
    elif echo "$SSH_BANNER" | grep -qiE "OpenSSH_.*Ubuntu|OpenSSH_.*Debian"; then
        # Check if multiple SSH versions are present
        finding "LOW" "Standard SSH banner (verify version matches OS)"
    fi
fi

# ── 2. Service Fingerprint Analysis ───────────────────────────────────────────
log "$CYAN" "[2/8] Service fingerprinting..."
NMAP_VER=$(timeout 15 nmap -sT -T5 --top-ports 10 -Pn "$TARGET" 2>/dev/null || echo "")
echo "$NMAP_VER" >> "$REPORT_FILE"

# Check for inconsistent services
WIN_SERVICES=$(echo "$NMAP_VER" | grep -ciE "microsoft|iis|smb|netbios|rdp" || true)
LINUX_SERVICES=$(echo "$NMAP_VER" | grep -ciE "apache|nginx|openssh|linux" || true)

if [[ $WIN_SERVICES -gt 0 && $LINUX_SERVICES -gt 0 ]]; then
    finding "HIGH" "Mixed OS services detected (Windows + Linux) — strong honeypot indicator"
fi

# Check for honeypot-specific services
if echo "$NMAP_VER" | grep -qiE "Cowrie|Kippo|Dionaea|Conpot|Honeyd|Amun|Glutton|T-Pot"; then
    finding "CRITICAL" "Known honeypot service detected in banner"
fi

# ── 3. TCP Timestamp Analysis ────────────────────────────────────────────────
log "$CYAN" "[3/8] TCP timestamp analysis..."
# Quick port check (skip slow -sV and -O on remote targets)
TIMESTAMPS=$(timeout 10 nmap -sT -T5 --top-ports 10 -Pn "$TARGET" 2>/dev/null || echo "")
echo "$TIMESTAMPS" >> "$REPORT_FILE"

# Honeypots often have inconsistent OS fingerprints
OS_LINE=$(echo "$TIMESTAMPS" | grep -i "OS details:" 2>/dev/null || echo "$TIMESTAMPS" | grep -i "Running:" 2>/dev/null || echo "")
if [[ -n "$OS_LINE" ]] && echo "$OS_LINE" | grep -qiE "Linux.*Windows|Windows.*Linux|FreeBSD.*Linux" 2>/dev/null; then
    finding "HIGH" "Conflicting OS fingerprints: $OS_LINE"
fi

# ── 4. Timing Analysis ───────────────────────────────────────────────────────
log "$CYAN" "[4/8] Response timing analysis..."

# Send multiple pings and measure variance
echo "[*] Measuring response timing consistency..."
TIMES=()
for i in $(seq 1 5); do
    T=$(timeout 3 ping -c 1 -W 1 "$TARGET" 2>/dev/null | grep "time=" | sed 's/.*time=\([0-9.]*\).*/\1/' || echo "0")
    TIMES+=("$T")
done

# Calculate timing variance
AVG=$(echo "${TIMES[@]}" | tr ' ' '\n' | awk '{sum+=$1; n++} END {print sum/n}')
VARIANCE=$(echo "${TIMES[@]}" | tr ' ' '\n' | awk -v avg="$AVG" '{sum+=($1-avg)^2; n++} END {print sqrt(sum/n)}')

echo "  Avg RTT: ${AVG}ms, Variance: ${VARIANCE}ms" >> "$REPORT_FILE"

# Very low variance can indicate virtualization/honeypot
if [[ $(echo "$VARIANCE < 0.1" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
    finding "MEDIUM" "Suspiciously consistent response times (variance: ${VARIANCE}ms) — may be virtualized"
fi

# Very fast responses can indicate honeypot
if [[ $(echo "$AVG < 1.0" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
    finding "LOW" "Very fast response time (${AVG}ms) — check if target is on local network"
fi

# ── 5. TTL Analysis ───────────────────────────────────────────────────────────
log "$CYAN" "[5/8] TTL analysis..."
TTL=$(ping -c 1 -W 2 "$TARGET" 2>/dev/null | grep "ttl=" | sed 's/.*ttl=\([0-9]*\).*/\1/' || echo "unknown")

echo "  TTL: $TTL" >> "$REPORT_FILE"

if [[ "$TTL" != "unknown" ]]; then
    if [[ $TTL -le 10 ]]; then
        finding "MEDIUM" "Low TTL ($TTL) — target may be behind multiple hops or virtualized"
    elif [[ $TTL -ge 64 && $TTL -le 128 ]]; then
        finding "LOW" "TTL $TTL suggests Linux/Unix (64) or Windows (128) origin"
    fi
fi

# ── 6. HTTP Header Analysis ──────────────────────────────────────────────────
log "$CYAN" "[6/8] HTTP header analysis..."

for port in 80 443 8080 8443; do
    HEADERS=$(curl -sk -m 5 -I "http://$TARGET:$port/" 2>/dev/null || echo "")
    
    if [[ -n "$HEADERS" ]]; then
        echo "--- Port $port ---" >> "$REPORT_FILE"
        echo "$HEADERS" >> "$REPORT_FILE"
        
        # Check for honeypot indicators in headers
        if echo "$HEADERS" | grep -qiE "Server:.*Cowrie|Server:.*Honey|Server:.*Kippo"; then
            finding "CRITICAL" "Known honeypot HTTP server on port $port"
        fi
        
        # Check for missing security headers (common in honeypots)
        if echo "$HEADERS" | grep -qi "Server:"; then
            SERVER=$(echo "$HEADERS" | grep -i "Server:" | head -1)
            finding "LOW" "Server header exposed: $SERVER"
        fi
        
        # Check for generic/unrealistic headers
        if echo "$HEADERS" | grep -qiE "Server:.*Microsoft-IIS/[0-9]+\.[0-9]+"; then
            IIS_VER=$(echo "$HEADERS" | grep -i "Server:" | sed 's/.*IIS\/\([0-9.]*\).*/\1/')
            if [[ $(echo "$IIS_VER > 10.0" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
                finding "MEDIUM" "Unrealistic IIS version ($IIS_VER) — possible honeypot"
            fi
        fi
    fi
done

# ── 7. SSL/TLS Certificate Analysis ──────────────────────────────────────────
log "$CYAN" "[7/8] SSL/TLS certificate analysis..."

CERT_INFO=$(echo | timeout 5 openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null || echo "")

if [[ -n "$CERT_INFO" ]]; then
    # Check cert subject
    SUBJECT=$(echo "$CERT_INFO" | openssl x509 -noout -subject 2>/dev/null || echo "")
    ISSUER=$(echo "$CERT_INFO" | openssl x509 -noout -issuer 2>/dev/null || echo "")
    DATES=$(echo "$CERT_INFO" | openssl x509 -noout -dates 2>/dev/null || echo "")
    
    echo "  Subject: $SUBJECT" >> "$REPORT_FILE"
    echo "  Issuer: $ISSUER" >> "$REPORT_FILE"
    echo "  Dates: $DATES" >> "$REPORT_FILE"
    
    # Self-signed certs are common on honeypots
    if echo "$ISSUER" | grep -qi "self-signed\|CN.*$TARGET\|subject.*$TARGET"; then
        finding "MEDIUM" "Self-signed or target-matching certificate — possible honeypot"
    fi
    
    # Very short cert lifetimes
    if echo "$DATES" | grep -qi "notAfter"; then
        NOT_AFTER=$(echo "$DATES" | grep "notAfter" | sed 's/notAfter=//')
        CERT_EXPIRY=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
        NOW=$(date +%s)
        DAYS_LEFT=$(( (CERT_EXPIRY - NOW) / 86400 ))
        
        if [[ $DAYS_LEFT -lt 30 && $DAYS_LEFT -gt 0 ]]; then
            finding "LOW" "Certificate expires in $DAYS_LEFT days — short-lived certs can indicate automated honeypots"
        fi
    fi
fi

# ── 8. Behavioral Analysis ───────────────────────────────────────────────────
log "$CYAN" "[8/8] Behavioral analysis..."

# Check if the target accepts connections to unlikely ports
UNLIKELY_PORTS="31337 4444 5555 6666 9999 12345 54321"
for port in $UNLIKELY_PORTS; do
    if timeout 1 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null; then
        finding "MEDIUM" "Port $port open — unusual port, common in honeypots or C2"
    fi
done

# Check for tarpitting (very slow responses)
log "$CYAN" "  Checking for tarpitting..."
for i in $(seq 1 2); do
    START=$(date +%s%N)
    timeout 3 bash -c "echo >/dev/tcp/$TARGET/80" 2>/dev/null || true
    END=$(date +%s%N)
    ELAPSED=$(( (END - START) / 1000000 ))
    
    if [[ $ELAPSED -gt 3000 ]]; then
        finding "MEDIUM" "Response delay ${ELAPSED}ms on port 80 — possible tarpitting (honeypot defense)"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════" | tee -a "$REPORT_FILE"
echo "  SCAN COMPLETE" | tee -a "$REPORT_FILE"
echo "════════════════════════════════════════════════════════════════" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "  Findings: $FINDINGS" | tee -a "$REPORT_FILE"
echo "  Risk Score: $RISK_SCORE / 100" | tee -a "$REPORT_FILE"
echo "  Report: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

if [[ $RISK_SCORE -ge 25 ]]; then
    echo -e "  ${RED}╔══════════════════════════════════════════════╗${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${RED}║  HIGH RISK — LIKELY HONEYPOT                 ║${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${RED}║  Do NOT engage without further investigation  ║${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${RED}╚══════════════════════════════════════════════╝${NC}" | tee -a "$REPORT_FILE"
elif [[ $RISK_SCORE -ge 10 ]]; then
    echo -e "  ${YELLOW}╔══════════════════════════════════════════════╗${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${YELLOW}║  MEDIUM RISK — INVESTIGATE FURTHER           ║${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${YELLOW}║  Some indicators suggest honeypot activity   ║${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${YELLOW}╚══════════════════════════════════════════════╝${NC}" | tee -a "$REPORT_FILE"
else
    echo -e "  ${GREEN}╔══════════════════════════════════════════════╗${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${GREEN}║  LOW RISK — LIKELY LEGITIMATE TARGET         ║${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${GREEN}║  No strong honeypot indicators found         ║${NC}" | tee -a "$REPORT_FILE"
    echo -e "  ${GREEN}╚══════════════════════════════════════════════╝${NC}" | tee -a "$REPORT_FILE"
fi

echo ""
