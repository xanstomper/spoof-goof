#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-load — Decrypt and load secrets into current shell session
# ═══════════════════════════════════════════════════════════════════════════════
# Usage: source ~/.opsec/load.sh
# All secrets are in-memory only, never written to disk after decryption.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VAULT="${HOME}/.opsec/secrets.env.gpg"
PLAINTEXT="/dev/shm/.opsec_$$_$(date +%s)"

if [[ ! -f "$VAULT" ]]; then
    echo "[opsec] ERROR: Vault not found at $VAULT"
    echo "[opsec] Run: gpg --symmetric --cipher-algo AES256 ~/.opsec/secrets.env"
    return 1 2>/dev/null || exit 1
fi

echo "[opsec] Decrypting vault..."
gpg --batch --yes --quiet --decrypt --cipher-algo AES256 "$VAULT" > "$PLAINTEXT" 2>/dev/null

if [[ $? -ne 0 ]]; then
    echo "[opsec] ERROR: Decryption failed (wrong passphrase?)"
    rm -f "$PLAINTEXT"
    return 1 2>/dev/null || exit 1
fi

# Load each line, ignoring comments and blank lines
while IFS= read -r line; do
    line=$(echo "$line" | xargs)  # trim whitespace
    [[ -z "$line" || "$line" == \#* ]] && continue
    
    key="${line%%=*}"
    val="${line#*=}"
    # Strip surrounding quotes
    val="${val#\"}"
    val="${val%\"}"
    val="${val#\'}"
    val="${val%\'}"
    
    export "$key=$val"
done < "$PLAINTEXT"

# Securely wipe the temp file
shred -u "$PLAINTEXT" 2>/dev/null || rm -f "$PLAINTEXT"

echo "[opsec] Secrets loaded into session (in-memory only)"
echo "[opsec] To unload: unset \$(grep -oP '^[^#]+' ~/.opsec/secrets.env.gpg 2>/dev/null | cut -d= -f1)"
