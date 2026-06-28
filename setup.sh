#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# opsec-setup — First-time encryption of secrets vault
# ═══════════════════════════════════════════════════════════════════════════════
# Run this ONCE to encrypt your secrets vault.
# After this, `source ~/.opsec/load.sh` will decrypt and load secrets.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "════════════════════════════════════════════════════════════════"
echo "  OPSEC Vault Setup — Encrypt your secrets"
echo "════════════════════════════════════════════════════════════════"

SECRETS_FILE="${HOME}/.opsec/secrets.env"
VAULT_FILE="${HOME}/.opsec/secrets.env.gpg"

if [[ ! -f "$SECRETS_FILE" ]]; then
    echo "[!] ERROR: $SECRETS_FILE not found"
    exit 1
fi

# Check if vault already exists
if [[ -f "$VAULT_FILE" ]]; then
    echo "[!] Vault already exists at $VAULT_FILE"
    read -rp "Overwrite? [y/N] " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && exit 0
fi

echo ""
echo "[*] You'll be prompted to create a passphrase for the vault."
echo "[*] This passphrase decrypts all your API keys and secrets."
echo "[*] WRITE IT DOWN somewhere safe. Without it, secrets are lost."
echo ""

gpg --symmetric --cipher-algo AES256 --output "$VAULT_FILE" "$SECRETS_FILE"

if [[ $? -eq 0 && -f "$VAULT_FILE" ]]; then
    echo ""
    echo "[+] Vault encrypted: $VAULT_FILE"
    echo "[+] Plaintext file: $SECRETS_FILE (delete or keep as backup)"
    echo ""
    echo "[*] Add to your shell:"
    echo "    source ~/.opsec/load.sh"
    echo ""
    echo "[*] Clean API keys from .bashrc (see opsec-bashrc-clean.sh)"
else
    echo "[!] ERROR: Encryption failed"
    exit 1
fi
