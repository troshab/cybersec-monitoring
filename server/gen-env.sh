#!/usr/bin/env bash
# =============================================================================
# gen-env.sh - create the untracked .env from .env.example with random secrets
#
# Usage:
#   ./server/gen-env.sh            # creates .env; refuses to overwrite an existing one
#   ./server/gen-env.sh --force    # regenerates .env (rotates the generated secrets)
#
# Only the keys listed in GENERATED_KEYS are filled with random values. External
# credentials (Pushover, SNMP community, lab target logins) stay CHANGE_ME until
# the operator supplies them. CIS IG1 5.2: no default or shared credentials.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE="$ROOT/.env.example"
TARGET="$ROOT/.env"

GENERATED_KEYS="GRAFANA_ADMIN_PASSWORD GRAFANA_SECRET_KEY NETDISCO_DB_PASSWORD NETDISCO_ADMIN_PASS FLEET_MYSQL_ROOT_PASSWORD FLEET_MYSQL_PASSWORD FLEET_SERVER_PRIVATE_KEY"

if [[ "${1:-}" != "--force" && -f "$TARGET" ]]; then
    echo "[!] $TARGET already exists. Use --force to regenerate the generated secrets." >&2
    exit 1
fi

[[ -f "$EXAMPLE" ]] || { echo "[!] $EXAMPLE not found" >&2; exit 1; }
command -v openssl >/dev/null || { echo "[!] openssl is required" >&2; exit 1; }

# 24 alphanumeric characters: no shell- or YAML-special characters.
rand_secret() {
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 24
}

# 32 random bytes as hex (Grafana secret_key, Fleet private key).
rand_hex() {
    openssl rand -hex 32
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    key="${line%%=*}"
    if [[ "$line" == *"=CHANGE_ME" && " $GENERATED_KEYS " == *" $key "* ]]; then
        case "$key" in
            GRAFANA_SECRET_KEY|FLEET_SERVER_PRIVATE_KEY) value="$(rand_hex)" ;;
            *)                                            value="$(rand_secret)" ;;
        esac
        echo "${key}=${value}"
    else
        echo "$line"
    fi
done < "$EXAMPLE" > "$tmp"

if grep -q '=CHANGE_ME' "$tmp"; then
    echo "[i] Still CHANGE_ME (operator must set before use):"
    grep '=CHANGE_ME' "$tmp" | cut -d= -f1 | sed 's/^/    /'
fi

install -m 600 "$tmp" "$TARGET"
echo "[+] Wrote $TARGET (mode 600). Do not commit this file."
