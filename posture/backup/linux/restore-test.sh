#!/usr/bin/env bash
# =============================================================================
# Restore test (restic) for Linux servers/endpoints
# =============================================================================
# CIS IG1 11.3 - Test backup restoration. Restores the canary file from the
# latest snapshot into a temp directory and compares its SHA-256 with the value
# recorded by backup.sh outside the repository.
#
# Metric written only on success:
#   backup_last_restore_test_timestamp_seconds{job,host}
#
# Schedule weekly (systemd timer or cron as root). Same environment as backup.sh.
# =============================================================================
set -euo pipefail

TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile}"
JOB="${BACKUP_JOB:-restic}"
STATE_DIR="${STATE_DIR:-/var/lib/backup}"
HOST_NAME="$(hostname -s)"

command -v restic >/dev/null 2>&1 || { echo "restic not found in PATH" >&2; exit 1; }
: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is not set}"
if [[ -z "${RESTIC_PASSWORD_FILE:-}" && -z "${RESTIC_PASSWORD:-}" ]]; then
    echo "Set RESTIC_PASSWORD_FILE (preferred) or RESTIC_PASSWORD" >&2
    exit 1
fi

HASH_FILE="$STATE_DIR/canary.sha256"
if [[ ! -s "$HASH_FILE" ]]; then
    echo "Canary hash not found at $HASH_FILE; run backup.sh first" >&2
    exit 1
fi
expected_hash="$(awk '{print $1}' "$HASH_FILE")"
canary_path="$(awk '{print $2}' "$HASH_FILE")"

target="$(mktemp -d)"
cleanup() { rm -rf "$target"; }
trap cleanup EXIT

restic restore latest --tag "$JOB" --host "$HOST_NAME" --target "$target" --include "$canary_path"

restored="$(find "$target" -type f -name 'restore-canary.txt' | head -n 1)"
if [[ -z "$restored" ]]; then
    echo "Canary file not present in restored output" >&2
    exit 1
fi

actual_hash="$(sha256sum "$restored" | awk '{print $1}')"
if [[ "$actual_hash" != "$expected_hash" ]]; then
    echo "Canary hash mismatch: expected $expected_hash, got $actual_hash" >&2
    exit 1
fi

mkdir -p "$TEXTFILE_DIR"
tmp="$(mktemp "$TEXTFILE_DIR/.backup_restore_test.XXXXXX")"
cat > "$tmp" <<EOF
# HELP backup_last_restore_test_timestamp_seconds Unix time of the last successful restore test (canary hash verified).
# TYPE backup_last_restore_test_timestamp_seconds gauge
backup_last_restore_test_timestamp_seconds{job="${JOB}",host="${HOST_NAME}"} $(date +%s)
EOF
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_DIR/backup_restore_test.prom"
echo "Restore test passed; metric updated."
