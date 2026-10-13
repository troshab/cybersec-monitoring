#!/usr/bin/env bash
# =============================================================================
# Backup (restic) for Linux servers/endpoints
# =============================================================================
# CIS IG1 11.2 - Perform automated backups (metric: backup_last_success_timestamp_seconds)
# CIS IG1 11.4 - Protect backup data: the restic repository is encrypted; the
#                password is never stored in this repository.
#
# Requires: restic 0.19.1 (https://github.com/restic/restic/releases/tag/v0.19.1)
# Environment (keep outside the repo, e.g. /etc/restic/restic.env, mode 0600):
#   RESTIC_REPOSITORY      repository URL or path
#   RESTIC_PASSWORD_FILE   file holding the repo password (mode 0600, root-owned)
#
# Usage:
#   backup.sh [--dry-run] PATH [PATH...]
#
# The success metric is written only after backup, forget/prune and a partial
# data check (restic check --read-data-subset=5%) have all succeeded.
# =============================================================================
set -euo pipefail

TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile}"
JOB="${BACKUP_JOB:-restic}"
STATE_DIR="${STATE_DIR:-/var/lib/backup}"
HOST_NAME="$(hostname -s)"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi
if [[ $# -lt 1 ]]; then
    echo "usage: $0 [--dry-run] PATH [PATH...]" >&2
    exit 2
fi

command -v restic >/dev/null 2>&1 || { echo "restic not found in PATH" >&2; exit 1; }
: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is not set}"
if [[ -z "${RESTIC_PASSWORD_FILE:-}" && -z "${RESTIC_PASSWORD:-}" ]]; then
    echo "Set RESTIC_PASSWORD_FILE (preferred) or RESTIC_PASSWORD" >&2
    exit 1
fi

write_metric() {
    # Atomic publish so node_exporter never reads a partial file.
    local file="$1" body="$2" tmp
    mkdir -p "$TEXTFILE_DIR"
    tmp="$(mktemp "$TEXTFILE_DIR/.${file}.XXXXXX")"
    printf '%s\n' "$body" > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$TEXTFILE_DIR/$file"
}

# Canary: random token inside the backup set; its hash stays outside the repo
# so restore-test.sh can verify a restore without trusting the repository.
mkdir -p "$STATE_DIR/canary"
CANARY="$STATE_DIR/canary/restore-canary.txt"
if [[ $DRY_RUN -eq 0 ]]; then
    token="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    printf '%s\n' "$token" > "$CANARY"
    sha256sum "$CANARY" > "$STATE_DIR/canary.sha256"
fi

backup_args=(backup --tag "$JOB" --host "$HOST_NAME" "$@")
if [[ $DRY_RUN -eq 0 ]]; then
    backup_args+=("$CANARY")
else
    backup_args+=(--dry-run)
fi
restic "${backup_args[@]}"

if [[ $DRY_RUN -eq 1 ]]; then
    echo "Dry run complete; no retention, check or metric update performed."
    exit 0
fi

restic forget --tag "$JOB" --host "$HOST_NAME" \
    --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
restic check --read-data-subset=5%

now="$(date +%s)"
write_metric backup_last_success.prom "$(cat <<EOF
# HELP backup_last_success_timestamp_seconds Unix time of the last successful backup run (forget and check included).
# TYPE backup_last_success_timestamp_seconds gauge
backup_last_success_timestamp_seconds{job="${JOB}",host="${HOST_NAME}"} ${now}
EOF
)"
echo "Backup completed; metric written to $TEXTFILE_DIR/backup_last_success.prom"
