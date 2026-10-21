#!/usr/bin/env bash
# Stop the demo stand and delete its data volumes (demo/.env stays).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose down -v
