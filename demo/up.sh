#!/usr/bin/env bash
# Start the demo stand: production configs, synthetic data, everything on 127.0.0.1.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

command -v docker >/dev/null || { echo "[!] Docker is required: https://docs.docker.com/get-docker/" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "[!] Docker Compose v2 is required (docker compose ...)" >&2; exit 1; }

# A random Grafana admin password, kept in demo/.env (ignored by git).
if [[ ! -f .env ]] || ! grep -q '^GRAFANA_ADMIN_PASSWORD=' .env; then
  pass="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 || true)"
  key="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 || true)"
  printf 'GRAFANA_ADMIN_PASSWORD=%s\nGRAFANA_SECRET_KEY=%s\n' "$pass" "$key" >> .env
  chmod 600 .env
fi
set -a; . ./.env; set +a

docker compose up -d

port="${GRAFANA_PORT:-3000}"
printf 'Waiting for Grafana'
for _ in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then ok=1; break; fi
  printf '.'; sleep 2
done
echo
[[ "${ok:-}" == 1 ]] || { echo "[!] Grafana did not answer; see: docker compose logs grafana" >&2; exit 1; }

cat <<EOF
Demo stand is up.
  Grafana       http://127.0.0.1:${port}  (read-only without login; admin / ${GRAFANA_ADMIN_PASSWORD})
  Prometheus    http://127.0.0.1:${PROMETHEUS_PORT:-9090}
  Alertmanager  http://127.0.0.1:${ALERTMANAGER_PORT:-9093}
  Mailpit       http://127.0.0.1:${MAILPIT_WEB_PORT:-8025}  (alert e-mails)
An attack wave runs now and every ${DEMO_WAVE_MINUTES:-15} minutes. One more on demand:
  docker compose exec feeder python demo/feeder/feeder.py --repo /repo --loki http://loki:3100 --scenario spray
Stop: ./down.sh
EOF
