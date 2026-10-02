#!/usr/bin/env bash
# PurpleN8 one-shot setup. Safe to re-run.
#   1. generates missing secrets in .env
#   2. builds and starts the containers
#   3. hardens the Wazuh API and installs the n8n integration
#   4. creates the n8n credentials from .env and imports + publishes the workflows
set -euo pipefail
cd "$(dirname "$0")"
step() { echo; echo "==> $*"; }
getenv() { grep "^$1=" .env | cut -d= -f2-; }
setenv() { sed -i "/^$1=/d" .env; echo "$1=$2" >> .env; }

step "Checking .env"
[[ -f .env ]] || { cp .env.example .env; echo "Created .env from .env.example - fill in TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, then re-run."; exit 1; }
for v in TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID; do
  [[ -n "$(getenv $v)" ]] || { echo "Missing $v in .env"; exit 1; }
done
[[ -n "$(getenv POSTGRES_PASSWORD)" ]] || setenv POSTGRES_PASSWORD "$(openssl rand -hex 16)"
[[ -n "$(getenv WEBHOOK_TOKEN)" ]]     || setenv WEBHOOK_TOKEN "$(openssl rand -hex 24)"
echo "ok"

step "Starting containers"
docker volume inspect n8n_data >/dev/null 2>&1 || docker volume create n8n_data >/dev/null
docker compose up -d --build
echo "waiting for Wazuh manager..."
timeout 300 sh -c 'until docker exec purplen8-wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-apid is running"; do sleep 3; done'
timeout 120 sh -c 'until docker exec purplen8-wazuh-manager curl -sk -o /dev/null https://localhost:55000/; do sleep 3; done'

step "Hardening the Wazuh API"
./soar/wazuh-integration/setup-api.sh

step "Installing the Wazuh -> n8n integration"
./soar/wazuh-integration/install.sh

step "Creating n8n credentials from .env"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
python3 - "$TMP" <<'PY'
import json, sys
env = dict(l.rstrip("\n").split("=", 1) for l in open(".env") if "=" in l and not l.startswith("#"))
creds = [
  {"id": "purplen8Telegram",   "name": "PurpleN8 Telegram bot", "type": "telegramApi",
   "data": {"accessToken": env["TELEGRAM_BOT_TOKEN"]}},
  {"id": "purplen8Postgres",   "name": "PurpleN8 Postgres", "type": "postgres",
   "data": {"host": "postgres", "port": 5432, "database": "purplen8", "user": "purplen8",
            "password": env["POSTGRES_PASSWORD"], "ssl": "disable"}},
  {"id": "purplen8WazuhApi",   "name": "Wazuh API (purplen8)", "type": "httpBasicAuth",
   "data": {"user": env["WAZUH_API_USER"], "password": env["WAZUH_API_PASSWORD"]}},
  {"id": "purplen8WebhookTok", "name": "Wazuh webhook token", "type": "httpHeaderAuth",
   "data": {"name": "X-PurpleN8-Token", "value": env["WEBHOOK_TOKEN"]}},
]
json.dump(creds, open(sys.argv[1], "w"))
PY
docker cp "$TMP" purplen8-n8n:/tmp/purplen8-creds.json
docker exec purplen8-n8n n8n import:credentials --input=/tmp/purplen8-creds.json
docker exec -u root purplen8-n8n rm -f /tmp/purplen8-creds.json

step "Importing and publishing workflows"
mkdir -p pentest/reports
for wf in soar/workflows/*.json pentest/workflows/*.json; do
  docker exec purplen8-n8n n8n import:workflow --input="/files/$wf"
done
for id in wazuhActResp0001 wazuhTriage00001 pentestEngage001; do
  docker exec purplen8-n8n n8n publish:workflow --id=$id >/dev/null
done
docker compose restart n8n >/dev/null
# Registered webhook answers 403 without the token (404 = not active yet)
timeout 180 sh -c 'until [ "$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:5678/webhook/wazuh-alert)" = 403 ]; do sleep 2; done'

step "Done"
cat <<MSG
  n8n:      http://127.0.0.1:5678   (first visit: create your local owner account)
  Test:     ./soar/scripts/send-sample.sh            (sample alerts)
            ./soar/scripts/simulate-ssh-bruteforce.sh (real Wazuh alerts from the lab victim)
  Audit:    docker exec -it purplen8-postgres psql -U purplen8 -d purplen8 -c "select * from alert_log order by id desc limit 10"
  Pentest:  docker compose --profile pentest up -d juice-shop
            then open http://127.0.0.1:5678/form/purplen8-engagement
MSG
