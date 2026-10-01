#!/usr/bin/env bash
# Send sample Wazuh alerts to the SOAR webhook.
#   ./send-sample.sh                 -> send every sample
#   ./send-sample.sh 01              -> send samples matching "01"
#   TEST=1 ./send-sample.sh 01       -> use the editor's test URL (click "Execute workflow" first)
set -euo pipefail
DIR="$(cd "$(dirname "$0")/../samples" && pwd)"
BASE="${N8N_URL:-http://localhost:5678}"
PATH_PART="webhook"; [[ "${TEST:-0}" == "1" ]] && PATH_PART="webhook-test"
URL="$BASE/$PATH_PART/wazuh-alert"

for f in "$DIR"/*${1:-}*.json; do
  echo "-> $(basename "$f")"
  curl -s -X POST "$URL" -H 'Content-Type: application/json' --data @"$f"
  echo
done
