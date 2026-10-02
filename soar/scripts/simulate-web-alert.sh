#!/usr/bin/env bash
# Replay the sample web-attack access-log line (from soar/samples/02-web-sqli.json)
# into the lab web server's access log. Nothing is sent to any application;
# Wazuh simply reads the line, as it would a real log entry.
#   ./simulate-web-alert.sh [source-ip]
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
IP="${1:-167.94.138.35}"
C="${PROXY_CONTAINER:-purplen8-juice-shop}"
REQUEST=$(python3 -c "import json,sys; l=json.load(open(sys.argv[1]))['full_log']; print(l[l.index('\"'):])" "$DIR/../samples/02-web-sqli.json")
LINE="$IP - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] $REQUEST"
docker exec "$C" sh -c "printf '%s\n' '$LINE' >> /var/log/purplen8-web/access.log"
echo "[*] Replayed sample web log line from $IP (start the pentest profile first)"
