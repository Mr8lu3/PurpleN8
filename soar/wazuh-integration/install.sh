#!/usr/bin/env bash
# Install the PurpleN8 n8n integration into the Wazuh manager container.
#   ./install.sh [container-name]
# Safe to re-run: skips the config block if it is already present.
set -euo pipefail
C="${1:-purplen8-wazuh-manager}"
DIR="$(cd "$(dirname "$0")" && pwd)"
CONF=/var/ossec/etc/ossec.conf

echo "[*] Copying integration scripts into $C"
docker cp "$DIR/custom-n8n"    "$C:/var/ossec/integrations/custom-n8n"
docker cp "$DIR/custom-n8n.py" "$C:/var/ossec/integrations/custom-n8n.py"
docker exec "$C" sh -c 'chown root:wazuh /var/ossec/integrations/custom-n8n* && chmod 750 /var/ossec/integrations/custom-n8n*'

echo "[*] Creating lab log file"
docker exec "$C" sh -c 'mkdir -p /var/log/purplen8 && touch /var/log/purplen8/auth.log'

if docker exec "$C" grep -q '<name>custom-n8n</name>' "$CONF"; then
  echo "[*] PurpleN8 config already present in ossec.conf"
else
  echo "[*] Appending PurpleN8 config to ossec.conf (backup: ossec.conf.bak-purplen8)"
  docker exec "$C" cp "$CONF" "$CONF.bak-purplen8"
  docker exec -i "$C" sh -c "cat >> $CONF" < "$DIR/ossec-purplen8.xml"
fi

echo "[*] Restarting Wazuh services"
docker exec "$C" /var/ossec/bin/wazuh-control restart >/dev/null
docker exec "$C" /var/ossec/bin/wazuh-control status | grep -E 'integratord|logcollector'
