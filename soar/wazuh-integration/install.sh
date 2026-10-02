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

TOKEN=$(grep '^WEBHOOK_TOKEN=' "$DIR/../../.env" 2>/dev/null | cut -d= -f2-)
[[ -n "$TOKEN" ]] || { echo "[!] Set WEBHOOK_TOKEN in .env first"; exit 1; }

# Replace any previous PurpleN8 block, then append the current one
docker exec "$C" sh -c "test -f $CONF.bak-purplen8 || cp $CONF $CONF.bak-purplen8"
docker exec "$C" sed -i '/<!-- PurpleN8 BEGIN/,/<!-- PurpleN8 END -->/d' "$CONF"
echo "[*] Writing PurpleN8 config to ossec.conf (original saved as ossec.conf.bak-purplen8)"
sed "s|__WEBHOOK_TOKEN__|$TOKEN|" "$DIR/ossec-purplen8.xml" | docker exec -i "$C" sh -c "cat >> $CONF"

echo "[*] Restarting Wazuh services"
docker exec "$C" /var/ossec/bin/wazuh-control restart >/dev/null
docker exec "$C" /var/ossec/bin/wazuh-control status | grep -E 'integratord|logcollector' || true   # status exits 1 if any unused daemon (e.g. cluster) is stopped
