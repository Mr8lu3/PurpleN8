#!/usr/bin/env bash
# Harden the Wazuh API and create a least-privilege user for n8n.
#   1. Changes the factory admin password (wazuh:wazuh) to WAZUH_ADMIN_PASSWORD
#   2. Creates WAZUH_API_USER with a role that can ONLY run active responses
# Reads passwords from ../../.env (generated if missing). Safe to re-run.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV="$ROOT/.env"
C="${WAZUH_CONTAINER:-purplen8-wazuh-manager}"
API="https://localhost:55000"

# Wazuh password policy: 8-64 chars with upper, lower, digit and symbol
gen() { printf 'Pn8.%s-x' "$(openssl rand -hex 12)"; }
for var in WAZUH_ADMIN_PASSWORD WAZUH_API_PASSWORD; do
  grep -q "^$var=." "$ENV" 2>/dev/null || { sed -i "/^$var=/d" "$ENV"; echo "$var=$(gen)" >> "$ENV"; }
done
grep -q '^WAZUH_API_USER=.' "$ENV" || { sed -i '/^WAZUH_API_USER=/d' "$ENV"; echo "WAZUH_API_USER=purplen8" >> "$ENV"; }
ADMIN_PW=$(grep '^WAZUH_ADMIN_PASSWORD=' "$ENV" | cut -d= -f2-)
API_USER=$(grep '^WAZUH_API_USER=' "$ENV" | cut -d= -f2-)
API_PW=$(grep '^WAZUH_API_PASSWORD=' "$ENV" | cut -d= -f2-)

api() {  # api METHOD PATH [JSON] -- uses $TOKEN
  docker exec "$C" curl -sk -X "$1" "$API$2" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' ${3:+-d "$3"}
}
login() { docker exec "$C" curl -sk -u "$1:$2" -X POST "$API/security/user/authenticate?raw=true"; }
jq_py() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# 1. Admin login: try the factory default first, then the hardened password
TOKEN=$(login wazuh wazuh)
if [[ "$TOKEN" == eyJ* ]]; then
  echo "[*] Factory admin password still active - changing it"
  ADMIN_ID=$(api GET "/security/users?search=wazuh" | jq_py "[u['id'] for u in d['data']['affected_items'] if u['username']=='wazuh'][0]")
  api PUT "/security/users/$ADMIN_ID" "{\"password\":\"$ADMIN_PW\"}" | jq_py "d['message']"
  TOKEN=$(login wazuh "$ADMIN_PW")
else
  TOKEN=$(login wazuh "$ADMIN_PW")
fi
[[ "$TOKEN" == eyJ* ]] || { echo "[!] Could not log in as wazuh admin"; exit 1; }

# 2. Least-privilege policy -> role -> user
# Reuse any policy granting exactly active-response:command on agent:id:* (Wazuh ships one
# and rejects duplicates), otherwise create it.
POLICY_ID=$(api GET "/security/policies?limit=500" | jq_py "next((p['id'] for p in d['data']['affected_items'] if p['policy']['actions']==['active-response:command'] and p['policy']['resources']==['agent:id:*'] and p['policy']['effect']=='allow'), '')")
if [[ -z "$POLICY_ID" ]]; then
  POLICY_ID=$(api POST /security/policies '{"name":"purplen8_active_response","policy":{"actions":["active-response:command"],"resources":["agent:id:*"],"effect":"allow"}}' | jq_py "d['data']['affected_items'][0]['id']")
fi
ROLE_ID=$(api GET "/security/roles?search=purplen8_responder" | jq_py "next((r['id'] for r in d['data']['affected_items'] if r['name']=='purplen8_responder'), '')")
if [[ -z "$ROLE_ID" ]]; then
  ROLE_ID=$(api POST /security/roles '{"name":"purplen8_responder"}' | jq_py "d['data']['affected_items'][0]['id']")
  api POST "/security/roles/$ROLE_ID/policies?policy_ids=$POLICY_ID" >/dev/null
fi
USER_ID=$(api GET "/security/users?search=$API_USER" | jq_py "next((u['id'] for u in d['data']['affected_items'] if u['username']=='$API_USER'), '')")
if [[ -z "$USER_ID" ]]; then
  USER_ID=$(api POST /security/users "{\"username\":\"$API_USER\",\"password\":\"$API_PW\"}" | jq_py "d['data']['affected_items'][0]['id']")
  api POST "/security/users/$USER_ID/roles?role_ids=$ROLE_ID" >/dev/null
fi
echo "[*] API user '$API_USER' (id $USER_ID) -> role purplen8_responder (id $ROLE_ID) -> policy active-response:command (id $POLICY_ID)"

# 3. Verify
T=$(login "$API_USER" "$API_PW"); [[ "$T" == eyJ* ]] && echo "[*] $API_USER can log in" || echo "[!] $API_USER login failed"
# Wazuh RBAC filters out what a user may not see instead of returning an error
SEEN=$(docker exec "$C" curl -sk "$API/agents" -H "Authorization: Bearer $T" | jq_py "d['data']['total_affected_items']")
echo "[*] $API_USER can see $SEEN agents via GET /agents (expected 0: read access denied)"
[[ "$(login wazuh wazuh)" == eyJ* ]] && echo "[!] factory password STILL works" || echo "[*] factory password wazuh:wazuh rejected"
