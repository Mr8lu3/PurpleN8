#!/usr/bin/env bash
# End-to-end tests against the running PurpleN8 stack.
# Alerts carry "purplen8_dry_run": true, so they go through the real pipeline
# (auth, enrichment, scoring, dedupe, audit log) but never notify or block.
# Test rows are kept in alert_log with alert ids starting "it-".
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
TOKEN=$(grep '^WEBHOOK_TOKEN=' .env | cut -d= -f2-)
URL=http://127.0.0.1:5678/webhook/wazuh-alert
RUN="it-$(date +%s)"
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }
sql()  { docker exec purplen8-postgres psql -tAU purplen8 -d purplen8 -c "$1"; }

# send <sample-file> <alert-id> [python expression to modify alert `a`]
send() {
  python3 - "$1" "$2" "${3:-}" <<'PY' | curl -s -o /dev/null -X POST "$URL" -H 'Content-Type: application/json' -H "X-PurpleN8-Token: $TOKEN" --data @-
import json, sys
a = json.load(open(sys.argv[1])); a["id"] = sys.argv[2]; a["purplen8_dry_run"] = True
if sys.argv[3]: exec(sys.argv[3])
print(json.dumps(a))
PY
}
row() {  # wait for an audit row and print "severity|score|action|reasons"
  for _ in $(seq 1 40); do
    r=$(sql "select severity||'|'||score||'|'||action||'|'||reasons::text from alert_log where alert_id='$1' order by id desc limit 1")
    [ -n "$r" ] && { echo "$r"; return; }; sleep 0.5
  done
}
S=soar/samples

echo "== Webhook authentication"
check "no token is rejected"  "$(curl -s -o /dev/null -w '%{http_code}' -X POST $URL -d '{}')" 403
check "bad token is rejected" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $URL -H 'X-PurpleN8-Token: nope' -d '{}')" 403

echo "== Triage pipeline (dry run)"
sql "delete from dedupe_window where key in ('185.220.101.45|5763','167.94.138.35|31164','81.2.69.142|60122',
     'web-server-01|Integrity checksum changed.|550','10.9.8.7|5763','185.220.101.46|5763')" >/dev/null
send $S/01-ssh-bruteforce.json "$RUN-ssh"
send $S/02-web-sqli.json "$RUN-sqli"
send $S/03-windows-logon-failure.json "$RUN-win"
send $S/04-file-integrity-change.json "$RUN-fim"
send $S/01-ssh-bruteforce.json "$RUN-private" 'a["data"]["srcip"] = "10.9.8.7"'

r=$(row "$RUN-ssh");     check "SSH brute force from Tor exit -> high"       "$(cut -d'|' -f1 <<<"$r")" high
                         check "  ... Tor detected by offline enrichment"   "$(grep -c 'Tor exit node' <<<"$r")" 1
                         check "  ... would notify"                          "$(cut -d'|' -f3 <<<"$r")" "dry_run(notified)"
r=$(row "$RUN-sqli");    check "SQL injection from hosting provider -> medium" "$(cut -d'|' -f1 <<<"$r")" medium
                         check "  ... hosting provider detected"           "$(grep -c 'datacenter / hosting' <<<"$r")" 1
r=$(row "$RUN-win");     check "UK home IP logon failure -> low (20)"      "$(cut -d'|' -f1-3 <<<"$r")" "low|20|dry_run(logged)"
r=$(row "$RUN-fim");     check "File change without IP -> low (28)"        "$(cut -d'|' -f1-3 <<<"$r")" "low|28|dry_run(logged)"
r=$(row "$RUN-private"); check "Private source IP -> not enriched (40)"    "$(cut -d'|' -f1-2 <<<"$r")" "medium|40"
                         check "  ... marked internal"                     "$(grep -c 'internal source IP' <<<"$r")" 1

send $S/01-ssh-bruteforce.json "$RUN-dup"
r=$(row "$RUN-dup");     check "Repeat within 10 min -> suppressed"        "$(cut -d'|' -f3 <<<"$r")" "dry_run(suppressed)"

echo "== Dedupe under concurrency (10 identical alerts at once)"
for i in $(seq 1 10); do send $S/01-ssh-bruteforce.json "$RUN-burst-$i" 'a["data"]["srcip"] = "185.220.101.46"' & done; wait
for _ in $(seq 1 40); do [ "$(sql "select count(*) from alert_log where alert_id like '$RUN-burst-%'")" = 10 ] && break; sleep 0.5; done
check "exactly one of 10 is new" "$(sql "select count(*) from alert_log where alert_id like '$RUN-burst-%' and action <> 'dry_run(suppressed)'")" 1

echo "== Offline enrichment service"
check "Tor exit flagged"       "$(docker exec purplen8-n8n wget -qO- http://enrich:8080/lookup/185.220.101.45 | grep -o '"tor": true')" '"tor": true'
check "private IP not looked up" "$(docker exec purplen8-n8n wget -qO- http://enrich:8080/lookup/10.0.0.1 | grep -o 'private range')" "private range"

echo "== Wazuh API hardening"
API_USER=$(grep '^WAZUH_API_USER=' .env | cut -d= -f2-); API_PW=$(grep '^WAZUH_API_PASSWORD=' .env | cut -d= -f2-)
check "factory admin password rejected" "$(docker exec purplen8-wazuh-manager curl -sk -o /dev/null -w '%{http_code}' -u wazuh:wazuh -X POST https://localhost:55000/security/user/authenticate)" 401
T=$(docker exec purplen8-wazuh-manager curl -sk -u "$API_USER:$API_PW" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
check "n8n API user cannot list agents" "$(docker exec purplen8-wazuh-manager curl -sk https://localhost:55000/agents -H "Authorization: Bearer $T" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["total_affected_items"])')" 0

echo "== Network exposure"
check "n8n bound to localhost only" "$(docker port purplen8-n8n 5678/tcp)" "127.0.0.1:5678"
for c in purplen8-postgres purplen8-enrich purplen8-wazuh-manager purplen8-victim; do
  check "$c publishes no ports" "$(docker port $c | wc -l)" 0
done

echo "== Pentest scope gate"
curl -s -o /dev/null -X POST http://127.0.0.1:5678/form/purplen8-engagement -F "field-0=$RUN scope test" -F 'field-1=CI' \
  -F 'field-2=LAB-TEST' -F 'field-3=http://example.com' -F 'field-4=2020-01-01' -F 'field-5=2020-01-02' \
  -F 'field-6=I own or am authorised to test these targets'
for _ in $(seq 1 20); do s=$(sql "select status from engagements where name='$RUN scope test'"); [ -n "$s" ] && break; sleep 0.5; done
check "out-of-scope engagement rejected and recorded" "$s" rejected

echo; echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
