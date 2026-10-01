#!/usr/bin/env bash
# Simulate an SSH brute-force attempt by writing failed-login lines to the
# victim's lab log (read by its Wazuh agent). Nothing is attacked; Wazuh just reads the lines.
#   ./simulate-ssh-bruteforce.sh [source-ip] [attempts]
set -euo pipefail
IP="${1:-185.220.101.33}"
N="${2:-9}"
C="${VICTIM_CONTAINER:-purplen8-victim}"

echo "[*] Writing $N failed SSH logins from $IP"
for i in $(seq 1 "$N"); do
  docker exec "$C" sh -c "echo \"\$(date '+%b %e %H:%M:%S') victim-web-01 sshd[$((4000 + i))]: Failed password for invalid user admin from $IP port $((50000 + i)) ssh2\" >> /var/log/purplen8/auth.log"
  sleep 1
done
echo "[*] Done. Wazuh should raise rule 5710 per line and 5712 (brute force) after 8."
