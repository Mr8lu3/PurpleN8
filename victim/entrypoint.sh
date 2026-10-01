#!/bin/sh
# Configure and start the Wazuh agent, then keep the container alive.
set -e
CONF=/var/ossec/etc/ossec.conf
NAME="${WAZUH_AGENT_NAME:-victim-web-01}"

# Agent name used at enrollment
grep -q "<agent_name>" "$CONF" || sed -i "s|<enrollment>|<enrollment>\n      <agent_name>$NAME</agent_name>|" "$CONF"

# Watch the lab auth log written by soar/scripts/simulate-ssh-bruteforce.sh
mkdir -p /var/log/purplen8 && touch /var/log/purplen8/auth.log
grep -q "/var/log/purplen8/auth.log" "$CONF" || cat >> "$CONF" <<'XML'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/purplen8/auth.log</location>
  </localfile>
</ossec_config>
XML

/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log
