# Lab "victim" server: Ubuntu + Wazuh agent + iptables, so Wazuh active
# responses (firewall-drop) can really block IPs here.
FROM ubuntu:22.04
ARG WAZUH_VERSION=4.9.2-1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates iptables procps lsb-release \
 && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=${WAZUH_VERSION} \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY purplen8-unblock /var/ossec/active-response/bin/purplen8-unblock
RUN chown root:wazuh /var/ossec/active-response/bin/purplen8-unblock && chmod 750 /var/ossec/active-response/bin/purplen8-unblock
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
