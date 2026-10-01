#!/usr/bin/env python3
"""
Wazuh -> n8n integration.

Wazuh's integratord calls this script for every alert that matches the
<integration> block in ossec.conf, with these arguments:
    argv[1]  path to a temp file containing the alert (JSON)
    argv[2]  api_key   (unused here)
    argv[3]  hook_url  (the n8n webhook URL)

The alert is forwarded unchanged; all parsing and scoring happens in n8n.
Uses only the standard library so it runs on Wazuh's bundled Python.
"""
import json
import sys
import time
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT = 10


def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-n8n: {msg}\n")


def main(args):
    if len(args) < 4:
        log(f"wrong arguments: {args}")
        sys.exit(1)

    alert_file, hook_url = args[1], args[3]
    with open(alert_file) as f:
        alert = json.load(f)

    req = urllib.request.Request(
        hook_url,
        data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status >= 300:
                log(f"n8n returned HTTP {resp.status} for alert {alert.get('id')}")
    except Exception as e:
        log(f"failed to send alert {alert.get('id')} to {hook_url}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
