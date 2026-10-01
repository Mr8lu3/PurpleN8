"""
PurpleN8 local IP enrichment service.

Looks up IPs entirely offline so attacker/alert data never leaves the machine:
  - Country / city  : DB-IP "IP to City Lite"  (CC BY 4.0, https://db-ip.com)
  - ASN / network   : DB-IP "IP to ASN Lite"   (CC BY 4.0, https://db-ip.com)
  - Tor exit nodes  : Tor Project bulk exit list
  - Hosting/cloud   : heuristic from the ASN (known provider ASNs + name keywords)

Only the public datasets are downloaded (no lookups are sent anywhere).
Databases refresh monthly, the Tor list every 6 hours.

GET /lookup/<ip>  ->  {"status": "success", "query", "country", "countryCode", "city",
                       "asn", "isp", "tor", "hosting"}
GET /health       ->  dataset status
"""
import datetime as dt
import gzip
import ipaddress
import json
import os
import shutil
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import maxminddb

DATA = os.environ.get("DATA_DIR", "/data")
TOR_URL = "https://check.torproject.org/torbulkexitlist"
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
TOR_REFRESH = 6 * 3600

# Well-known hosting / cloud / VPS providers (ASN numbers). Not exhaustive.
HOSTING_ASNS = {
    16509, 14618,          # Amazon AWS
    396982, 15169,         # Google Cloud / Google
    8075,                  # Microsoft Azure
    14061,                 # DigitalOcean
    16276,                 # OVH
    24940,                 # Hetzner
    63949,                 # Akamai / Linode
    20473,                 # Vultr (Choopa)
    51167,                 # Contabo
    12876,                 # Scaleway
    31898,                 # Oracle Cloud
    45102,                 # Alibaba Cloud
    132203,                # Tencent Cloud
    60781, 28753,          # Leaseweb
    9009,                  # M247
    398324, 398705,        # Censys
    13335,                 # Cloudflare
    47583,                 # Hostinger
    8560,                  # IONOS
    53667,                 # FranTech / BuyVM
    212238, 60068,         # Datacamp / CDN77
}
HOSTING_KEYWORDS = ("hosting", "cloud", "datacenter", "data center", "server", "vps", "colocation")

state = {"city": None, "asn": None, "tor": set(), "tor_updated": None, "db_month": None}
lock = threading.Lock()


def log(msg):
    print(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {msg}")


def download(url, dest):
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": "PurpleN8-enrich"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f)
    os.replace(tmp, dest)


def load_dbip():
    """Use this month's DB-IP files, falling back to last month (published early in the month)."""
    today = dt.date.today()
    months = [today.strftime("%Y-%m"), (today.replace(day=1) - dt.timedelta(days=1)).strftime("%Y-%m")]
    for month in months:
        try:
            readers = {}
            for kind in ("city", "asn"):
                path = f"{DATA}/dbip-{kind}-lite-{month}.mmdb"
                if not os.path.exists(path):
                    log(f"downloading DB-IP {kind} lite {month}")
                    download(DBIP_URL.format(kind=kind, month=month), path + ".gz")
                    with gzip.open(path + ".gz") as src, open(path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    os.remove(path + ".gz")
                readers[kind] = maxminddb.open_database(path)
            with lock:
                state["city"], state["asn"], state["db_month"] = readers["city"], readers["asn"], month
            # remove older months
            for f in os.listdir(DATA):
                if f.startswith("dbip-") and month not in f:
                    os.remove(os.path.join(DATA, f))
            log(f"DB-IP databases loaded ({month})")
            return
        except Exception as e:
            log(f"DB-IP {month} unavailable: {e}")


def load_tor():
    path = f"{DATA}/tor-exits.txt"
    try:
        download(TOR_URL, path)
    except Exception as e:
        log(f"Tor list download failed ({e}); using cached copy if present")
    if os.path.exists(path):
        with open(path) as f:
            exits = {line.strip() for line in f if line.strip() and not line.startswith("#")}
        with lock:
            state["tor"], state["tor_updated"] = exits, dt.datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
        log(f"Tor exit list loaded ({len(exits)} nodes)")


def refresher():
    while True:
        time.sleep(TOR_REFRESH)
        load_tor()
        if state["db_month"] != dt.date.today().strftime("%Y-%m"):
            load_dbip()


def lookup(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"status": "fail", "message": "invalid query", "query": ip}
    if not addr.is_global:
        return {"status": "fail", "message": "private range", "query": ip}
    with lock:
        city, asn, tor = state["city"], state["asn"], state["tor"]
    if city is None or asn is None:
        return {"status": "fail", "message": "databases not loaded yet", "query": ip}

    c = city.get(ip) or {}
    a = asn.get(ip) or {}
    asn_num = a.get("autonomous_system_number")
    org = a.get("autonomous_system_organization") or ""
    hosting = asn_num in HOSTING_ASNS or any(k in org.lower() for k in HOSTING_KEYWORDS)
    return {
        "status": "success",
        "query": ip,
        "country": (c.get("country") or {}).get("names", {}).get("en"),
        "countryCode": (c.get("country") or {}).get("iso_code"),
        "city": (c.get("city") or {}).get("names", {}).get("en"),
        "asn": asn_num,
        "isp": org,
        "tor": ip in tor,
        "hosting": hosting,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/lookup/"):
            self._send(200, lookup(self.path[len("/lookup/"):]))
        elif self.path == "/health":
            self._send(200, {"db_month": state["db_month"], "tor_nodes": len(state["tor"]),
                             "tor_updated": state["tor_updated"]})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):  # keep looked-up IPs out of the container logs
        pass


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    load_dbip()
    load_tor()
    threading.Thread(target=refresher, daemon=True).start()
    log("listening on :8080")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
