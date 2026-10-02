#!/usr/bin/env python3
"""Static checks for the PurpleN8 repo (run locally and in CI).

1. Workflow integrity: valid JSON, every connection points at an existing node,
   every credential a node uses is one that setup.sh creates.
2. Secret scan: no bot tokens, private keys or filled-in .env values in tracked files.
"""
import json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors = []

# --- 1. workflows ---------------------------------------------------------------
setup = (ROOT / "setup.sh").read_text()
known_creds = set(re.findall(r'"id": "(purplen8\w+)"', setup))
workflows = sorted(ROOT.glob("*/workflows/*.json"))
for wf_path in workflows:
    rel = wf_path.relative_to(ROOT)
    try:
        wf = json.loads(wf_path.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"{rel}: invalid JSON ({e})"); continue
    names = {n["name"] for n in wf["nodes"]}
    if len(names) != len(wf["nodes"]):
        errors.append(f"{rel}: duplicate node names")
    for src, outputs in wf["connections"].items():
        if src not in names:
            errors.append(f"{rel}: connection from missing node '{src}'")
        for branch in outputs.get("main", []):
            for link in branch or []:
                if link["node"] not in names:
                    errors.append(f"{rel}: '{src}' connects to missing node '{link['node']}'")
    for n in wf["nodes"]:
        for ctype, cred in (n.get("credentials") or {}).items():
            if cred["id"] not in known_creds:
                errors.append(f"{rel}: node '{n['name']}' uses credential '{cred['id']}' that setup.sh does not create")
        if n["type"].endswith(".code") and "jsCode" not in n["parameters"]:
            errors.append(f"{rel}: code node '{n['name']}' has no code")
print(f"[workflows] {len(workflows)} checked, credentials known to setup.sh: {sorted(known_creds)}")

# --- 2. secrets -----------------------------------------------------------------
try:
    files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                           cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
except (subprocess.CalledProcessError, FileNotFoundError):
    files = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
PATTERNS = {
    "Telegram bot token": re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "filled-in secret variable": re.compile(r"^(TELEGRAM_BOT_TOKEN|POSTGRES_PASSWORD|WEBHOOK_TOKEN|WAZUH_ADMIN_PASSWORD|WAZUH_API_PASSWORD)=\S+", re.M),
}
for f in files:
    if f == ".env":
        errors.append(".env is tracked by git - it must stay ignored"); continue
    path = ROOT / f
    if path.suffix in {".png", ".jpg", ".gif", ".mmdb"} or not path.is_file():
        continue
    text = path.read_text(errors="ignore")
    for label, rx in PATTERNS.items():
        if rx.search(text):
            errors.append(f"{f}: looks like it contains a {label}")
print(f"[secrets]   {len(files)} files scanned")

# --- 3. executable bits ------------------------------------------------------------
# Committing from Windows (core.fileMode=false) silently drops +x, which breaks
# ./setup.sh for anyone who clones the repo. Check the mode git actually stores.
try:
    staged = subprocess.run(["git", "ls-files", "-s"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for line in staged.splitlines():
        mode, _, _, path = line.split(maxsplit=3)
        if (path.endswith(".sh") or path.startswith("tests/check_repo")) and mode != "100755":
            errors.append(f"{path}: not executable in git (fix: git update-index --chmod=+x {path})")
    print("[modes]     executable bits checked")
except (subprocess.CalledProcessError, FileNotFoundError):
    print("[modes]     not a git checkout, skipped")

if errors:
    print("\nFAILED:"); [print("  -", e) for e in errors]; sys.exit(1)
print("OK")
