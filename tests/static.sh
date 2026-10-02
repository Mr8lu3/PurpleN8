#!/usr/bin/env bash
# Static checks: script syntax, shellcheck (if installed), workflow integrity,
# secret scan and docker-compose validation. Used locally and by CI.
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPTS=$(git ls-files '*.sh' victim/entrypoint.sh 2>/dev/null || find . -name '*.sh' -not -path './.git/*')
SCRIPTS="$SCRIPTS soar/wazuh-integration/custom-n8n victim/purplen8-unblock"

echo "[syntax]    shell"; for f in $SCRIPTS; do bash -n "$f" 2>/dev/null || sh -n "$f"; done
echo "[syntax]    python"; python3 -m py_compile soar/wazuh-integration/custom-n8n.py enrich/app.py tests/check_repo.py
# custom-n8n is Wazuh's stock integration wrapper, vendored unchanged, so it is not linted.
LINT=${SCRIPTS/soar\/wazuh-integration\/custom-n8n/}
if command -v shellcheck >/dev/null; then
  echo "[shellcheck]"; shellcheck -S warning $LINT
else
  echo "[shellcheck] not installed, skipped (runs in CI)"
fi
python3 tests/check_repo.py
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  echo "[compose]   validating with placeholder secrets"
  POSTGRES_PASSWORD=ci docker compose --env-file .env.example --profile pentest config -q
fi
echo "static checks passed"
