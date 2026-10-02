# PurpleN8 threat model

This is a STRIDE-style review of PurpleN8 itself: what an attacker (or a mistake) could do to the lab, which control handles it, how that control is tested, and what risk is left over.

**Scope:** the Docker stack on one machine (n8n, Wazuh manager, Postgres, enrich, victim, Juice Shop and its proxy), Telegram as the notification channel, and the operator who uses it.
**Out of scope:** compromise of the host OS or Docker itself, Telegram's own security, and the deliberately vulnerable Juice Shop application.

## Assets

| Asset | Why it matters |
|---|---|
| Alert pipeline integrity | Fake or altered alerts lead to wrong decisions, including blocks |
| Ability to block IPs | Can be abused to cut off legitimate users |
| Secrets in `.env` | Bot token, database, Wazuh API and webhook credentials |
| Audit trail (`alert_log`, `response_log`, `engagements`) | The evidence for incident review |
| Alert data (attacker IPs, usernames, log lines) | Should stay on the operator's machine |
| Lab isolation | Juice Shop is vulnerable by design and must not be reachable from the network |

## Entry points

| Entry point | Exposure |
|---|---|
| n8n webhook `/webhook/wazuh-alert` | `127.0.0.1` only, shared-secret header |
| Telegram Block/Ignore buttons | Signed n8n resume URLs pointing at `127.0.0.1` |
| Wazuh API (55000) | Internal Docker network only |
| n8n editor and engagement form | `127.0.0.1` only, local owner account |
| Juice Shop via logging proxy | `127.0.0.1:3000`, only with `--profile pentest` |

## Threats and controls

| STRIDE | Threat | Control | Verified by |
|---|---|---|---|
| **Spoofing** | Someone posts fake alerts to n8n | `X-PurpleN8-Token` header required; n8n bound to `127.0.0.1` | `tests/integration.sh`: no or bad token gets 403; port binding check |
| **Spoofing** | Someone forges a Block/Ignore answer | Buttons use n8n's HMAC-signed resume URLs and only resolve on the operator's PC | Manual: buttons tested from Telegram Desktop. Signature checking is n8n's built-in HMAC validation (reviewed in n8n's source, not separately tested here). |
| **Spoofing** | Default Wazuh credentials are used | `setup.sh` replaces the factory `wazuh:wazuh` admin password | Integration test: factory login gets 401 |
| **Tampering** | Log content injects markup into Telegram messages | All log-derived fields are HTML- or Markdown-escaped before sending | Unit test: `<script>` and Markdown characters are escaped |
| **Tampering** | Command injection through the block feature | Command allowlist and strict IPv4 check in the sub-workflow, checked **again** on the agent before iptables runs | Unit test (`1.2.3.4;id`, `256.1.1.1`, unknown commands rejected); live test of the agent script rejecting `1.2.3.4;id` |
| **Tampering** | Audit rows are edited or deleted | Postgres publishes no ports; only n8n holds credentials | Integration test: no published ports. *Residual: anyone with Docker access on the host can still edit rows.* |
| **Repudiation** | "Who approved that block?" | Every decision is written to `response_log` with a timestamp and outcome | Live tests of block, ignore, timeout and failure paths. *Residual: URL buttons carry no user identity; fine for a single-analyst lab, not for a team.* |
| **Information disclosure** | Attacker IPs are leaked to lookup services | Enrichment is fully offline (DB-IP Lite, Tor exit list); the service publishes no ports and doesn't log lookups | Code review: lookups are answered from local database files (`enrich/app.py`); integration test checks Tor and private-range results |
| **Information disclosure** | Secrets are committed to git | `.env` is git-ignored; CI scans for bot tokens, private keys and filled-in secret variables | `tests/check_repo.py` in CI |
| **Information disclosure** | Alert content is visible to Telegram | Accepted trade-off: Telegram is the one external service. Messages carry only the fields needed for a decision. | *Residual by design* |
| **Denial of service** | Alert floods overwhelm the analyst | Atomic dedupe in Postgres (one notification per source and rule per 10 minutes) | Integration test: 10 simultaneous identical alerts produce exactly 1 new |
| **Denial of service** | Spoofed source IPs trick the system into blocking legitimate users | Blocks need human approval, expire automatically (`BLOCK_MINUTES`) and default to *ignore* after 30 minutes | Live tests of all response paths |
| **Denial of service** | n8n is down when Wazuh sends alerts | *Residual: the integration does not retry, so alerts sent during an n8n restart are lost.* Seen during development in Wazuh's `integrations.log`. Alerts remain in Wazuh's own `alerts.json`. | Observed |
| **Denial of service** | Disk exhaustion | Wazuh vulnerability detection is disabled. It needs the indexer this lab doesn't run, and it had silently downloaded about 43 GB of CVE feeds. | Observed and fixed; the manager volume is now under 10 MB |
| **Elevation of privilege** | Stolen Wazuh API credentials are misused | The n8n API user's role allows **only** `active-response:command`; it cannot read agents, rules or users | Integration test: `GET /agents` returns 0 items for this user |
| **Elevation of privilege** | A workflow reads or writes arbitrary files | `N8N_RESTRICT_FILE_ACCESS_TO=/files/pentest/reports` | Configuration |
| **Elevation of privilege** | The vulnerable lab target is reached from the network | Juice Shop has no published port; its proxy is bound to `127.0.0.1` and only runs with `--profile pentest` | Configuration; integration test checks port exposure for the core services |
| **Elevation of privilege** | Pentest tooling is pointed at systems without permission | Scope gate: hostname allowlist, authorisation reference, confirmation and date window; rejected requests are recorded | Unit tests (6 cases) and an integration test |

## Residual risks, summarised

1. **Anyone with control of the host or Docker controls everything.** That's normal for a single-machine lab. A real deployment would separate the database and use host hardening.
2. **No retry queue between Wazuh and n8n.** Alerts sent while n8n is restarting are dropped. A fix would be a small spool on the manager, or n8n queue mode.
3. **No analyst identity on decisions.** URL buttons cannot say who tapped them. A team setup would need authenticated approvals.
4. **TLS verification is off on the internal n8n to Wazuh API connection** (Wazuh's self-signed certificate). The traffic never leaves the Docker network.
5. **Telegram sees alert content.** This was a deliberate choice; swapping in a self-hosted channel would remove it.

## Lessons from building it

- **Workflow memory is not a database.** The first dedupe used n8n's static data. Under concurrent alerts it let duplicates through and only saved state on successful runs. Moving it to a single atomic `INSERT ... ON CONFLICT` in Postgres fixed both problems, and an integration test now guards it.
- **"Healthy" is not "ready".** n8n reports healthy before its webhooks are registered. Setup and tests now wait for the webhook to answer 403 rather than trusting the health check.
- **Defaults can be dangerous.** Two factory defaults would have hurt a "security-first" lab: the Wazuh API `wazuh:wazuh` login, and a vulnerability module that filled the disk.
- **Test against the real tool, not your assumptions.** A hand-written sample alert claimed the wrong Wazuh rule. Replaying its log line through `wazuh-logtest` showed what Wazuh really does, and the sample was corrected.
