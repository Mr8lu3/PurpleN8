import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { nodeCode, run, one } from './harness.mjs';

const WF = new URL('../../soar/workflows/wazuh-alert-triage.json', import.meta.url).pathname;
const AR = new URL('../../soar/workflows/wazuh-active-response.json', import.meta.url).pathname;
const sample = (name) => JSON.parse(readFileSync(new URL(`../../soar/samples/${name}`, import.meta.url)));
const normalise = (alert) => one(run(nodeCode(WF, 'Normalise Alert'), { json: { body: alert } }));

test('Normalise: source IP is found for each log type', () => {
  assert.equal(normalise(sample('01-ssh-bruteforce.json')).srcip, '185.220.101.45');
  assert.equal(normalise(sample('03-windows-logon-failure.json')).srcip, '81.2.69.142');   // Windows eventdata
  assert.equal(normalise(sample('04-file-integrity-change.json')).srcip, null);             // FIM has no IP
});

test('Normalise: private ranges are not treated as public', () => {
  const pub = (ip) => normalise({ rule: { level: 5 }, data: { srcip: ip } }).publicIp;
  for (const ip of ['10.1.2.3', '192.168.0.1', '172.16.0.1', '172.31.255.255', '127.0.0.1', '169.254.1.1']) assert.equal(pub(ip), false, ip);
  for (const ip of ['172.32.0.1', '8.8.8.8', '185.220.101.45']) assert.equal(pub(ip), true, ip);
});

test('Normalise: dry-run flag only when explicitly true', () => {
  assert.equal(normalise({ ...sample('01-ssh-bruteforce.json'), purplen8_dry_run: true }).dryRun, true);
  assert.equal(normalise({ ...sample('01-ssh-bruteforce.json'), purplen8_dry_run: 'yes' }).dryRun, false);
});

const score = (alert, geo) => one(run(nodeCode(WF, 'Score Alert'), {
  json: geo ? { status: 'success', ...geo } : {},
  nodes: { 'Normalise Alert': normalise(alert) },
  env: { HOME_COUNTRIES: 'United Kingdom' },
}));

test('Score: SSH brute force from a Tor exit is high (80)', () => {
  const r = score(sample('01-ssh-bruteforce.json'), { country: 'Germany', isp: 'Tor host', tor: true, hosting: false });
  assert.equal(r.score, 80); assert.equal(r.severity, 'high');
  assert.ok(r.reasons.includes('Tor exit node'));
});

test('Score: web attack from a US hosting provider is medium (59)', () => {
  const r = score(sample('02-web-sqli.json'), { country: 'United States', isp: 'Censys, Inc.', tor: false, hosting: true });
  assert.equal(r.score, 59); assert.equal(r.severity, 'medium');
});

test('Score: UK home IP logon failure is low (20)', () => {
  const r = score(sample('03-windows-logon-failure.json'), { country: 'United Kingdom', isp: 'AAISP', tor: false, hosting: false });
  assert.equal(r.score, 20); assert.equal(r.severity, 'low');
});

test('Score: capped at 100', () => {
  const r = score({ ...sample('02-web-sqli.json'), rule: { ...sample('02-web-sqli.json').rule, level: 15 } },
                  { country: 'Russia', isp: 'x', tor: true, hosting: true });
  assert.equal(r.score, 100);
});

test('Score: log text is escaped for Telegram HTML and Markdown', () => {
  const evil = { ...sample('01-ssh-bruteforce.json'), full_log: '<script>alert(1)</script> & co',
                 data: { srcip: '185.220.101.45', srcuser: 'evil_user*' } };
  const r = score(evil, { country: 'Germany', isp: 'x', tor: true, hosting: false });
  assert.ok(!r.safe.log.includes('<script>'));
  assert.ok(r.safe.log.includes('&lt;script&gt;'));
  assert.equal(r.md.user, 'evil\\_user\\*');
});

const decide = (scored, isNew) => one(run(nodeCode(WF, 'Decide Action'), { json: { is_new: isNew }, nodes: { 'Score Alert': scored } }));

test('Decide: duplicate -> suppressed, low -> logged, otherwise notified', () => {
  assert.equal(decide({ severity: 'high' }, false).action, 'suppressed');
  assert.equal(decide({ severity: 'low' }, true).action, 'logged');
  assert.equal(decide({ severity: 'medium' }, true).action, 'notified');
  assert.equal(decide({ severity: 'high', dryRun: true }, true).action, 'dry_run(notified)');
});

const validate = (command, srcip) => run(nodeCode(AR, 'Validate Input'), { json: { command, srcip } });

test('Active response: only allowlisted commands and valid IPv4 pass', () => {
  assert.doesNotThrow(() => validate('!firewall-drop', '185.220.101.45'));
  assert.doesNotThrow(() => validate('!purplen8-unblock', '203.0.113.5'));
  assert.throws(() => validate('!restart-wazuh', '185.220.101.45'), /not allowed/);
  assert.throws(() => validate('!firewall-drop', '1.2.3.4;id'), /Invalid IPv4/);
  assert.throws(() => validate('!firewall-drop', '256.1.1.1'), /Invalid IPv4/);
  assert.throws(() => validate('!firewall-drop', undefined), /Invalid IPv4/);
});
