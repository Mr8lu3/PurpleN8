-- PurpleN8 database. Runs automatically the first time the postgres container starts.

-- One row per (source, rule) pair: when we last sent a notification for it.
-- Used for atomic dedupe (safe when several alerts arrive at the same moment).
CREATE TABLE dedupe_window (
    key        TEXT PRIMARY KEY,
    last_sent  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit trail: every alert n8n triaged and what it decided.
CREATE TABLE alert_log (
    id          BIGSERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    alert_id    TEXT,
    alert_time  TEXT,
    rule_id     TEXT,
    level       INT,
    description TEXT,
    agent       TEXT,
    srcip       TEXT,
    srcuser     TEXT,
    country     TEXT,
    isp         TEXT,
    mitre       JSONB,
    score       INT,
    severity    TEXT,
    reasons     JSONB,
    action      TEXT          -- notified | suppressed | logged
);
CREATE INDEX alert_log_srcip_idx ON alert_log (srcip);
CREATE INDEX alert_log_received_idx ON alert_log (received_at);

-- Response actions taken on alerts (append-only audit trail).
CREATE TABLE response_log (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    alert_id  TEXT,
    srcip     TEXT,
    action    TEXT,       -- blocked | unblocked | dismissed | no_response | block_failed | unblock_failed
    detail    TEXT
);
CREATE INDEX response_log_srcip_idx ON response_log (srcip);

-- ===== Pentest engagement assistant =====

-- Every engagement request, including rejected ones (scope-gate audit trail).
CREATE TABLE engagements (
    id             BIGSERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    name           TEXT,
    tester         TEXT,
    auth_ref       TEXT,
    targets        JSONB,
    starts_on      DATE,
    ends_on        DATE,
    status         TEXT,        -- accepted | rejected
    reject_reasons JSONB
);

-- Findings from the automated configuration review (and any added manually).
CREATE TABLE findings (
    id             BIGSERIAL PRIMARY KEY,
    engagement_id  BIGINT REFERENCES engagements(id),
    found_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    target         TEXT,
    title          TEXT,
    severity       TEXT,        -- info | low | medium | high (qualitative rubric, not CVSS)
    evidence       TEXT,
    recommendation TEXT,
    reference      TEXT,
    status         TEXT NOT NULL DEFAULT 'open'
);

-- Manual testing checklist created for each accepted engagement.
CREATE TABLE checklist (
    id             BIGSERIAL PRIMARY KEY,
    engagement_id  BIGINT REFERENCES engagements(id),
    category       TEXT,
    item           TEXT,
    status         TEXT NOT NULL DEFAULT 'todo',
    notes          TEXT
);
