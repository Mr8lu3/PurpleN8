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
