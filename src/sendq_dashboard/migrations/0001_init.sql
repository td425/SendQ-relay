-- Initial schema for the SendQ dashboard database.

CREATE TABLE IF NOT EXISTS message_history (
  msg_id          TEXT PRIMARY KEY,
  sender          TEXT NOT NULL,
  sender_domain   TEXT NOT NULL,
  peer_ip         TEXT NOT NULL,
  size_bytes      INTEGER NOT NULL,
  status          TEXT NOT NULL CHECK (status IN
                    ('queued','delivering','deferred','delivered','failed')),
  received_at     TEXT NOT NULL,
  last_attempt_at TEXT,
  finalized_at    TEXT,
  last_error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_sender_domain ON message_history(sender_domain, received_at);
CREATE INDEX IF NOT EXISTS idx_msg_status        ON message_history(status, received_at);
CREATE INDEX IF NOT EXISTS idx_msg_received      ON message_history(received_at);

CREATE TABLE IF NOT EXISTS message_recipients (
  msg_id           TEXT NOT NULL REFERENCES message_history(msg_id) ON DELETE CASCADE,
  recipient        TEXT NOT NULL,
  recipient_domain TEXT NOT NULL,
  PRIMARY KEY (msg_id, recipient)
);
CREATE INDEX IF NOT EXISTS idx_rcpt_domain ON message_recipients(recipient_domain);

CREATE TABLE IF NOT EXISTS delivery_attempts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  msg_id      TEXT NOT NULL REFERENCES message_history(msg_id) ON DELETE CASCADE,
  attempt_at  TEXT NOT NULL,
  remote_host TEXT,
  smtp_code   INTEGER,
  smtp_resp   TEXT,
  outcome     TEXT NOT NULL CHECK (outcome IN ('success','deferred','failed'))
);
CREATE INDEX IF NOT EXISTS idx_att_msg ON delivery_attempts(msg_id, attempt_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  actor     TEXT NOT NULL,
  actor_ip  TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT,
  detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, ts);
