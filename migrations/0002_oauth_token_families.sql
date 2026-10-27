-- Add refresh-token replay detection and DCR rate limiting without rewriting
-- the initial schema migration. Existing access tokens expire naturally.
ALTER TABLE oauth_access ADD COLUMN family_id TEXT;
ALTER TABLE oauth_refresh ADD COLUMN family_id TEXT;
UPDATE oauth_refresh SET family_id = lower(hex(randomblob(16))) WHERE family_id IS NULL;

CREATE TABLE IF NOT EXISTS oauth_refresh_replays (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumer_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_dcr_limits (
  ip_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (ip_hash, window_start)
);

CREATE INDEX IF NOT EXISTS oauth_refresh_family ON oauth_refresh(family_id);
CREATE INDEX IF NOT EXISTS oauth_access_family ON oauth_access(family_id);
CREATE INDEX IF NOT EXISTS oauth_replays_exp ON oauth_refresh_replays(expires_at);
CREATE INDEX IF NOT EXISTS oauth_dcr_window ON oauth_dcr_limits(window_start);

