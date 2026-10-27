CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  auth_method TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  client_name TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_pending (
  handle TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_access (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_refresh (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_login_attempts (
  ip_hash TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_pending_exp ON oauth_pending(expires_at);
CREATE INDEX IF NOT EXISTS oauth_codes_exp ON oauth_codes(expires_at);
CREATE INDEX IF NOT EXISTS oauth_refresh_exp ON oauth_refresh(expires_at);
CREATE INDEX IF NOT EXISTS oauth_login_ip_time ON oauth_login_attempts(ip_hash, attempted_at);
