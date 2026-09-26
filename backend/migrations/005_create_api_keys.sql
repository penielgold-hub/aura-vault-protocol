BEGIN;

CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY,
  owner TEXT NOT NULL CHECK (length(owner) > 0),
  key_hash TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('read', 'write', 'admin')),
  expires_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_owner_created
  ON api_keys (owner, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_active_expiry
  ON api_keys (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  api_key_id UUID NULL REFERENCES api_keys(id) ON DELETE SET NULL,
  owner TEXT NULL,
  event TEXT NOT NULL,
  request_method TEXT NULL,
  request_path TEXT NULL,
  status_code INTEGER NULL CHECK (status_code BETWEEN 100 AND 599),
  result TEXT NOT NULL,
  ip_address TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_api_key_created
  ON audit_logs (api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_owner_created
  ON audit_logs (owner, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_created
  ON audit_logs (event, created_at DESC);

COMMIT;
