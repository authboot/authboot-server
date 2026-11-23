-- MySQL 8.0; apply once before deploying batch 3. No data deletion is performed.
-- Take a backup and stop old application writers during the cutover.
ALTER TABLE tb_admin_users
  ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN mfa_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE tb_users ADD COLUMN session_version bigint NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS tb_admin_mfa (
  account_id bigint NOT NULL PRIMARY KEY,
  secret text NOT NULL,
  enabled boolean NOT NULL DEFAULT false,
  last_counter bigint NOT NULL DEFAULT -1,
  setup_expires_at bigint NOT NULL DEFAULT 0,
  generation bigint NOT NULL DEFAULT 0
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS tb_admin_mfa_recovery (
  account_id bigint NOT NULL,
  hash varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIMARY KEY(account_id, hash)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS tb_admin_mfa_challenges (
  hash varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  account_id bigint NOT NULL,
  generation bigint NOT NULL,
  device_id varchar(255),
  device_name varchar(255),
  ip varchar(64),
  user_agent text,
  password_hash varchar(255),
  expires_at bigint NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  INDEX idx_admin_mfa_challenges_expires_at(expires_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS tb_security_grants (
  hash varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  subject varchar(8) NOT NULL,
  account_id bigint NOT NULL,
  organization_id bigint NOT NULL,
  session_id varchar(64) NOT NULL,
  scope varchar(128) NOT NULL,
  expires_at bigint NOT NULL,
  INDEX idx_security_grants_expires_at(expires_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS tb_revocation_outbox (
  id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
  subject varchar(8) NOT NULL,
  account_id bigint NOT NULL,
  organization_id bigint NOT NULL DEFAULT 0,
  before_version bigint NOT NULL,
  created_at bigint NOT NULL,
  next_attempt_at bigint NOT NULL DEFAULT 0,
  lease_until bigint NOT NULL DEFAULT 0,
  lease_token varchar(64) NOT NULL DEFAULT '',
  attempts int NOT NULL DEFAULT 0,
  completed_at bigint NOT NULL DEFAULT 0,
  INDEX idx_revoke_due(completed_at,next_attempt_at)
) ENGINE=InnoDB;
CREATE INDEX idx_batch3_event_retention ON tb_user_security_events(resolved_at);
CREATE INDEX idx_batch3_admin_login_retention ON tb_admin_login_logs(created_at);
