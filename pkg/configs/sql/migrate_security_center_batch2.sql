-- Apply once to an existing database, or use startup AutoMigrate instead.
-- Requires batch1's user login location columns. Never run init.sql on live data.
ALTER TABLE tb_user_devices
  ADD COLUMN last_active_at bigint NOT NULL DEFAULT 0,
  ADD COLUMN last_active_ip varchar(64) DEFAULT NULL,
  ADD COLUMN last_active_location text DEFAULT NULL;
ALTER TABLE tb_user_sessions
  ADD COLUMN last_active_ip varchar(64) DEFAULT NULL,
  ADD COLUMN last_active_location text DEFAULT NULL;

CREATE TABLE IF NOT EXISTS tb_user_security_events (
  id varchar(64) NOT NULL,
  organization_id bigint NOT NULL,
  user_id bigint NOT NULL,
  session_id varchar(64) DEFAULT NULL,
  device_id varchar(64) DEFAULT NULL,
  kind varchar(64) DEFAULT NULL,
  ip varchar(64) DEFAULT NULL,
  location text DEFAULT NULL,
  status varchar(32) DEFAULT NULL,
  created_at bigint DEFAULT NULL,
  resolved_at bigint DEFAULT NULL,
  notify_status varchar(32) DEFAULT NULL,
  notify_attempts bigint NOT NULL DEFAULT 0,
  notify_after bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY idx_tb_user_security_events_session_id (session_id),
  KEY idx_security_owner (organization_id, user_id),
  KEY idx_tb_user_security_events_notify_status (notify_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
