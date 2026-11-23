-- Apply once to existing databases BEFORE deploying, or let the existing
-- AutoMigrate(UserSessionRow, UserDevice) add these nullable columns on startup.
-- Do not run init.sql against an existing database (it drops tables).
ALTER TABLE `tb_user_sessions` ADD COLUMN `location` text DEFAULT NULL;
ALTER TABLE `tb_user_devices` ADD COLUMN `last_location` text DEFAULT NULL;
