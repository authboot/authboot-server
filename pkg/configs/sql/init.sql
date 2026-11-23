-- =====================================================================
-- authboot-server 初始化 SQL
--
-- 结构：先 DROP / CREATE 所有表（§1），最后统一 INSERT 种子数据（§2）。
-- 说明：常规业务表（tb_organization / tb_users 等）由 GORM AutoMigrate
--       在启动时自动建表/加列，本文件用于全新环境手工初始化与本地联调。
-- =====================================================================

SET NAMES utf8mb4;
SET TIME_ZONE = '+00:00';
SET FOREIGN_KEY_CHECKS = 0;

-- =====================================================================
-- §1 表结构（DROP + CREATE）
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1.1 平台管理员账号（单 admin 体系：种子数据即唯一账号）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_admin_users`;
CREATE TABLE `tb_admin_users` (
  `id`               bigint       NOT NULL AUTO_INCREMENT,
  `email`            varchar(255) DEFAULT NULL,
  `user_name`        longtext,
  `password`         longtext,             -- bcrypt hash
  `avatar`           longtext,
  `background_image` longtext,
  `signature`        longtext,
  `status`           tinyint      NOT NULL DEFAULT '1',
  `settings`         json         DEFAULT NULL,
  `created_at`       datetime(3)  DEFAULT NULL,
  `updated_at`       datetime(3)  DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_tb_admin_users_email` (`email`),
  KEY `idx_tb_admin_users_status` (`status`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.2 组织（settings: 组织级配置 JSON，见 biz/dal/db/organization_settings.go）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_organization`;
CREATE TABLE `tb_organization` (
  `id`            bigint       NOT NULL AUTO_INCREMENT,
  `name`          varchar(128) NOT NULL,
  `code`          varchar(64)  NOT NULL,
  `logo`          varchar(512) DEFAULT NULL,    -- 当前 logo，"bucket/key" 相对路径
  `previous_logo` varchar(512) DEFAULT NULL,    -- 最近一次被替换的旧 logo
  `settings`      json         DEFAULT NULL,    -- 组织设置（admin token 时长 / 登录方式开关）
  `status`        tinyint      NOT NULL DEFAULT '1',
  `created_at`    datetime(3)  NOT NULL,
  `updated_at`    datetime(3)  NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_tb_organization_code` (`code`),
  KEY `idx_tb_organization_status` (`status`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.3 组织成员关系（account ↔ organization 纯绑定，无角色）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_organization_membership`;
CREATE TABLE `tb_organization_membership` (
  `id`             bigint      NOT NULL AUTO_INCREMENT,
  `organization_id` bigint     NOT NULL,
  `account_id`     bigint      NOT NULL,
  `role`           varchar(16) NOT NULL DEFAULT 'member',
  `status`         tinyint     NOT NULL DEFAULT '1',
  `created_at`     datetime(3) NOT NULL,
  `updated_at`     datetime(3) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_org_account` (`organization_id`, `account_id`),
  KEY `idx_membership_org_status` (`organization_id`, `status`),
  KEY `idx_tb_organization_membership_status` (`status`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.4 组织邀请（凭 token 接受；无角色字段）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_organization_invitation`;
CREATE TABLE `tb_organization_invitation` (
  `id`                 bigint       NOT NULL AUTO_INCREMENT,
  `organization_id`    bigint       NOT NULL,
  `email`              varchar(255) NOT NULL,
  `inviter_account_id` bigint       DEFAULT NULL,
  `token`              varchar(64)  NOT NULL,
  `status`             tinyint      NOT NULL DEFAULT '1',
  `expired_at`         bigint       NOT NULL,
  `accepted_account_id` bigint      NOT NULL DEFAULT '0',
  `created_at`         bigint       NOT NULL,
  `updated_at`         bigint       NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_tb_organization_invitation_token` (`token`),
  KEY `idx_tb_organization_invitation_organization_id` (`organization_id`),
  KEY `idx_tb_organization_invitation_email` (`email`),
  KEY `idx_tb_organization_invitation_status` (`status`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.5 OAuth 提供商配置（每组织 × 每提供商一行，config 为 AES-GCM 加密 JSON）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_oauth_configs`;
CREATE TABLE `tb_oauth_configs` (
  `id`              bigint        NOT NULL AUTO_INCREMENT,
  `organization_id` bigint        NOT NULL,
  `provider`        varchar(32)   NOT NULL,
  `config`          varbinary(2048) NOT NULL,
  `enabled`         tinyint       NOT NULL DEFAULT '1',
  `created_at`      datetime(3)   NOT NULL,
  `updated_at`      datetime(3)   NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_org_provider` (`organization_id`, `provider`),
  KEY `idx_tb_oauth_configs_enabled` (`enabled`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.6 应用客户端（登录入口：ios / android / h5 / mini_program）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_app_clients`;
CREATE TABLE `tb_app_clients` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint       NOT NULL,
  `name`            varchar(128) NOT NULL,
  `client_type`     int          NOT NULL DEFAULT '0',
  `status`          tinyint      NOT NULL DEFAULT '1',
  `created_at`      bigint       DEFAULT NULL,
  `updated_at`      bigint       DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_tb_app_clients_organization_id` (`organization_id`),
  KEY `idx_tb_app_clients_status` (`status`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.7 组织普通用户（App 业务用户，绑定单个组织）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_users`;
CREATE TABLE `tb_users` (
  `id`               bigint       NOT NULL AUTO_INCREMENT,
  `organization_id`  bigint       DEFAULT NULL,
  `user_name`        longtext,
  `password`         longtext,             -- bcrypt hash，OAuth/验证码注册的账号可为空
  `avatar`           longtext,
  `background_image` longtext,
  `signature`        longtext,
  `settings`         json         DEFAULT NULL,
  `gender`           tinyint      NOT NULL DEFAULT '0',   -- 0 未知 / 1 男 / 2 女 / 3 其他
  `birthday`         varchar(32)  DEFAULT NULL,
  `bio`              varchar(512) DEFAULT NULL,
  `status`           tinyint      NOT NULL DEFAULT '1',
  `created_at`       bigint       DEFAULT NULL,           -- unix 秒
  `updated_at`       bigint       DEFAULT NULL,           -- unix 秒
  PRIMARY KEY (`id`),
  KEY `idx_tb_users_organization_id` (`organization_id`),
  KEY `idx_users_org_created` (`organization_id`, `created_at`),
  KEY `idx_users_org_status` (`organization_id`, `status`),
  KEY `idx_tb_users_status` (`status`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.8 用户登录身份（email / phone / username / wechat_openid / google / apple）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_user_identities`;
CREATE TABLE `tb_user_identities` (
  `id`             bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint      NOT NULL,
  `user_id`        bigint       NOT NULL,
  `identity_type`  varchar(32)  NOT NULL,
  `identity_value` varchar(255) NOT NULL,
  `created_at`     bigint       DEFAULT NULL,
  `updated_at`     bigint       DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_org_type_value` (`organization_id`, `identity_type`, `identity_value`),
  KEY `idx_tb_user_identities_user_id` (`user_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.9 用户地址
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_user_addresses`;
CREATE TABLE `tb_user_addresses` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint       NOT NULL,
  `user_id`         bigint       NOT NULL,
  `receiver_name`   varchar(64)  DEFAULT NULL,
  `receiver_phone`  varchar(32)  DEFAULT NULL,
  `province`        varchar(64)  DEFAULT NULL,
  `city`            varchar(64)  DEFAULT NULL,
  `district`        varchar(64)  DEFAULT NULL,
  `detail`          varchar(255) DEFAULT NULL,
  `is_default`      tinyint(1)   NOT NULL DEFAULT '0',
  `created_at`      datetime(3)  NOT NULL,
  `updated_at`      datetime(3)  NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_tb_user_addresses_organization_id` (`organization_id`),
  KEY `idx_tb_user_addresses_user_id` (`user_id`),
  KEY `idx_tb_user_addresses_is_default` (`is_default`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.10 站内通知
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_notification`;
CREATE TABLE `tb_notification` (
  `id`         bigint       NOT NULL AUTO_INCREMENT,
  `user_id`    bigint       NOT NULL,
  `type`       tinyint      NOT NULL DEFAULT '0',
  `level`      tinyint      NOT NULL DEFAULT '0',
  `title`      varchar(255) NOT NULL,
  `content`    text,
  `url`        varchar(512) DEFAULT NULL,
  `status`     tinyint      NOT NULL DEFAULT '1',
  `data`       text,
  `created_at` bigint       NOT NULL,               -- unix 秒
  `read_at`    bigint       NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_user_status` (`user_id`, `status`),
  KEY `idx_tb_notification_created_at` (`created_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.11 用户登录日志（identity_value 脱敏存储）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_user_login_logs`;
CREATE TABLE `tb_user_login_logs` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint       NOT NULL,
  `user_id`         bigint       NOT NULL DEFAULT '0',
  `identity_type`   varchar(32)  DEFAULT NULL,
  `identity_value`  varchar(255) DEFAULT NULL,
  `client_id`       bigint       DEFAULT NULL,
  `device_id`       varchar(64)  DEFAULT NULL,
  `device_name`     varchar(128) DEFAULT NULL,
  `ip`              varchar(64)  DEFAULT NULL,
  `user_agent`      varchar(255) DEFAULT NULL,
  `success`         tinyint(1)   NOT NULL DEFAULT '0',
  `err_msg`         varchar(255) DEFAULT NULL,
  `created_at`      bigint       DEFAULT NULL,        -- unix 秒
  PRIMARY KEY (`id`),
  KEY `idx_tb_user_login_logs_organization_id` (`organization_id`),
  KEY `idx_login_org_created` (`organization_id`, `created_at`, `success`, `user_id`),
  KEY `idx_tb_user_login_logs_user_id` (`user_id`),
  KEY `idx_tb_user_login_logs_success` (`success`),
  KEY `idx_tb_user_login_logs_created_at` (`created_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.12 管理端审计日志（before / after / extra 为 JSON 快照）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_admin_audit_logs`;
CREATE TABLE `tb_admin_audit_logs` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `request_id`      varchar(64)  DEFAULT NULL,
  `trace_id`       varchar(64)  DEFAULT NULL,
  `admin_id`        bigint       DEFAULT NULL,
  `organization_id` bigint       DEFAULT NULL,
  `session_id`      varchar(64)  DEFAULT NULL,
  `action`          varchar(64)  DEFAULT NULL,
  `resource_type`   varchar(64)  DEFAULT NULL,
  `resource_id`     varchar(128) DEFAULT NULL,
  `method`          varchar(8)   DEFAULT NULL,
  `path`            varchar(255) DEFAULT NULL,
  `ip`              varchar(64)  DEFAULT NULL,
  `user_agent`      varchar(255) DEFAULT NULL,
  `success`         tinyint(1)   DEFAULT NULL,
  `status_code`     int          DEFAULT NULL,
  `err_msg`         varchar(512) DEFAULT NULL,
  `before`          json         DEFAULT NULL,
  `after`           json         DEFAULT NULL,
  `extra`           json         DEFAULT NULL,
  `latency_ms`      bigint       DEFAULT NULL,
  `created_at`      datetime(3)  NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_tb_admin_audit_logs_request_id` (`request_id`),
  KEY `idx_tb_admin_audit_logs_trace_id` (`trace_id`),
  KEY `idx_tb_admin_audit_logs_admin_id` (`admin_id`),
  KEY `idx_tb_admin_audit_logs_organization_id` (`organization_id`),
  KEY `idx_tb_admin_audit_logs_session_id` (`session_id`),
  KEY `idx_tb_admin_audit_logs_action` (`action`),
  KEY `idx_tb_admin_audit_logs_resource_id` (`resource_id`),
  KEY `idx_tb_admin_audit_logs_success` (`success`),
  KEY `idx_tb_admin_audit_logs_created_at` (`created_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.13 管理员登录日志（与 tb_user_login_logs 对称）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_admin_login_logs`;
CREATE TABLE `tb_admin_login_logs` (
  `id`          bigint       NOT NULL AUTO_INCREMENT,
  `admin_id`    bigint       NOT NULL DEFAULT '0',  -- 0 = 账号未找到（登录前即失败）
  `email`       varchar(255) DEFAULT NULL,
  `device_id`   varchar(64)  DEFAULT NULL,
  `device_name` varchar(128) DEFAULT NULL,
  `ip`          varchar(64)  DEFAULT NULL,
  `user_agent`  varchar(255) DEFAULT NULL,
  `success`     tinyint(1)   NOT NULL DEFAULT '0',
  `err_msg`     varchar(255) DEFAULT NULL,
  `created_at`  bigint       NOT NULL,              -- unix 秒
  PRIMARY KEY (`id`),
  KEY `idx_admin_login_admin` (`admin_id`, `created_at`),
  KEY `idx_admin_login_created` (`success`, `created_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.14 用户审计日志（App 用户敏感操作：改密/重置/绑定/合并/注销）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_user_audit_logs`;
CREATE TABLE `tb_user_audit_logs` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint       NOT NULL,
  `user_id`         bigint       NOT NULL DEFAULT '0',
  `action`          varchar(64)  DEFAULT NULL,
  `resource_type`   varchar(64)  DEFAULT NULL,
  `resource_id`     varchar(128) DEFAULT NULL,
  `ip`              varchar(64)  DEFAULT NULL,
  `user_agent`      varchar(255) DEFAULT NULL,
  `success`         tinyint(1)   NOT NULL DEFAULT '0',
  `err_msg`         varchar(512) DEFAULT NULL,
  `detail`          json         DEFAULT NULL,     -- 已脱敏的 JSON 快照
  `created_at`      bigint       NOT NULL,         -- unix 秒
  PRIMARY KEY (`id`),
  KEY `idx_user_audit_org_created` (`organization_id`, `created_at`),
  KEY `idx_user_audit_user` (`user_id`, `created_at`),
  KEY `idx_tb_user_audit_logs_action` (`action`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.15 管理员会话持久化（热路径在 Redis，此处为审计/巡检记录）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_admin_sessions`;
CREATE TABLE `tb_admin_sessions` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `session_id`      varchar(64)  NOT NULL,
  `account_id`      bigint       NOT NULL,
  `organization_id` bigint       NOT NULL DEFAULT '0', -- 0 = 未绑定组织（平台级令牌）
  `device_id`       varchar(64)  DEFAULT NULL,
  `device_name`     varchar(128) DEFAULT NULL,
  `ip`              varchar(64)  DEFAULT NULL,
  `user_agent`      varchar(255) DEFAULT NULL,
  `status`          tinyint      NOT NULL DEFAULT '1', -- 1 active / 2 revoked
  `created_at`      bigint       NOT NULL,
  `expires_at`      bigint       NOT NULL,
  `last_active_at`  bigint       NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_admin_session_sid` (`session_id`),
  KEY `idx_admin_session_account` (`account_id`, `expires_at`),
  KEY `idx_tb_admin_sessions_status` (`status`),
  KEY `idx_tb_admin_sessions_expires_at` (`expires_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.16 用户会话持久化（与 tb_admin_sessions 对称，组织内绑定）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_user_sessions`;
CREATE TABLE `tb_user_sessions` (
  `last_active_ip` varchar(64) DEFAULT NULL,
  `last_active_location` text DEFAULT NULL,
  `location`        text DEFAULT NULL,
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `session_id`      varchar(64)  NOT NULL,
  `organization_id` bigint       NOT NULL,
  `user_id`         bigint       NOT NULL,
  `client_id`       bigint       DEFAULT NULL,
  `device_id`       varchar(64)  DEFAULT NULL,
  `device_name`     varchar(128) DEFAULT NULL,
  `ip`              varchar(64)  DEFAULT NULL,
  `user_agent`      varchar(255) DEFAULT NULL,
  `status`          tinyint      NOT NULL DEFAULT '1',
  `created_at`      bigint       NOT NULL,
  `expires_at`      bigint       NOT NULL,
  `last_active_at`  bigint       NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_session_sid` (`session_id`),
  KEY `idx_user_session_user` (`user_id`, `expires_at`),
  KEY `idx_tb_user_sessions_organization_id` (`organization_id`),
  KEY `idx_tb_user_sessions_status` (`status`),
  KEY `idx_tb_user_sessions_expires_at` (`expires_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.17 管理员设备登记（每 admin × device 一行，登录时 upsert）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_admin_devices`;
CREATE TABLE `tb_admin_devices` (
  `id`           bigint       NOT NULL AUTO_INCREMENT,
  `account_id`   bigint       NOT NULL,
  `device_id`    varchar(64)  NOT NULL,
  `device_name`  varchar(128) DEFAULT NULL,
  `last_ip`      varchar(64)  DEFAULT NULL,
  `user_agent`   varchar(255) DEFAULT NULL,
  `login_count`  bigint       NOT NULL DEFAULT '1',
  `created_at`   bigint       NOT NULL,
  `last_used_at` bigint       NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_admin_device` (`account_id`, `device_id`),
  KEY `idx_tb_admin_devices_last_used_at` (`last_used_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.18 用户设备登记（与 tb_admin_devices 对称，组织内绑定）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_user_devices`;
CREATE TABLE `tb_user_devices` (
  `last_active_at` bigint NOT NULL DEFAULT 0,
  `last_active_ip` varchar(64) DEFAULT NULL,
  `last_active_location` text DEFAULT NULL,
  `last_location`   text DEFAULT NULL,
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint       NOT NULL,
  `user_id`         bigint       NOT NULL,
  `device_id`       varchar(64)  NOT NULL,
  `device_name`     varchar(128) DEFAULT NULL,
  `client_id`       bigint       DEFAULT NULL,
  `last_ip`         varchar(64)  DEFAULT NULL,
  `user_agent`      varchar(255) DEFAULT NULL,
  `login_count`     bigint       NOT NULL DEFAULT '1',
  `created_at`      bigint       NOT NULL,
  `last_used_at`    bigint       NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_device` (`user_id`, `device_id`),
  KEY `idx_tb_user_devices_organization_id` (`organization_id`),
  KEY `idx_tb_user_devices_last_used_at` (`last_used_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 1.19 组织法律文档版本（用户协议 / 隐私政策，追加式不可变版本历史）
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS `tb_organization_legal_doc_versions`;
CREATE TABLE `tb_organization_legal_doc_versions` (
  `id`              bigint       NOT NULL AUTO_INCREMENT,
  `organization_id` bigint       NOT NULL,
  `doc_type`        varchar(32)  NOT NULL,   -- user_agreement / privacy_policy
  `version`         bigint       NOT NULL,   -- 每 (org, doc_type) 单调递增，发布时由服务端分配
  `url`             varchar(512) NOT NULL,   -- 对外展示的文档链接
  `changelog`       varchar(512) DEFAULT NULL, -- 变更摘要（版本历史展示）
  `status`          varchar(16)  NOT NULL,   -- active / scheduled / retired
  `effective_at`    bigint       NOT NULL,   -- 生效时间（unix 秒）
  `published_by`    varchar(255) DEFAULT NULL,
  `published_at`    bigint       NOT NULL,
  `content_hash`    varchar(64)  DEFAULT NULL, -- 归档快照 SHA-256 前 16 hex
  `has_snapshot`    tinyint(1)   NOT NULL DEFAULT '0',
  `content`         mediumtext,              -- 归档快照原文（未归档为空）
  `created_at`      bigint       NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_org_doc_ver` (`organization_id`, `doc_type`, `version`),
  KEY `idx_tb_organization_legal_doc_versions_org_doc` (`organization_id`, `doc_type`, `effective_at`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- =====================================================================
-- App user security events: separate from admin notifications.
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

-- §2 种子数据（表结构全部创建完成后统一初始化）
-- =====================================================================

-- 唯一的平台管理员账号（密码 bcrypt，登录后请立即修改）
INSERT INTO `tb_admin_users`
  (`id`, `email`, `user_name`, `password`, `avatar`, `background_image`, `signature`, `status`, `settings`, `created_at`, `updated_at`)
VALUES
  (1, 'test@test.com', 'self my', '$2a$05$ZBhGv2sg8Fe6R0.ak2dwsOm4XdLaAQJAQqqXzVx31OP1iyKJnHvUy', '', '', '', 1, NULL, '2026-11-06 17:24:48.698', NULL);

-- 演示组织
INSERT INTO `tb_organization`
  (`id`, `name`, `code`, `logo`, `previous_logo`, `settings`, `status`, `created_at`, `updated_at`)
VALUES
  (1, 'team01', 'team01', '', NULL, NULL, 1, '2026-11-06 17:09:03.113', '2026-11-06 17:09:03.113'),
  (2, 'team02', 'team02', '', NULL, NULL, 1, '2026-11-06 17:55:26.944', '2026-11-06 17:55:26.944');

-- 演示用户
INSERT INTO `tb_users`
  (`id`, `organization_id`, `user_name`, `password`, `avatar`, `background_image`, `signature`, `settings`, `gender`, `birthday`, `bio`, `status`, `created_at`, `updated_at`)
VALUES
  (1, 1, 'user01', '', '', '', '', NULL, 0, '', '', 1, 1793962423, 1793962423),
  (2, 1, 'user02', NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 1, 1793962423, 1793962423);

-- 演示用户登录身份
INSERT INTO `tb_user_identities`
  (`id`, `organization_id`, `user_id`, `identity_type`, `identity_value`, `created_at`, `updated_at`)
VALUES
  (1, 1, 1, 'email', 'icvhub@gmail.com', 1793962423, 1793962423),
  (2, 1, 2, 'email', '545498529@qq.com', 1793962423, 1793962423);

-- 历史审计日志（可选；全新环境可整段删除）
INSERT INTO `tb_admin_audit_logs`
  (`id`, `request_id`, `trace_id`, `admin_id`, `organization_id`, `session_id`, `action`, `resource_type`, `resource_id`, `method`, `path`, `ip`, `user_agent`, `success`, `status_code`, `err_msg`, `before`, `after`, `extra`, `latency_ms`, `created_at`)
VALUES
  (1, '1f56828b-5b0b-4ced-a6a7-14f7887cf08e', '', 0, 0, '', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 0, 0, 'account not found', NULL, NULL, '{"email": "test@test.com"}', 0, '2026-11-06 14:58:51.462'),
  (2, '792271fa-0fd2-45e9-ac44-dc9f9a285599', '', 1, 0, '', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 0, 0, 'password mismatch', NULL, NULL, '{"email": "test@test.com"}', 0, '2026-11-06 15:38:23.143'),
  (3, 'b7f1dc62-02f7-4564-9e9c-e34947e18c59', '', 1, 0, '99f763fc-9f81-49b2-bb79-4d19fb93c953', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 15:38:59.143'),
  (4, 'e870c25d-3984-408c-9173-6ecfcfb4cf86', '', 1, 0, '', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 0, 0, 'password mismatch', NULL, NULL, '{"email": "test@test.com"}', 0, '2026-11-06 15:39:55.142'),
  (5, 'f27951e6-9df7-4796-8814-532e821280ae', '', 1, 0, '2f5bd93b-862e-4292-bb79-41005f856eb8', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 15:40:31.170'),
  (6, 'e2db49ed-2cc2-4a78-a1d9-25048d29fcca', '', 1, 0, '15e60e5a-ee9f-44b0-b467-167fd2f66436', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 15:42:21.172'),
  (7, 'e9124d02-a9c6-4388-88b1-e96130126510', '', 1, 0, '', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 0, 0, 'password mismatch', NULL, NULL, '{"email": "test@test.com"}', 0, '2026-11-06 15:49:45.170'),
  (8, '868ef67e-8cd1-4dbd-81e3-8b8f9d01cd12', '', 1, 0, 'aafb047c-f984-4661-8816-7fecc5f59e80', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 15:49:53.171'),
  (9, '0eac0c48-a91c-471a-b3e1-894c596d60cf', '', 1, 0, 'aafb047c-f984-4661-8816-7fecc5f59e80', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 0, 0, '', NULL, NULL, NULL, 10, '2026-11-06 15:50:31.170'),
  (10, 'fd972ad5-8e98-42d7-93e1-57de7799d5bc', '', 1, 0, 'aafb047c-f984-4661-8816-7fecc5f59e80', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 0, 0, '', NULL, NULL, NULL, 0, '2026-11-06 15:50:45.170'),
  (11, '680eda09-081b-4512-b247-d13fdf547cb8', '', 1, 0, '98e7eab1-e45c-4e23-8896-b64735d091e4', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:08:35.820'),
  (12, '5c857e71-b681-47cf-a003-b6bfbd549369', '', 1, 0, 'b6cd105b-3e14-4792-a720-969a668fc5bb', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:37:48.514'),
  (13, '8e4465c5-7eeb-496e-8853-a17441aca1f6', '', 1, 0, '8abceada-d384-4afd-9d9e-c1e217304859', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:40:58.514'),
  (14, '997697bf-baef-4906-b903-f2fd3df97510', '', 1, 0, '9e9ce25b-4ef3-40af-dc9f9a285599', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:43:10.545'),
  (15, '2e701a5b-b168-4671-a4a5-8609bf4cb5ca', '', 1, 0, '96dc5070-96dc5070-96dc5070-96dc5070', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:57:32.860'),
  (16, '102d000d-5d8f-42fb-bded-9b2eec892617', '', 1, 0, 'd34f3ef7-d34f3ef7-d34f3ef7-d34f3ef7', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:58:38.860'),
  (17, 'de14d300-88e4-46c1-a00d-5a4f29fe8b0b', '', 1, 0, '483adb3d-483adb3d-483adb3d-483adb3d', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 16:59:24.860'),
  (18, '661deecf-b38a-47a1-9ab8-4631b6e0af06', '', 1, 0, '483adb3d-483adb3d-483adb3d-483adb3d', 'organization.create', 'organization', '1', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, '{"id": 1, "code": "team01", "logo": "", "name": "team01", "status": 1, "created_at": "2026-11-06T17:09:03.113+08:00", "updated_at": "2026-11-06T17:09:03.113+08:00"}', NULL, 307, '2026-11-06 17:09:04.988'),
  (19, 'e0c11d61-e0c11d61-e0c11d61-e0c11d61', '', 1, 0, '5cfa9a48-5cfa9a48-5cfa9a48-5cfa9a48', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 17:14:48.993'),
  (20, 'ad62e31f-ad62e31f-ad62e31f-ad62e31f', '', 1, 0, '5cfa9a48-5cfa9a48-5cfa9a48-5cfa9a48', 'PUT /api/v1/admin/me', '', '', 'PUT', '/api/v1/admin/me', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 192, '2026-11-06 17:24:49.056'),
  (21, '745fdc01-745fdc01-745fdc01-745fdc01', '', 1, 0, '5cfa9a48-5cfa9a48-5cfa9a48-5cfa9a48', 'admin.logout', '', '', 'POST', '/api/v1/admin/auth/logout', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 17:25:55.058'),
  (22, 'd7cfebe9-d7cfebe9-d7cfebe9-d7cfebe9', '', 1, 0, 'bcd40cdd-bcd40cdd-bcd40cdd-bcd40cdd', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 17:26:13.057'),
  (23, '652b7d72-652b7d72-652b7d72-652b7d72', '', 1, 0, 'aea4f10e-aea4f10e-aea4f10e-aea4f10e', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 17:35:17.068'),
  (24, '3f680b6b-3f680b6b-3f680b6b-3f680b6b', '', 1, 0, '08aa6eeb-08aa6eeb-08aa6eeb-08aa6eeb', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 17:35:53.069'),
  (25, '06d17685-06d17685-06d17685-06d17685', '', 1, 0, '3cc0fb31-3cc0fb31-3cc0fb31-3cc0fb31', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 17:51:53.103'),
  (26, 'b8109988-b8109988-b8109988-b8109988', '', 1, 0, '3cc0fb31-3cc0fb31-3cc0fb31-3cc0fb31', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 42, '2026-11-06 17:54:49.107'),
  (27, '335d9052-335d9052-335d9052-335d9052', '', 1, 0, '3cc0fb31-3cc0fb31-3cc0fb31-3cc0fb31', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 38, '2026-11-06 17:54:51.106'),
  (28, '18a0ec37-18a0ec37-18a0ec37-18a0ec37', '', 1, 0, '3cc0fb31-3cc0fb31-3cc0fb31-3cc0fb31', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 43, '2026-11-06 17:55:09.107'),
  (29, '8c072e96-8c072e96-8c072e96-8c072e96', '', 1, 0, '3cc0fb31-3cc0fb31-3cc0fb31-3cc0fb31', 'organization.create', 'organization', '2', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, '{"id": 2, "code": "team02", "logo": "", "name": "team02", "status": 1, "created_at": "2026-11-06T17:55:26.944+08:00", "updated_at": "2026-11-06T17:55:26.944+08:00"}', NULL, 98, '2026-11-06 17:55:27.157'),
  (30, '244d8791-244d8791-244d8791-244d8791', '', 1, 0, '38c5c025-38c5c025-38c5c025-38c5c025', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 18:11:23.126'),
  (31, '832f4df2-832f4df2-832f4df2-832f4df2', '', 1, 0, '4742ef4f-4742ef4f-4742ef4f-4742ef4f', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 18:31:47.181'),
  (32, '1335ddf2-1335ddf2-1335ddf2-1335ddf2', '', 1, 0, 'e8257573-e8257573-e8257573-e8257573', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 18:41:29.216'),
  (33, '0cb0fd56-0cb0fd56-0cb0fd56-0cb0fd56', '', 1, 0, 'e8257573-e8257573-e8257573-e8257573', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 37, '2026-11-06 18:41:29.216'),
  (34, '4449829b-4449829b-4449829b-4449829b', '', 1, 0, '4742ef4f-4742ef4f-4742ef4f-4742ef4f', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 38, '2026-11-06 18:41:55.217'),
  (35, '88e86650-88e86650-88e86650-88e86650', '', 1, 0, 'f8ed9d42-f8ed9d42-f8ed9d42-f8ed9d42', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 18:47:03.224'),
  (36, '6e6607ef-6e6607ef-6e6607ef-6e6607ef', '', 1, 0, '3746cb8d-3746cb8d-3746cb8d-3746cb8d', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 19:02:35.209'),
  (37, '4890124c-4890124c-4890124c-4890124c', '', 1, 0, '1a027c3b-1a027c3b-1a027c3b-1a027c3b', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 19:02:53.209'),
  (38, '2f5a69bf-2f5a69bf-2f5a69bf-2f5a69bf', '', 1, 0, '349e9ea3-349e9ea3-349e9ea3-349e9ea3', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 19:03:47.210'),
  (39, '4233d912-4233d912-4233d912-4233d912', '', 1, 0, '5666d89a-5666d89a-5666d89a-5666d89a', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 19:04:03.210'),
  (40, '93eb0674-93eb0674-93eb0674-93eb0674', '', 1, 0, '65a58236-65a58236-65a58236-65a58236', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'curl/8.7.1', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-06 19:04:55.216'),
  (41, '23c8360a-23c8360a-23c8360a-23c8360a', '', 1, 0, 'ef963fcc-ef963fcc-ef963fcc-ef963fcc', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-08 19:06:27.136'),
  (42, '7c28e668-7c28e668-7c28e668-7c28e668', '', 1, 0, '6cac0056-6cac0056-6cac0056-6cac0056', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-08 19:06:31.136'),
  (43, '0ecbab5f-0ecbab5f-0ecbab5f-0ecbab5f', '', 1, 0, 'edc0beb0-edc0beb0-edc0beb0-edc0beb0', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-09 10:20:30.480'),
  (44, '3ef4883a-3ef4883a-3ef4883a-3ef4883a', '', 1, 0, '4b49c711-4b49c711-4b49c711-4b49c711', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-09 10:38:06.475'),
  (45, '682251e3-682251e3-682251e3-682251e3', '', 1, 0, '6dea95f4-6dea95f4-6dea95f4-6dea95f4', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-09 10:56:52.463'),
  (46, 'bf697bdb-bf697bdb-bf697bdb-bf697bdb', '', 1, 0, 'ad8c72c6-ad8c72c6-ad8c72c6-ad8c72c6', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-09 16:08:11.085'),
  (47, '8a29cee1-8a29cee1-8a29cee1-8a29cee1', '', 1, 0, 'dad566c2-dad566c2-dad566c2-dad566c2', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-09 16:31:59.105'),
  (48, '3b32c4ae-3b32c4ae-3b32c4ae-3b32c4ae', '', 1, 0, '910728e9-910728e9-910728e9-910728e9', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '::1', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-09 17:07:01.163'),
  (49, '3244313b-3244313b-3244313b-3244313b', '', 1, 0, '5619cb31-5619cb31-5619cb31-5619cb31', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '172.18.103.96', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:33:19.369'),
  (50, '8a2d1611-8a2d1611-8a2d1611-8a2d1611', '', 1, 0, '657fa436-657fa436-657fa436-657fa436', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '172.18.103.96', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:33:27.369'),
  (51, '64e67989-64e67989-64e67989-64e67989', '', 1, 0, '657fa436-657fa436-657fa436-657fa436', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '172.18.103.96', 'node', 0, 0, '', NULL, NULL, NULL, 1, '2026-11-11 17:41:37.579'),
  (52, '82eea452-82eea452-82eea452-82eea452', '', 1, 0, '657fa436-657fa436-657fa436-657fa436', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '172.18.103.96', 'node', 0, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:41:39.578'),
  (53, '95f2d871-95f2d871-95f2d871-95f2d871', '', 1, 0, '657fa436-657fa436-657fa436-657fa436', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '172.18.103.96', 'node', 0, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:41:39.578'),
  (54, '18c00994-18c00994-18c00994-18c00994', '', 1, 0, '657fa436-657fa436-657fa436-657fa436', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '172.18.103.96', 'node', 0, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:41:41.578'),
  (55, '04c79ac9-04c79ac9-04c79ac9-04c79ac9', '', 1, 0, '657fa436-657fa436-657fa436-657fa436', 'admin.logout', '', '', 'POST', '/api/v1/admin/auth/logout', '172.18.103.96', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:42:15.578'),
  (56, 'aad3f433-aad3f433-aad3f433-aad3f433', '', 1, 0, '4403ba1b-4403ba1b-4403ba1b-4403ba1b', 'admin.login', '', '', 'POST', '/api/v1/admin/auth/login', '172.18.103.96', 'node', 1, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:42:37.578'),
  (57, '50b03d2b-50b03d2b-50b03d2b-50b03d2b', '', 1, 0, '4403ba1b-4403ba1b-4403ba1b-4403ba1b', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '172.18.103.96', 'node', 0, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:42:45.578'),
  (58, '01b2ef11-01b2ef11-01b2ef11-01b2ef11', '', 1, 0, '4403ba1b-4403ba1b-4403ba1b-4403ba1b', 'POST /api/v1/admin/organizations', '', '', 'POST', '/api/v1/admin/organizations', '172.18.103.96', 'node', 0, 0, '', NULL, NULL, NULL, 0, '2026-11-11 17:42:47.578');

SET FOREIGN_KEY_CHECKS = 1;
