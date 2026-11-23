# 第三批认证安全强化

## 部署与兼容性

本批增加管理员 TOTP MFA、一次性 step-up、持久化撤销补偿、可选保留任务以及内部监控端点。已有管理员默认不强制启用 MFA，不会因未配置 MFA key 而全部无法登录。未配置或错误的 key 会阻止 enrollment；已启用 MFA 的账户不会降级为仅密码登录。

部署顺序：

1. 备份 MySQL、Redis 和密钥管理系统中的配置；在预发布环境验证迁移与恢复。
2. 停止旧版写入实例，执行 `pkg/configs/sql/migrate_security_batch3.sql` **一次**。脚本没有删除数据，`ALTER TABLE ADD COLUMN` 不能重复运行。若已通过 AutoMigrate 创建字段，应先由 DBA 对照实际 schema，不能再次直接执行脚本。
3. 配置所有副本一致的 MFA key，以及独立的 metrics token。代码的 AutoMigrate 也声明了新增表。
4. 更新客户端，再启动新版服务。不要混跑仍不检查 SQL session version 的旧实例；回滚旧代码同样会失去版本撤销保证。
5. 先保持 retention 关闭，配置 Prometheus，观察 outbox。批准保留政策后开启 dry-run，核对候选数量，再单独设置 destructive 模式。

兼容变化：

- 管理员密码登录增加响应字段 tag 9–11，既有 tag 不变。前端必须先检查 `mfa_required`，不能把挑战视为登录成功。
- MFA 启用和禁用都会使该账户所有旧管理员会话失效，包括当前会话；客户端必须重新登录。
- 用户改密、重置密码、禁用和注销立即使旧用户会话失效。旧客户端不能继续使用先前 refresh token。
- 下表中的危险操作新增 `X-Step-Up-Token`。未附带有效凭证会被拒绝。
- 用户修改密码、删除账户保留原有请求内密码/绑定 OTP 验证，不额外要求第二份 step-up。解绑身份此前没有再次证明，本批新增凭证要求。
- 管理员 refresh / switch-organization 的 HTTP handler 原来是空响应占位，本批接入已有 service。
- 注销用户不再删除与其数字 ID 相同的管理员通知；两个身份域不是同一个账号。

## MFA key

`ADMIN_MFA_ENCRYPTION_KEY` 必须是标准 Base64 编码的 32 个随机字节。可在受控运维环境使用 `openssl rand -base64 32` 生成，再直接放入密钥管理系统；不要提交到 Git、工单、日志或聊天记录。`.env.example` 只有空配置。

存储格式为 `v1:` 加 AES-256-GCM 密文。每次加密使用新 nonce，以 `admin:<account_id>` 为附加认证数据。普通账户接口不返回 MFA 状态内部字段、密文、计数器或恢复码哈希。

当前仅支持单 key，不支持在线双 key 轮换。不能直接替换环境变量：旧密文将不能解密。轮换应在维护窗口中备份旧 key 和数据库，使用经过审查的离线迁移工具逐账户解密并以新 key 重加密，完整验证后同时更新所有实例。仓库没有提供自动执行此迁移的端点。丢失 key 时首先恢复受控备份；恢复码也不能用来绕过缺失 key 的部署。没有邮件免 MFA 或管理员后门重置接口。

## MFA API

以下路径均以 `/api/v1/admin/auth` 为前缀。除登录与 `mfa/verify` 外，需要管理员 `Authorization: Bearer <access_token>`。敏感响应带 `Cache-Control: no-store`，客户端不得持久化 setup 响应或将它送入分析系统。

### 申请 setup

先调用 `POST /step-up`：

```json
{"password":"<当前密码>","scope":"mfa:setup"}
```

成功：

```json
{"code":0,"step_up_token":"<一次性凭证>","expires_at":1900000120}
```

随后 `POST /mfa/setup`，请求体 `{}`，header `X-Step-Up-Token: <一次性凭证>`：

```json
{
  "code":0,
  "message":"success",
  "secret":"<仅本次返回的 Base32 secret>",
  "otpauth_uri":"otpauth://totp/Authboot%3Aaccount?...",
  "expires_at":1900000600
}
```

setup 十分钟内有效，再次 setup 会替换尚未确认的 secret。已启用的账户不能重复 setup。

### 确认启用

以当前密码取得 `scope: "mfa:confirm"` 的新 step-up，随后：

```http
POST /api/v1/admin/auth/mfa/confirm
Authorization: Bearer <access_token>
X-Step-Up-Token: <新凭证>
Content-Type: application/json

{"code":"<认证器当前六位码>"}
```

返回 `recovery_codes` 数组（十个高熵码，仅返回一次）和 `reauthentication_required: true`。启用事务同时更新 MFA 状态、账户代际和撤销 outbox。当前及其他旧会话即刻失效。

TOTP 使用 RFC 6238 SHA-1、30 秒步长、六位码，接受当前时间步及前后各一步；已接受的计数器及更早计数器不能再次使用。成功用过 TOTP 登录后，下一次 step-up 通常需要等待下一时间步或使用尚未消费的恢复码。

### 登录与恢复码

`POST /login` 保留原有 email/password/device_id/device_name。已启用 MFA 时返回：

```json
{
  "code":0,
  "message":"MFA verification required",
  "access_token":"",
  "refresh_token":"",
  "mfa_required":true,
  "mfa_challenge_token":"<三分钟挑战>",
  "mfa_challenge_expires_at":1900000180
}
```

验证：

```json
{"challenge_token":"<挑战>","code":"<六位 TOTP>","recovery":false}
```

发送到 `POST /mfa/verify`。恢复登录使用同一路径：

```json
{"challenge_token":"<挑战>","code":"<尚未使用的恢复码>","recovery":true}
```

成功后才返回正常 access/refresh。挑战绑定账号、MFA 代际、密码哈希、原始设备标识/名称和服务端观察到的 IP/UA，最多尝试五次，成功消费后不能重放。IP/UA 改变需要重新密码登录取得挑战。反向代理必须使用已有的可信代理配置，不能允许客户端伪造来源。

TOTP 与恢复码验证共享每账户五次/五分钟限额；挑战签发、管理操作及 step-up 也有限额，Redis 不可用时失败关闭。恢复码以绑定管理员账户的 SHA-256 存储，160 位熵，不是低熵短数字密码；数据库条件删除确保单次消费。

### 轮换恢复码与关闭 MFA

对已启用 MFA 的账号申请 step-up 必须提供 **密码 + TOTP 或恢复码**：

```json
{"password":"<密码>","code":"<未使用的恢复码>","recovery":true,"scope":"mfa:recovery"}
```

`POST /mfa/recovery` 带该凭证、请求体 `{}`，返回新的十个恢复码；原有恢复码全部失效。

关闭使用 `scope: "mfa:disable"`，随后 `POST /mfa/disable`。成功删除 secret/恢复码，提高代际并撤销所有旧管理员会话。没有仅凭密码关闭已启用 MFA 的路径。

## Step-up 适用表

管理员申请端点 `/api/v1/admin/auth/step-up`；用户申请端点 `/api/v1/user/auth/step-up`。凭证有效两分钟，仅保存 token 哈希，绑定 subject/account/session/organization/scope，不授予额外 RBAC 权限。跨身份域、跨会话、跨组织、过期和重复消费都拒绝。对管理路由先做资源权限检查，再消费凭证；请求失败时可能需要重新申请，不应自动无上限重试危险操作。

| 操作 | scope / 已有证明 |
| --- | --- |
| 管理员 MFA setup / confirm / disable / 恢复码轮换 | `mfa:setup` / `mfa:confirm` / `mfa:disable` / `mfa:recovery` |
| DELETE 管理组织 | `organization:delete` |
| 修改成员角色、移除成员 | `member:manage` |
| 写入/删除组织 OAuth 配置 | `oauth:manage` |
| 撤销自己的其他管理会话、批量撤销管理会话、logout 指定其他 sid | `session:revoke` |
| 用户解绑身份 | `identity:unbind` |
| 用户修改密码 | 原请求 `old_password`，不叠加 header |
| 用户重置密码 | 原绑定身份的 `reset_password` 一次性验证码 |
| 用户注销 | 原请求密码或绑定身份的 `delete_account` 验证码 |
| 普通读取、登录、refresh、当前会话自助 logout | 不要求 step-up |

管理员不能通过 `session:revoke` 撤销其他管理员账户的会话；既有账号所有权限制仍生效。

用户申请示例：

```json
{"password":"<当前密码>","scope":"identity:unbind"}
```

无密码用户可用已绑定邮箱/手机号的现有 login OTP：

```json
{"identity_type":"email","identity_value":"<已绑定邮箱>","credential":"<OTP>","scope":"identity:unbind"}
```

解绑仍保留至少一个登录身份，计数检查、凭证消费和删除在同一用户行锁事务中执行。

## 撤销权威与 worker

Redis 仍是会话内容、refresh 轮换的权威存储；MySQL 账户上的 `session_version`（用户）/`mfa_generation`（管理员）是**撤销边界**的权威存储，MySQL session 表仍是镜像。受保护请求、refresh 和验证令牌不能只检查 Redis，还会检查 SQL 版本。SQL/Redis 不可用时认证失败关闭。

改密、重置、注销、用户禁用，以及管理员 MFA 启用/禁用，将安全状态更新与 outbox 放在同一 SQL 事务。Redis 故障不撤销已提交的数据库修改，也不将补偿丢成一条日志。SQL 提交后旧版本立即被拒绝，worker 只清理小于目标版本的 Redis 会话；稍后的新登录即便发生在同一秒也不受影响。

worker 随 bootstrap 启动，每 30 秒处理至多 200 条任务；每条使用一分钟租约、随机 lease token 和条件更新，失败退避从两秒增长，最大 1024 秒，不丢弃失败任务。任务幂等，多副本可以运行。退出时取消 context 并等待 goroutine 完成；Redis 请求仍受现有客户端超时控制。未完成 outbox 永远不被 retention 清除。Redis 成功删除前，按 subject/account/org/sid 更新相应镜像状态。

## 保留策略

默认：

```dotenv
SECURITY_RETENTION_ENABLED=false
SECURITY_RETENTION_DRY_RUN=true
SECURITY_RETENTION_DAYS=180
```

可配置范围 30–3650 天；每轮每类最多 200 条。dry-run 只统计候选，不执行删除。当前实现沿用统一期限，部署方必须按合规要求确定，不应将默认值解释为法律意见。

- 登录日志、审计日志：超过期限的记录。
- 用户安全事件：已经解决且通知不再处于 pending/sending/retry，解决时间超过期限。
- 会话镜像：仅 revoked 且过期时间超过期限。标记 active 的镜像保守保留，即使镜像时间陈旧也不会直接删除；历史镜像状态修复应单独审查。
- 设备：长时间未登录/活跃，并通过 Redis 确认没有有效设备会话；与新会话创建共用账户行锁。Redis 查询失败时不假定设备已经离线。
- 已过期的 step-up、登录挑战及未确认 enrollment；有效挑战和已启用的 MFA secret 不清理。
- 已完成且完成时间超过期限的 outbox；未完成任务不清理。
- 注销时立即清除用户主表密码、资料、settings、身份及地址；审计/登录记录中的历史 PII 按保留期限清理，不能声称注销后立即删除所有历史数据。

数据库、日志文件、对象存储和备份具有不同生命周期。此 worker 不删除 MinIO 对象、不操作备份、不执行生产库外部清理。部署前应评估历史证据、取证、用户设备安全提示丢失的风险。

## 监控与告警

配置至少 32 字符的随机 `SECURITY_METRICS_TOKEN`，通过 TLS/内网反代访问：

- `GET /internal/metrics`
- `GET /internal/ready`
- 两者必须带 `Authorization: Bearer <SECURITY_METRICS_TOKEN>`；未配置拒绝访问。

readiness 只验证 SQL ping 与 Redis session 客户端 ping，不暴露依赖错误详情。指标使用固定名称，无 user/IP/组织/secret 标签，包括登录、MFA、step-up 失败，撤销 pending/失败、worker 失败、retention 候选/删除、GeoIP unavailable、通知投递失败。

Prometheus 示例（token 文件置于 Prometheus 主机的密钥目录）：

```yaml
scrape_configs:
  - job_name: authboot-security
    metrics_path: /internal/metrics
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /run/secrets/authboot_metrics_token
    static_configs:
      - targets: ["authboot.internal.example:443"]
rule_files:
  - /etc/prometheus/security.rules.yml
```

规则示例位于 `pkg/configs/prometheus/security.rules.yml`，包括撤销积压、MFA 失败激增、worker 失败和抓取失败；阈值需按实例数量及业务量调整。应用只暴露指标，不主动向 Slack/邮箱/外部告警平台发消息。

## 验证与部署边界

新增测试使用 SQLite / miniredis 和测试专用固定 key，不读取 `.env`，不连接生产数据库或真实邮箱。覆盖 RFC 向量、窗口/重放、恢复码与 step-up 原子消费、管理员 MFA HTTP 生命周期、旧会话失效、撤销失败后重试保护新会话、保留 active/pending 和 worker shutdown，以及 metrics 鉴权。

MySQL 锁行为、生产数据迁移耗时、真实 Redis 故障切换、反代 IP/UA 稳定性、Prometheus 抓取/规则加载及部署恢复仍需在预发布验证。代码与测试通过不能替代这些验证。
