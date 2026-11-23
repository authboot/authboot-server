# App 用户安全中心（第二批）

本批是**登录后的风险识别、提醒和确认处置**，没有增加登录前拦截或独立 MFA。所有新接口仅接受 App user access token，管理员令牌不能使用。组织、用户及当前 session 均来自已验证的 JWT + Redis 会话，不接受请求指定的 owner 或保留 session。

## 接口与客户端接入

所有接口以 `/api/v1/me/security` 开头，携带 `Authorization: Bearer <user_access_token>`。业务响应沿用 `code` / `message`；认证失败为 HTTP 401，其余业务错误使用现有业务错误码，客户端不能只检查 HTTP 200。

| 方法 | 路径 | 输入 | 输出 |
| --- | --- | --- | --- |
| GET | `/devices` | `page=1&page_size=20` | `devices`, `total` |
| GET | `/sessions` | 同上 | `sessions`, `total` |
| GET | `/events` | 同上 | `events`, `total` |
| POST | `/revoke` | `mode`, 可选 `device_id` | `revoked_sessions` |
| POST | `/confirm` | `event_id`, `decision`，重新验证凭据 | `revoked_sessions`, `change_password_required` |

分页默认每页 20，上限 100。时间均为 Unix 秒。接口 IDL 位于 `idl/security.proto`。设备、事件列表分页在数据库执行；会话列表从 Redis 账号索引读取后过滤组织并分页。现有系统未限制单账号会话总数，极多会话账号仍会增加读取与 Lua 批量操作成本。

设备示例（省略部分位置字段）：

```json
{
  "device_id": "app-install-id",
  "device_name": "我的手机",
  "current": true,
  "last_login_at": 1795200000,
  "last_active_at": 1795200300,
  "ip": "203.0.113.10",
  "location": {"display": "未知地区", "status": "non_public"},
  "last_active_ip": "203.0.113.10",
  "last_active_location": {"display": "未知地区", "status": "non_public"},
  "active_sessions": 2,
  "status": "active",
  "browser": "Safari",
  "os": "iOS"
}
```

`current` 取自当前认证 session 的 device_id。客户端 device_id、设备名及 User-Agent 均可伪造，只用于展示和分组，不构成可信设备凭据。UA 仅解析常见浏览器和系统，未识别返回 `Unknown`。同一 device_id 可以对应多个 session；历史设备无活跃 session 时返回 `inactive` 和计数 0，不删除历史记录。设备记录失败时，Redis 会话仍可从 `/sessions` 查看和退出。

没有 device_id 时不创建设备登记、不产生“首次设备”事件。此类 session 在会话列表中仍可见，当前会话用 session 的 `current` 标识，不能将空 device_id 视为同一可信设备。

登录响应增量字段 `security_event_ids` 给出本次登录产生的事件 ID；没有新事件时为空数组。客户端应登录后及进入安全中心时调用 `/events`，按 `pending` 状态显示站内提醒。refresh 不创建新设备事件。现有 protobuf 字段编号均保留，Session 新增 `current`、`last_active_ip`、`last_active_location`、`user_agent`。

登录/refresh 的 `session.expires_at` 统一表示 Redis session 到期时间，与列表一致；短期 access token 到期请使用顶层 `access_token_expires_at`，客户端不应继续把 session 到期当作 access token 到期。

保留当前 session，退出全部其他 session（包括同设备的其他 session）：

```json
{"mode": "others"}
```

退出指定设备的所有 session：

```json
{"mode": "device", "device_id": "app-install-id"}
```

按设备退出包含当前设备时会同时撤销当前会话，客户端应清理令牌并回到登录页。不存在或不属于当前 owner 的 device_id 是幂等 no-op，计数为 0，不泄露其他账号的设备。请求中的 `keep`、`session_id` 等额外字段不会改变保留对象。

“是本人”的密码路径需要**严格早于事件创建的其他有效会话**，且该会话自身没有 pending / not_me 安全事件，并重新验证当前密码。会话时间与事件时间相同秒、缺失历史时间均保守拒绝：

```json
{"event_id": "<event-id>", "decision": "me", "password": "<current-password>"}
```

“不是本人”：

```json
{"event_id": "<event-id>", "decision": "not_me", "password": "<current-password>"}
```

无密码账号可复用已有 login 场景验证码发行接口（仍需遵守已有验证码、发送频控等要求），并使用当前用户已绑定的邮箱或手机号：

```json
{
  "event_id": "<event-id>",
  "decision": "not_me",
  "identity_type": "email",
  "identity_value": "<bound-email>",
  "credential": "<fresh-login-code>"
}
```

验证前先核验事件 owner；验证码必须属于当前组织、用户已绑定身份，成功后一次性消费。密码尝试按组织+用户最多 5 次/5 分钟，正确尝试也计数。不提供密码缓存授权窗口；每次操作都重新验证，错误密码不自动回退到验证码。

`me` 不能由事件关联的可疑 session 自己确认。仅持相同密码重新登录 A、B，不能相互确认：较新的会话不能确认较旧事件，有未解决安全事件的 A 也不能为 B 背书。没有合格历史会话时，可以从另一有效会话使用独立联系方式验证码（上例 decision 改为 `me`）；联系方式必须在事件之前已绑定，CreatedAt 为零、同秒或晚于事件均拒绝该路径。验证码仍需本次验证并一次性消费，不接受 device_id 作为可信依据。`not_me` 不要求历史会话，允许撤销自身，会导致后续请求 401。独立 OTP 证明的是已绑定联系方式控制权；同时泄露密码和联系方式、或已被控制的历史会话仍超出本策略保证。

`not_me` 撤销的是事件关联的可疑 session（不自动封禁 device_id，也不自动改密码），返回 `change_password_required: true` 及明确改密提示。客户端应引导修改/重置密码，检查绑定身份，并按需调用“退出其他会话”。重新验证真实凭据后允许 `pending → me`、`pending → not_me`、`me → not_me`；`not_me` 不可逆。重复相同决定仍需凭据校验，可幂等返回；重复 not_me 返回撤销数 0、改密提示 true。事件 ID 即使被猜到也没有操作权限；没有邮件 GET 操作链接。

## 活跃、撤销和持久化语义

- 首次 session 的 `created_at`、`ip`、`location`、UA 不随 touch 或 refresh 覆盖。设备 `last_used_at` 对外映射 `last_login_at`，只记录最近登录；独立 `last_active_at` 记录认证请求活动。
- 只有 user middleware 成功校验 JWT、Redis owner 和数据库有效状态后才 touch。每 session 使用 Redis 原子 gate 限频 5 分钟；gate 命中前不查询 GeoIP、不写数据库。
- IP 改变时才在通过 gate 后解析近似位置。使用第一批可信代理/IP 提取策略及本地 GeoIP，不表示 GPS、实时位置或个人精确位置。旧会话没有活跃数据时在首次成功 touch 后补齐。
- touch Lua 只修改仍存在记录的活跃字段，使用原剩余 TTL，不修改 refresh lookup，不延长会话期限。rotate 在 Lua 内基于当前记录更新 token/到期时间，避免覆盖并发 touch。撤销后 touch/rotate 不会重建 session。
- 批量撤销以一段 Redis Lua 为线性化点，检查当前 session owner 后按 org/user 选择目标并删除当时的 refresh token。操作前已创建的匹配会话均撤销，操作后新登录的会话仍有效。已通过认证、正在执行的业务请求不会被追溯取消。
- Redis 为活跃状态权威来源，MySQL 是尽力写入的审计镜像；设备和会话列表的活跃计数使用 Redis。设备、事件或镜像写入失败记录日志，不让已成功认证登录失败。数据库故障时可能缺失设备历史或安全事件，不能承诺全量审计。
- refresh 镜像只更新仍 active 行的 expires_at，不能将 revoked 行复活；touch 镜像按 owner、active 状态及时间条件更新。数据库和 Redis 没有跨系统事务：事件处置先撤销 Redis，再提交事件决定，提交失败时安全动作可能已经生效，需要重新认证后重试/检查。

## 风险规则与提醒

同一用户登录通过数据库用户行锁串行登记设备，设备登记与新事件写入同一事务。已有全局唯一 user_id 及设备唯一键约束继续保留；所有业务查询另加组织过滤。同设备重复正常登录不会重复发首次设备提醒。

规则：

1. 首次见到非空 device_id：`new_device`，用于提醒，不代表攻击已发生。
2. 与该用户最近已登记设备的上次登录国家比较；双方 `status=approximate` 且非空 country_code 不同：`country_changed`。同时满足新设备时国家变化优先，本次仍只生成一个事件。
3. 未知地理、缺少国家码、城市/省变化不会单独触发国家异常。首次登录无可比较历史，不能据此宣称异地异常。

国家基线取最近设备登记，缺 device_id 登录不更新基线；VPN、旅行、运营商出口和 GeoIP 数据误差都可能产生提示。规则没有行为模型、旅行速度推断或实时攻击阻断。

安全事件使用独立 `tb_user_security_events`，不写原 `tb_notification`（该表缺 org/身份域），不会把 user 提醒投递给相同数字 ID 的管理员。

运行时复用现有 `email.Send`，仅选择当前 App user 在当前组织已绑定的首个邮箱。事件先持久化 `notify_status=pending`，邮件错误只记日志。每次成功登录最多处理 3 个到期事件；每事件 5 分钟租约、最多 3 次尝试；状态为 `pending` / `sent` / `failed` / `no_email`。进程中断遗留的最终租约过期后，在后续登录标为 failed。

这是登录驱动的有限重试，没有常驻投递队列；用户不再登录则 pending 可能长期保留。发送成功但状态写回失败可能重复邮件，不承诺 exactly-once。单次发送 deadline 从领取事件租约的时间起算 10 秒，严格短于 300 秒租约，慢查询不会向后推迟发送期限。SMTP 使用 context deadline 与配置 Timeout 的较早期限，TLS 和明文连接均在读取 greeting 前设置覆盖整个 SMTP 读写的 deadline，STARTTLS 继续继承底层期限；context 取消关闭连接，初始化失败同样关闭连接。发送同步执行，可能增加登录延迟，但错误不改变登录成功结果。站内事件无需邮件服务即可查看。

## 部署与验证

1. 先完成第一批安全及 GeoIP 迁移。
2. 现有库执行 `pkg/configs/sql/migrate_security_center_batch2.sql` 一次，或按现有启动流程使用 AutoMigrate；二选一，不要重复 ALTER。新库 `init.sql` 已包含字段和事件表，不要对现有库执行 init.sql。
3. 保持已有 Redis、JWT、可信代理、GeoIP 和 EMAIL_PROVIDER 配置；本批没有读取或输出部署环境秘密。Redis Lua 延续现有单实例部署假设，未适配 Redis Cluster 跨 slot。
4. 客户端接入五个接口、登录事件 ID、密码/绑定验证码确认和改密引导。旧客户端可忽略增量字段。
5. 只生成模型，不运行会覆盖自定义路由的 `hz update`：

```sh
hz model --idl idl/session.proto --no_recurse
hz model --idl idl/auth.proto --no_recurse
hz model --idl idl/security.proto --no_recurse --unset_omitempty
```

自动验证使用 miniredis、内存 SQLite 和注入的邮件发送函数；auth 登录测试故意不初始化邮件 provider，验证发送失败也返回令牌，不向真实用户发送邮件。

```sh
go build ./...
go test -race ./biz/mw/redis ./biz/dal/db ./biz/service/session ./biz/service/auth ./biz/mw/jwt ./biz/router ./biz/service/message ./pkg/utils ./pkg/geoip ./pkg/clientip
```

真实 MySQL InnoDB 行锁/DDL、线上 Redis Lua、SMTP/Resend 投递、真实 GeoIP 数据库、代理部署和 App UI 未在本地替代测试中验证。SQLite 单连接并发测试验证业务幂等与唯一约束，不能替代 MySQL 隔离级别验证。上线应在隔离预发布环境验证这些依赖；本次不执行数据库部署、不发送真实邮件、不提交或推送代码。
