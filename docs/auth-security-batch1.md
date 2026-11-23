# 第一批认证安全变更

## 部署顺序

1. 备份并执行 `pkg/configs/sql/migrate_membership_role.sql` 的加列操作。
   启动时 AutoMigrate 也会加列，已有列时不要重复执行 ALTER。
2. 由组织负责人核实既有组织的 owner，按迁移脚本中的限定条件赋值。
   既有 membership 缺少所有权证据，默认 `member`，不自动提升权限。
   membership 的 active 为 **2**，pending/disabled/removed 为 1/3/4；
   这与 user/organization 的 enabled=1 不同。不要把 pending 批量改成 active。
3. 前端接入 captcha 三步流程后再切换流量。所有实例应同时升级会话
   轮换实现；滚动期间旧版本的多命令轮换无法提供并发保证。
4. Redis 必须可用，并允许 EVAL；当前客户端使用 Redis DB 3（验证码）、
   DB 4（会话），适用于单节点/Sentinel，不支持 Redis Cluster 多键脚本。
   配置可信代理 CIDR，使 IP 限流使用实际来源；未配置时只信任连接对端。

## 会话接口

- 用户 logout 必须携带有效 access；`session_id` 留空退出当前会话，
  指定时仅能退出当前用户、当前组织的会话。未知/他人会话返回同一鉴权错误。
- admin logout 同样支持留空退出当前会话或指定本人其他会话，不能退出他人会话。
- 用户/admin refresh 只使用请求体 `refresh_token` 认证，忽略 access 是否存在、
  是否过期。签发前检查账户、组织及适用的成员状态。
- 轮换在 Redis Lua 中比较当前 refresh 和映射，只允许一个并发请求成功。
  失败重放不撤销获胜会话；客户端应串行刷新并保存获胜返回的新 token。
  撤销与轮换并发时不会复活会话。响应在网络中丢失后旧 token 无法重试，
  客户端需重新认证，这是严格一次轮换的行为。
- 前置验证失败不消费旧 refresh。Lua 在写入前检查索引类型。
  Redis 进程崩溃、持久化或故障切换的数据丢失不由应用脚本保证。
- access middleware 和 validate-token 同时检查 Redis 会话及账户状态；
  用户 token 的账户/组织必须与 session 一致。
- 保留原有 admin 切换组织语义：登录会话本身 org=0，切换签发组织 access；
  refresh 返回该底层会话的 scope，客户端仍需按需再次切换组织。

## 验证码

1. `GET /api/v1/captcha?scene=N` 创建图片挑战。
2. `POST /api/v1/captcha/verify` 提交 `captcha_id/answer/scene`。
3. 成功取得 `verify_token`，在 `POST /api/v1/message/send-code` 原有字段
   `captcha_verify_token` 中提交；场景和来源 IP 必须一致。

场景 1–6 分别是登录、注册、绑定手机、绑定邮箱、重置密码、注销账号。
图片答案及绑定数据存 Redis，支持多实例。挑战答题尝试消费绑定；
验证凭证是 crypto/rand 生成的 256-bit 随机值，有效期 120 秒、仅用一次。
验证码有效期 5 分钟，crypto/rand 生成六位数字；正确答案原子一次消费，
累计五次错误失效。发送失败按值删除本次验证码，不删除后续替代值。

固定窗口限制：

| 维度 | 限制 |
| --- | --- |
| 创建图片/IP | 30 次/分钟 |
| 验证图片/IP | 60 次/分钟 |
| 发送请求/IP | 20 次/小时（失败尝试也计数） |
| 发送/目标账号 | 10 次/小时 |
| 发送/目标账号/场景 | 1 次/分钟 |

邮箱目标去首尾空白并转小写，使大小写不能绕过发送/消费限制。
限流与验证码存储不可用时拒绝操作。现有直接 email.Send/sms.Send 服务调用
不受公共 send-code 的 captcha 门槛影响；仓库中 SendCode 的调用方只有公共 handler。

## 密码

注册、重置、改密统一要求 8–72 **字节**，bcrypt 使用 DefaultCost（10）。
历史短密码仍可验证；成功认证后低 cost hash 才升级。
写回条件包含账户、原 hash（用户还包含组织），不会覆盖并发改密。
管理员不再打印密码 hash。

## 最小组织授权

| 角色 | 业务资源读写 | 组织配置/生命周期 | 成员/邀请/角色管理 |
| --- | --- | --- | --- |
| owner | 允许 | 允许 | 允许 |
| admin | 允许 | 拒绝 | 拒绝 |
| member / 未知 | 拒绝 | 拒绝 | 拒绝 |

组织资源要求 token scope 与 URL/资源实际组织一致，数据库中的账户、组织、
membership 均有效。拒绝请求体/查询参数与 URL 冲突的 organization_id。
仅凭 membership_id/invitation_id 的接口先解析真实归属再鉴权。
组织列表仅返回当前账号的有效成员组织；新建组织事务内为创建者创建 active owner。
平台 admin 会话查询/撤销仅允许操作自己的会话。

现有成员列表、成员详情返回兼容新增的 `role` 字段。角色授权接口：

```http
PUT /api/v1/admin/organizations/:organization_id/members/:membership_id/role
Authorization: Bearer <owner-access-token>
Content-Type: application/json

{"role":"admin"}
```

可授予 owner/admin/member，目标必须是本组织 active 成员。
owner 不能通过此接口被降级，也不能被成员删除/退出接口移除，
避免并发丢失最后一个 owner。需转移/清退 owner 时由部署运维核实处理。
这不是可自定义权限的完整 RBAC 产品，没有全局 superadmin 后门。

## 验证方式与边界

安全测试使用 miniredis 和内存 SQLite，邮件通过测试内注入的 sender 验证，
不连接生产 Redis/MySQL、不发送真实邮件/短信、不读取 .env。
覆盖并发轮换/撤销、重放、退出归属、过期 access 刷新、状态禁用、
captcha 一次性与场景/IP 绑定、发送限流、验证码爆破/一次消费、
跨组织/角色授权及密码兼容/升级/CAS。

真实 MySQL 行锁、Redis 故障切换、SMTP/SMS 厂商投递仍需部署环境验证。
仓库 MinIO 旧测试依赖真实客户端/配置，不纳入隔离安全测试。

本轮验证结果：

- `go build ./...`：通过。
- `go test -race ./biz/mw/redis ./biz/router ./biz/service/message ./pkg/utils`：通过。
- `go test ./... -skip '^Test(BucketExist|BuckMake|GetObjURL)$'`：通过。
- `git diff --check`：通过。
- 单独执行 `go test ./biz/mw/minio -run '^TestBucketExist$'`：
  复现既有失败，`minio_test.go:31` 在 `Client == nil` 时调用 BucketExists
  导致空指针 panic。未为这些旧测试读取生产配置或连接生产服务。
