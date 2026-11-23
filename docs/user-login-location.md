# 用户登录 IP 近似位置

登录、注册自动登录和 OAuth 成功登录在公共流程解析一次位置，session 保存首次创建时的 IP、client_id、User-Agent 和位置快照。refresh 仅延续该快照，不按刷新请求 IP 更新。device 保存最近一次成功登录位置，同一登录只计数一次；未提供 device_id 时仍保存 session，但不登记设备。旧 session 没有位置时显示未知，不按今天的数据补算历史。

位置是网络出口的近似地区，不是 GPS、实时位置或身份验证依据；VPN、运营商出口、数据库版本都可能造成误差。不存储经纬度。API 在原 Session 字段外增加 ip 和 location（country_code/country/region/city/display/source/status），没有新增设备 API。

## 部署

1. 从 [ip2region 官方数据目录](https://github.com/lionsoul2014/ip2region/tree/master/data) 获取 `ip2region_v4.xdb`，例如放到 `/var/lib/authboot/geoip/ip2region_v4.xdb`。此配置使用官方 `service.BufferCache` 在启动时加载 IPv4 库，记录字段顺序为 `国家|省份|城市|ISP|ISO 两位国家代码`。升级旧库时请一并替换数据文件。
2. 在 https://dev.maxmind.com/geoip/geolite2-free-geolocation-data 注册 MaxMind 账号，接受其许可条款，使用账号的 license key 下载 **GeoLite2 City** mmdb（或用官方 geoipupdate 定期更新）。license key 只交给独立更新工具，应用本身仅需要文件路径；不下载或提交授权数据到代码仓库。
3. 将以下环境变量传入服务进程（项目示例文件不会自动保证被加载）：

   ```dotenv
   IP2REGION_DB_PATH=/var/lib/authboot/geoip/ip2region_v4.xdb
   GEOLITE2_CITY_DB_PATH=/var/lib/authboot/geoip/GeoLite2-City.mmdb
   LOGIN_TRUSTED_PROXY_CIDRS=10.20.0.0/24
   ```

4. 现有库部署前执行 `pkg/configs/sql/migrate_user_login_location.sql` 一次，或由当前启动 AutoMigrate 添加两列，二选一。新库 init.sql 已同步；不要对现有库执行 init.sql。迁移不回填历史位置。
5. 数据文件给予服务只读权限。通过独立更新任务定期下载、校验并原子替换，随后重启服务加载新数据。已有 session 保持原始位置快照。xdb 全量驻内存；City reader 在启动打开，退出关闭。请求期间不访问网络、不重复打开文件。数据文件由 .gitignore 排除。

## 选择和降级

IPv4 若 ip2region 返回国家代码 CN，完整采用该结果。其他情况优先 GeoLite2 City，失败或无命中时使用 ip2region 的完整结果。IPv6 由本地 GeoLite2 City 处理。GeoLite 地名优先取中文，其次取英文。展示附有“IP 近似位置”。

私网、回环、无效、链路本地、文档/基准测试/保留地址返回未知，不查库。status 为 approximate、invalid_ip、non_public、unavailable、lookup_error、not_found 或旧记录 unknown；source 为 ip2region、geolite2、unknown。缺失配置/坏文件启动只汇总 warning 一次，登录继续；有效来源仍可降级使用。两个文件都没有时不会产生真实定位。

默认只信任 socket peer，忽略客户端自带 X-Forwarded-For 和 X-Real-IP。仅当 peer 在 LOGIN_TRUSTED_PROXY_CIDRS 中，才从右向左剥离可信代理，取首个不可信跳点；XFF 缺失时才使用 X-Real-IP。畸形 XFF 回退 peer，不能借另一个头绕过。配置错误整组退回 peer-only。应仅列出实际受控代理网段，不能填所有公网；代理必须追加/重建可信的 XFF。登录日志与 session/device 使用同一个解析出的 IP，其他审计 API 不变。

Redis 当前项目使用 JSON string，新增字段沿用其格式并兼容旧记录，没有改成 hash。MySQL 是 best-effort 镜像，Redis 仍为 session 真源；数据库故障不改变现有登录成功语义。
